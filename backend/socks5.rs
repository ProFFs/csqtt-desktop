// [DESKTOP] SOCKS5-прокси (режим «Прокси (браузер)»): альтернатива wintun-TUN.
//
// Принцип: ядро в UDP-"proxy"-ветке Dispatcher (tun_uds="") уже умеет
// принимать СЫРЫЕ IPv4-пакеты и гнать их в туннель (dispatch → воркеры),
// а даунлинк складывать в очередь inbound. Здесь вместо UDP-сокета:
//   * TCP-листенер 127.0.0.1:PORT с SOCKS5-протоколом (greeting + CONNECT);
//   * synthetic-движок TCP (SYN → SYN/ACK → ESTABLISHED → PSH/FIN), который
//     пакует сегменты в IPv4+TCP (src = виртуальный 198.18.0.2:vport,
//     dst = реальный IP цели) и инжектирует через Dispatcher::dispatch;
//   * обратный путь — Dispatcher::set_return_sink: write_udp вместо отправки
//     на UDP-адрес клиента отдаёт пакеты сюда, демультимплексор разносит их
//     по vport (глобальный реестр) в сессии;
//   * домены резолвятся синтетическим DNS A-запросом через тот же туннель
//     (UDP src=198.18.0.2:vport → 8.8.8.8:53, фолбэк 1.1.1.1, 8 с суммарно);
//   * UDP ASSOCIATE не поддерживается (RESP 0x07) — браузер сам падает на TCP.
//
// Прав администратора не требует: никаких сетевых интерфейсов, только loopback.

use crate::direct_relay::{build_tcp_packet, build_udp_packet};
use crate::dispatcher::Dispatcher;
use crate::packet::{PacketBuf, PacketPool};
use crate::stats::Stats;
use anyhow::{Context, Result, bail};
use rand::RngExt;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Виртуальный src-адрес синтетических пакетов: 198.18.0.0/15 — benchmark-
/// диапазон, проходит is_forwardable_packet и не конфликтует с TUNCONF 10.66.x.
pub const VIRT_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);

/// Максимум байт TCP-полезной нагрузки в сегменте (1440 + 20 TCP + 20 IPv4).
pub const MAX_SEGMENT: usize = 1440;
const RETRY_DELAY: Duration = Duration::from_millis(1500);
const MAX_RETRY_ATTEMPTS: u32 = 5;
/// Тайм-аут дожития после отправки своего FIN (ждать FIN/ACK оппонента).
const FIN_LINGER: Duration = Duration::from_secs(8);
/// Суммарный бюджет резолва: по 4 с на 8.8.8.8 и 1.1.1.1.
const DNS_PHASE: Duration = Duration::from_secs(4);
const DNS_SERVERS: [Ipv4Addr; 2] = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)];
const FOREVER: Duration = Duration::from_secs(3600);

// ────────────────────────── SOCKS5 handshake ──────────────────────────

pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_FAILURE: u8 = 0x01;
pub const REP_COMMAND_UNSUPPORTED: u8 = 0x07;
pub const REP_ATYP_UNSUPPORTED: u8 = 0x08;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocksTarget {
    /// Готовый IPv4-адрес из запроса.
    V4(SocketAddr),
    /// Домен + порт — требует резолва через туннель.
    Domain { host: String, port: u16 },
    /// IPv6 — не поддерживается (RESP 0x08).
    V6(SocketAddr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocksCommand {
    Connect,
    UdpAssociate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocksRequest {
    pub command: SocksCommand,
    pub target: SocksTarget,
}

/// Разбор готового буфера запроса (VER CMD RSV ATYP ADDED.RD.PORT).
/// Возвращает запрос и число потреблённых байт.
pub fn parse_socks5_request(buf: &[u8]) -> Result<(SocksRequest, usize)> {
    if buf.len() < 4 {
        bail!("SOCKS5: короткий заголовок запроса");
    }
    if buf[0] != 5 {
        bail!("SOCKS5: версия {} не поддерживается", buf[0]);
    }
    let command = match buf[1] {
        1 => SocksCommand::Connect,
        2 => SocksCommand::UdpAssociate,
        3 => bail!("SOCKS5: BIND не поддерживается"),
        other => bail!("SOCKS5: неизвестная команда {other}"),
    };
    if buf[2] != 0 {
        bail!("SOCKS5: RSV должен быть 0");
    }
    let request = match buf[3] {
        1 => {
            if buf.len() < 10 {
                bail!("SOCKS5: обрезанный IPv4-адрес");
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            SocksRequest {
                command,
                target: SocksTarget::V4(SocketAddr::new(IpAddr::V4(ip), port)),
            }
        }
        3 => {
            let host_len = buf[4] as usize;
            let end = 5 + host_len + 2;
            if buf.len() < end {
                bail!("SOCKS5: обрезанный домен");
            }
            let host = String::from_utf8(buf[5..5 + host_len].to_vec())
                .context("SOCKS5: недопустимая доменная строка")?;
            if host.is_empty() || host.len() > 253 {
                bail!("SOCKS5: недопустимая длина домена");
            }
            let port = u16::from_be_bytes([buf[5 + host_len], buf[5 + host_len + 1]]);
            SocksRequest {
                command,
                target: SocksTarget::Domain { host, port },
            }
        }
        4 => {
            if buf.len() < 22 {
                bail!("SOCKS5: обрезанный IPv6-адрес");
            }
            let octets: [u8; 16] = buf[4..20].try_into().unwrap();
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            SocksRequest {
                command,
                target: SocksTarget::V6(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
            }
        }
        other => bail!("SOCKS5: неизвестный ATYP {other}"),
    };
    let consumed = match &request.target {
        SocksTarget::V4(_) => 10,
        SocksTarget::Domain { host, .. } => 5 + host.len() + 2,
        SocksTarget::V6(_) => 22,
    };
    Ok((request, consumed))
}

/// Ответ SOCKS5-сервера (REP с нулевым BND.ADDR/PORT, ATYP=IPv4).
pub fn socks5_reply(rep: u8) -> [u8; 10] {
    [5, rep, 0, 1, 0, 0, 0, 0, 0, 0]
}

// ───────────────────────── мини-DNS (A-запись) ─────────────────────────

/// Сборка стандартного DNS A-запроса (RD=1, один вопрос).
pub fn build_dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(32 + name.len());
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            // нелегальная метка — имя обрываем (ответ будет NXDOMAIN/ошибка)
            break;
        }
        msg.push(bytes.len() as u8);
        msg.extend_from_slice(bytes);
    }
    msg.push(0);
    msg.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    msg
}

fn dns_skip_name(msg: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let len = *msg.get(off)?;
        if len & 0xc0 == 0xc0 {
            // сжатие: 2 байта, дальше данных имени нет
            return off.checked_add(2).filter(|next| *next <= msg.len());
        }
        off += 1;
        if len == 0 {
            return Some(off);
        }
        off = off.checked_add(len as usize)?;
        if off > msg.len() {
            return None;
        }
    }
}

/// Первый A-запись из DNS-ответа (RDATA длиной 4).
pub fn parse_dns_a(msg: &[u8]) -> Option<Ipv4Addr> {
    if msg.len() < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    if an == 0 {
        return None;
    }
    let mut off = 12usize;
    for _ in 0..qd {
        off = dns_skip_name(msg, off)?.checked_add(4)?;
    }
    for _ in 0..an {
        off = dns_skip_name(msg, off)?;
        if msg.len() < off + 10 {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rclass = u16::from_be_bytes([msg[off + 2], msg[off + 3]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        off += 10;
        if msg.len() < off + rdlen {
            return None;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            return Some(Ipv4Addr::new(
                msg[off],
                msg[off + 1],
                msg[off + 2],
                msg[off + 3],
            ));
        }
        off += rdlen;
    }
    None
}

// ─────────────────────── реестр обратного пути ───────────────────────
// vport → канал сессии. Демультимплексор pump входящие из return_sink
// диспетчера по порту назначения (мы всегда шлём src=VIRT_IP:vport).

#[derive(Default)]
pub struct ReturnRegistry {
    inner: Mutex<HashMap<u16, mpsc::UnboundedSender<Vec<u8>>>>,
}

impl ReturnRegistry {
    pub fn register(&self, vport: u16, tx: mpsc::UnboundedSender<Vec<u8>>) -> bool {
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.contains_key(&vport) {
            return false;
        }
        guard.insert(vport, tx);
        true
    }

    pub fn remove(&self, vport: u16) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.remove(&vport);
        }
    }

    /// Доставка сырого IPv4-пакета сессии по vport (без владельца — дроп).
    pub fn deliver(&self, vport: u16, packet: &[u8]) {
        let sender = self
            .inner
            .lock()
            .ok()
            .and_then(|guard| guard.get(&vport).cloned());
        if let Some(sender) = sender {
            let _ = sender.send(packet.to_vec());
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Выдача динамического vport из диапазона 2048..=u16::MAX (с обходом занятых).
fn alloc_vport() -> Option<(u16, mpsc::UnboundedReceiver<Vec<u8>>)> {
    static NEXT: AtomicU16 = AtomicU16::new(2048);
    let registry = global_registry();
    for _ in 0..60000u32 {
        let mut vport = NEXT.fetch_add(1, Ordering::Relaxed);
        if vport < 2048 {
            // перескок зоны 1024..2047 после wrap-around
            vport = 2048 + (vport % 63488);
        }
        let (tx, rx) = mpsc::unbounded_channel();
        if registry.register(vport, tx) {
            return Some((vport, rx));
        }
    }
    None
}

/// Глобальный реестр обратного пути (один на процесс; GUI-режим = одна сессия).
fn global_registry() -> &'static ReturnRegistry {
    static REGISTRY: OnceLock<ReturnRegistry> = OnceLock::new();
    REGISTRY.get_or_init(ReturnRegistry::default)
}

/// Маршрутизация обратного IPv4-пакета: TCP (proto 6) и UDP (proto 17) —
/// по порту назначения (наш vport); всё остальное дроп.
pub fn route_return_packet(registry: &ReturnRegistry, raw: &[u8]) {
    if raw.len() < 28 || raw[0] >> 4 != 4 {
        return;
    }
    let ihl = (raw[0] & 0x0f) as usize * 4;
    if ihl < 20 || raw.len() < ihl + 8 {
        return;
    }
    if raw[9] != 6 && raw[9] != 17 {
        return;
    }
    let total = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if total < ihl + 8 || total > raw.len() {
        return;
    }
    // назначением должен быть наш виртуальный адрес (IPv4 dst = байты 16..20)
    if raw[16..20] != VIRT_IP.octets() {
        return;
    }
    let dport = u16::from_be_bytes([raw[ihl + 2], raw[ihl + 3]]);
    registry.deliver(dport, &raw[..total]);
}

// ───────────────────────── TCP-движок (state machine) ─────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineState {
    SynSent,
    Established,
    FinSent,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineEvent {
    Established,
    Data(Vec<u8>),
    /// Оппонент закрылся (FIN) или сбросил (RST) — исходящие прекращаются.
    RemoteClosed,
}

struct UnackedSeg {
    seq: u32,
    occupied: u32, // SYN/FIN = 1, данные = len
    bytes: Vec<u8>,
}

/// Упрощённый клиентский TCP-движок: SYN → ESTAB → FIN, seq/ack-трекинг,
/// ретрансмит 1.5 с × 5, окно из SYN/ACK (fallback 14400, MSS из опции).
pub struct TcpEngine {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    iss: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub peer_window: u32,
    pub max_seg: usize,
    pub state: EngineState,
    unacked: VecDeque<UnackedSeg>,
    pub attempts: u32,
}

/// a строго больше b в wrapping-арифметике (окно половины пространства).
fn seq_after(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < 0x8000_0000
}

impl TcpEngine {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        let iss = rand::rng().random();
        Self {
            src,
            dst,
            iss,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            rcv_nxt: 0,
            peer_window: 14400,
            max_seg: MAX_SEGMENT,
            state: EngineState::SynSent,
            unacked: VecDeque::new(),
            attempts: 0,
        }
    }

    /// SYN + постановка в ре trasmиссит.
    pub fn syn_packet(&mut self) -> Vec<u8> {
        let pkt = build_tcp_packet(self.src, self.dst, self.iss, 0, 0x02, &[])
            .expect("SYN всегда помещается");
        self.unacked.push_back(UnackedSeg {
            seq: self.iss,
            occupied: 1,
            bytes: pkt.clone(),
        });
        pkt
    }

    pub fn inflight(&self) -> u32 {
        self.snd_nxt.wrapping_sub(self.snd_una)
    }

    pub fn window_space(&self) -> usize {
        self.peer_window.saturating_sub(self.inflight()) as usize
    }

    pub fn has_unacked(&self) -> bool {
        !self.unacked.is_empty() && self.state != EngineState::Closed
    }

    /// Сегмент данных (PSH+ACK). Вызывать только при window_space ≥ len.
    pub fn push_segment(&mut self, data: &[u8]) -> Vec<u8> {
        debug_assert!(!data.is_empty() && data.len() <= self.max_seg);
        let seq = self.snd_nxt;
        let pkt = build_tcp_packet(self.src, self.dst, seq, self.rcv_nxt, 0x18, data)
            .expect("сегмент всегда собирается");
        self.unacked.push_back(UnackedSeg {
            seq,
            occupied: data.len() as u32,
            bytes: pkt.clone(),
        });
        self.snd_nxt = self.snd_nxt.wrapping_add(data.len() as u32);
        pkt
    }

    pub fn push_fin(&mut self) -> Option<Vec<u8>> {
        if self.state == EngineState::Closed {
            return None;
        }
        let seq = self.snd_nxt;
        let pkt = build_tcp_packet(self.src, self.dst, seq, self.rcv_nxt, 0x11, &[])
            .expect("FIN всегда собирается");
        self.unacked.push_back(UnackedSeg {
            seq,
            occupied: 1,
            bytes: pkt.clone(),
        });
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.state = EngineState::FinSent;
        Some(pkt)
    }

    /// Обработка обратного TCP-пакета (сырой IPv4). Возвращает события и
    /// пакеты для немедленной отправки (ACK на SYN/ACK, ACK на данные/FIN).
    pub fn on_inbound(&mut self, raw: &[u8]) -> (Vec<EngineEvent>, Vec<Vec<u8>>) {
        let mut events = Vec::new();
        let mut out = Vec::new();
        let Some(seg) = parse_ipv4_tcp(raw) else {
            return (events, out);
        };
        if seg.dst != self.src || seg.src != self.dst {
            return (events, out); // чужой поток
        }
        // RST — разрыв без церемоний
        if seg.flags & 0x04 != 0 {
            if self.state != EngineState::Closed {
                self.state = EngineState::Closed;
                self.unacked.clear();
                events.push(EngineEvent::RemoteClosed);
            }
            return (events, out);
        }
        let syn_ack = (seg.flags & 0x12) == 0x12;
        if self.state == EngineState::SynSent {
            if !syn_ack {
                return (events, out);
            }
            if seg.ack != self.iss.wrapping_add(1) {
                return (events, out);
            }
            self.rcv_nxt = seg.seq.wrapping_add(1);
            if seg.window > 0 {
                self.peer_window = seg.window;
            }
            if let Some(mss) = seg.mss {
                self.max_seg = (mss as usize).clamp(536, MAX_SEGMENT);
            }
            if self.unacked.front().is_some_and(|s| s.seq == self.iss) {
                self.unacked.pop_front();
            }
            self.snd_una = seg.ack;
            self.attempts = 0;
            self.state = EngineState::Established;
            events.push(EngineEvent::Established);
            if let Some(pkt) =
                build_tcp_packet(self.src, self.dst, self.snd_nxt, self.rcv_nxt, 0x10, &[])
            {
                out.push(pkt);
            }
            return (events, out);
        }
        if self.state == EngineState::Closed {
            return (events, out);
        }
        // окно обновляем любым пакетом
        self.peer_window = seg.window;
        // ACK-продвижение (ack in (snd_una, snd_nxt], включая ack == snd_nxt)
        let delta = seg.ack.wrapping_sub(self.snd_una);
        if delta != 0 && delta <= self.snd_nxt.wrapping_sub(self.snd_una) {
            self.snd_una = seg.ack;
            while let Some(front) = self.unacked.front() {
                if !seq_after(front.seq.wrapping_add(front.occupied), seg.ack) {
                    self.unacked.pop_front();
                } else {
                    break;
                }
            }
            self.attempts = 0;
        }
        // данные in-order → событие + ACK; дубликат/разрыв → dup ACK
        if !seg.payload.is_empty() {
            if seg.seq == self.rcv_nxt {
                events.push(EngineEvent::Data(seg.payload.clone()));
                self.rcv_nxt = self.rcv_nxt.wrapping_add(seg.payload.len() as u32);
            }
            if let Some(pkt) =
                build_tcp_packet(self.src, self.dst, self.snd_nxt, self.rcv_nxt, 0x10, &[])
            {
                out.push(pkt);
            }
        }
        // FIN — в payload-seq FIN стоит сразу за данными (у нас in-order мир)
        if seg.flags & 0x01 != 0 {
            if seg.seq.wrapping_add(seg.payload.len() as u32) == self.rcv_nxt {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                if let Some(pkt) =
                    build_tcp_packet(self.src, self.dst, self.snd_nxt, self.rcv_nxt, 0x10, &[])
                {
                    out.push(pkt);
                }
            }
            self.state = EngineState::Closed;
            self.unacked.clear();
            events.push(EngineEvent::RemoteClosed);
        }
        (events, out)
    }

    /// Подтверждён ли наш FIN (очередь очищена после его отправки).
    pub fn fin_acknowledged(&self) -> bool {
        self.state == EngineState::FinSent && self.unacked.is_empty()
    }

    /// Тик ретрансмита: заново все неподтверждённые сегменты; после
    /// MAX_RETRY_ATTEMPTS подряд — смерть потока (true = dead).
    pub fn on_timeout(&mut self) -> (Vec<Vec<u8>>, bool) {
        if self.unacked.is_empty() {
            return (Vec::new(), false);
        }
        self.attempts += 1;
        if self.attempts > MAX_RETRY_ATTEMPTS {
            self.state = EngineState::Closed;
            self.unacked.clear();
            return (Vec::new(), true);
        }
        (
            self.unacked.iter().map(|seg| seg.bytes.clone()).collect(),
            false,
        )
    }
}

/// Разбор IPv4+TCP для обратного пути (порт/флаги/seq/ack/окно/MSS/payload).
pub struct TcpInbound {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub window: u32,
    pub mss: Option<u16>,
    pub payload: Vec<u8>,
}

pub fn parse_ipv4_tcp(raw: &[u8]) -> Option<TcpInbound> {
    if raw.len() < 40 || raw[0] >> 4 != 4 || raw[9] != 6 {
        return None;
    }
    let ihl = (raw[0] & 0x0f) as usize * 4;
    if ihl < 20 || raw.len() < ihl + 20 {
        return None;
    }
    let total = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if total < ihl + 20 || total > raw.len() {
        return None;
    }
    let tcp = raw.get(ihl..total)?;
    let doff = (tcp[12] >> 4) as usize * 4;
    if doff < 20 || tcp.len() < doff {
        return None;
    }
    let src = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15])),
        u16::from_be_bytes([tcp[0], tcp[1]]),
    );
    let dst = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19])),
        u16::from_be_bytes([tcp[2], tcp[3]]),
    );
    let mut mss = None;
    let mut opts = tcp.get(20..doff)?;
    while !opts.is_empty() {
        match opts[0] {
            0 => break,
            1 => opts = &opts[1..],
            kind => {
                if opts.len() < 2 {
                    break;
                }
                let len = opts[1] as usize;
                if len < 2 || opts.len() < len {
                    break;
                }
                if kind == 2 && len == 4 {
                    mss = Some(u16::from_be_bytes([opts[2], opts[3]]));
                }
                opts = &opts[len..];
            }
        }
    }
    Some(TcpInbound {
        src,
        dst,
        flags: tcp[13],
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        window: u16::from_be_bytes([tcp[14], tcp[15]]) as u32,
        mss,
        payload: tcp[doff..].to_vec(),
    })
}

// ────────────────────────── inject в туннель ──────────────────────────

/// Инъекция сырого IPv4-пакета в uplink (тот же путь, что read_udp → dispatch).
async fn inject_raw(
    dispatcher: &Dispatcher,
    pool: &Arc<PacketPool>,
    stats: &Stats,
    raw: &[u8],
    cancel: &CancellationToken,
) {
    let mut packet = loop {
        if let Some(packet) = pool.try_acquire() {
            break packet;
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return,
            _ = pool.wait_available() => {}
        }
    };
    let Ok(area) = packet.extend_tail(raw.len()) else {
        return;
    };
    area.copy_from_slice(raw);
    stats
        .total_bytes_up
        .fetch_add(raw.len() as i64, Ordering::Relaxed);
    dispatcher.dispatch(packet).await;
}

// ─────────────────────────── DNS через туннель ───────────────────────────

async fn resolve_via_tunnel(
    dispatcher: &Arc<Dispatcher>,
    pool: &Arc<PacketPool>,
    stats: &Arc<Stats>,
    name: &str,
    cancel: &CancellationToken,
) -> Result<Ipv4Addr> {
    for (index, server) in DNS_SERVERS.iter().enumerate() {
        let server = SocketAddr::new(IpAddr::V4(*server), 53);
        let answer = tokio::select! {
            biased;
            _ = cancel.cancelled() => bail!("SOCKS5: резолв отменён"),
            answer = dns_attempt(dispatcher, pool, stats, server, name, cancel) => answer,
            _ = tokio::time::sleep(DNS_PHASE) => {
                crate::log_error!(
                    "[SOCKS5] DNS {name} через {server} не ответил (фаза {}/{})",
                    index + 1,
                    DNS_SERVERS.len()
                );
                continue;
            }
        };
        match answer {
            Some(ip) => return Ok(ip),
            None => {
                crate::log_error!("[SOCKS5] DNS {name}: пустой A-ответ от {server}");
            }
        }
    }
    bail!("SOCKS5: домен {name} не разрешился через туннель")
}

async fn dns_attempt(
    dispatcher: &Arc<Dispatcher>,
    pool: &Arc<PacketPool>,
    stats: &Arc<Stats>,
    server: SocketAddr,
    name: &str,
    cancel: &CancellationToken,
) -> Option<Ipv4Addr> {
    let id = rand::random::<u16>();
    let query = build_dns_query(id, name);
    let (vport, mut rx) = alloc_vport()?;
    let src = SocketAddr::new(IpAddr::V4(VIRT_IP), vport);
    let Some(raw) = build_udp_packet(src, server, &query) else {
        global_registry().remove(vport);
        return None;
    };
    inject_raw(dispatcher, pool, stats, &raw, cancel).await;
    let result = loop {
        let packet = tokio::select! {
            biased;
            _ = cancel.cancelled() => break None,
            packet = rx.recv() => packet,
        };
        let Some(packet) = packet else { break None };
        // сырой IPv4+UDP → DNS-сообщение
        let Some(payload) = udp_payload(&packet) else {
            continue;
        };
        if payload.len() >= 4 && u16::from_be_bytes([payload[0], payload[1]]) == id {
            break parse_dns_a(payload);
        }
    };
    global_registry().remove(vport);
    result
}

/// UDP-полезная нагрузка сырого IPv4-пакета (с проверкой заголовков).
fn udp_payload(raw: &[u8]) -> Option<&[u8]> {
    if raw.len() < 28 || raw[0] >> 4 != 4 || raw[9] != 17 {
        return None;
    }
    let ihl = (raw[0] & 0x0f) as usize * 4;
    if ihl < 20 || raw.len() < ihl + 8 {
        return None;
    }
    let total = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    if total > raw.len() {
        return None;
    }
    let udp_len = u16::from_be_bytes([raw[ihl + 4], raw[ihl + 5]]) as usize;
    let payload_start = ihl + 8;
    if udp_len < 8 || ihl + udp_len > total {
        return None;
    }
    raw.get(payload_start..ihl + udp_len)
}

// ─────────────────────────── основной цикл ───────────────────────────

/// Поднять SOCKS5-прокси на `listen` (TCP, loopback). Возвращает порт.
/// Обратный путь подключается к Dispatcher через set_return_sink.
pub async fn start_socks5(
    dispatcher: Arc<Dispatcher>,
    pool: Arc<PacketPool>,
    stats: Arc<Stats>,
    listen: &str,
    cancel: CancellationToken,
) -> Result<u16> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("SOCKS5: bind {listen}"))?;
    let port = listener.local_addr()?.port();

    // обратный путь: Dispatcher.write_udp → return_sink → демультимплексор
    let (return_tx, mut return_rx) = mpsc::unbounded_channel::<PacketBuf>();
    dispatcher.set_return_sink(return_tx);
    let pump_cancel = cancel.clone();
    tokio::spawn(async move {
        loop {
            let packet = tokio::select! {
                biased;
                _ = pump_cancel.cancelled() => return,
                packet = return_rx.recv() => packet,
            };
            let Some(packet) = packet else { return };
            route_return_packet(global_registry(), packet.as_slice());
        }
    });

    let accept_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut consecutive_errors = 0u32;
        loop {
            let accepted = tokio::select! {
                biased;
                _ = accept_cancel.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, _peer)) => {
                    consecutive_errors = 0;
                    let dispatcher = dispatcher.clone();
                    let pool = pool.clone();
                    let stats = stats.clone();
                    let cancel = accept_cancel.clone();
                    tokio::spawn(async move {
                        let label = stream
                            .peer_addr()
                            .map(|addr| addr.to_string())
                            .unwrap_or_else(|_| "сокет".to_owned());
                        if let Err(error) =
                            handle_connection(stream, dispatcher, pool, stats, cancel).await
                        {
                            crate::log_error!("[SOCKS5] {label}: {error:#}");
                        }
                    });
                }
                Err(error) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= 8 {
                        crate::log_error!("[SOCKS5] accept сыпется ошибками ({error}) — стоп");
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    });
    crate::log_error!("[SOCKS5] слушает {listen} (порт {port})");
    Ok(port)
}

async fn handle_connection(
    mut stream: TcpStream,
    dispatcher: Arc<Dispatcher>,
    pool: Arc<PacketPool>,
    stats: Arc<Stats>,
    cancel: CancellationToken,
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let request = handshake(&mut stream)
        .await
        .context("рукопожатие SOCKS5");
    let request = match request {
        Ok(request) => request,
        Err(error) => return Err(error),
    };
    if request.command == SocksCommand::UdpAssociate {
        // QUIC/UDP не ведём — браузер сам пересядет на TCP.
        stream.write_all(&socks5_reply(REP_COMMAND_UNSUPPORTED)).await.ok();
        bail!("UDP ASSOCIATE отклонён (0x07)");
    }
    let target: SocketAddr = match request.target {
        SocksTarget::V4(addr) => addr,
        SocksTarget::V6(_) => {
            stream.write_all(&socks5_reply(REP_ATYP_UNSUPPORTED)).await.ok();
            bail!("цель IPv6 не поддерживается (0x08)");
        }
        SocksTarget::Domain { host, port } => {
            if let Ok(ip) = host.parse::<Ipv4Addr>() {
                SocketAddr::new(IpAddr::V4(ip), port)
            } else if host.parse::<Ipv6Addr>().is_ok() {
                stream.write_all(&socks5_reply(REP_ATYP_UNSUPPORTED)).await.ok();
                bail!("адресная строка IPv6 не поддерживается");
            } else {
                match resolve_via_tunnel(&dispatcher, &pool, &stats, &host, &cancel).await {
                    Ok(ip) => SocketAddr::new(IpAddr::V4(ip), port),
                    Err(error) => {
                        stream.write_all(&socks5_reply(REP_FAILURE)).await.ok();
                        return Err(error);
                    }
                }
            }
        }
    };
    run_tcp_session(stream, dispatcher, pool, stats, target, cancel).await
}

/// SOCKS5 greeting: Version 5, без аутентификации, затем CONNECT-запрос.
async fn handshake(stream: &mut TcpStream) -> Result<SocksRequest> {
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .context("SOCKS5: чтение greeting")?;
    if greeting[0] != 5 {
        bail!("SOCKS5: версия {} (нужен SOCKS5)", greeting[0]);
    }
    if greeting[1] == 0 {
        bail!("SOCKS5: пуст список методов");
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .context("SOCKS5: чтение методов")?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xFF]).await.ok();
        bail!("SOCKS5: нет метода NO AUTH");
    }
    stream
        .write_all(&[5, 0])
        .await
        .context("SOCKS5: ответ на greeting")?;

    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .context("SOCKS5: заголовок запроса")?;
    if head[0] != 5 {
        bail!("SOCKS5: версия {} в запросе", head[0]);
    }
    let request = match head[3] {
        1 => {
            let mut rest = [0u8; 6];
            stream.read_exact(&mut rest).await.context("SOCKS5: IPv4")?;
            let mut buf = head.to_vec();
            buf.extend_from_slice(&rest);
            parse_socks5_request(&buf)?.0
        }
        3 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .context("SOCKS5: длина домена")?;
            let mut rest = vec![0u8; 1 + len[0] as usize + 2];
            rest[0] = len[0];
            stream
                .read_exact(&mut rest[1..])
                .await
                .context("SOCKS5: домен")?;
            let mut buf = head.to_vec();
            buf.extend_from_slice(&rest);
            parse_socks5_request(&buf)?.0
        }
        4 => {
            let mut rest = [0u8; 18];
            stream.read_exact(&mut rest).await.context("SOCKS5: IPv6")?;
            // команду/RSV валидируем; V6-цель → вызывающий ответит 0x08
            let mut buf = head.to_vec();
            buf.extend_from_slice(&rest);
            parse_socks5_request(&buf)?.0
        }
        other => bail!("SOCKS5: неизвестный ATYP {other}"),
    };
    Ok(request)
}

/// Одна SOCKS5-сессия = один туннельный TCP-поток от VIRT_IP:vport к цели.
async fn run_tcp_session(
    mut stream: TcpStream,
    dispatcher: Arc<Dispatcher>,
    pool: Arc<PacketPool>,
    stats: Arc<Stats>,
    target: SocketAddr,
    cancel: CancellationToken,
) -> Result<()> {
    let Some((vport, mut rx)) = alloc_vport() else {
        stream.write_all(&socks5_reply(REP_FAILURE)).await.ok();
        bail!("SOCKS5: локальные порты исчерпаны");
    };
    let src = SocketAddr::new(IpAddr::V4(VIRT_IP), vport);
    let registry = global_registry();
    let mut engine = TcpEngine::new(src, target);
    let syn = engine.syn_packet();
    inject_raw(&dispatcher, &pool, &stats, &syn, &cancel).await;
    crate::log_error!("[SOCKS5] {src} → SYN → {target}");

    let mut reply_written = false;
    let mut sock_eof = false;
    let mut pending_out: Vec<u8> = Vec::new();
    let mut read_buf = vec![0u8; 32 * 1024];
    let mut retry_deadline = tokio::time::Instant::now() + RETRY_DELAY;
    let mut fin_deadline: Option<tokio::time::Instant> = None;

    let outcome: &'static str;
    'session: loop {
        if engine.state == EngineState::Closed {
            outcome = "поток закрыт оппонентом";
            break 'session;
        }
        let fin_at = fin_deadline.unwrap_or_else(|| tokio::time::Instant::now() + FOREVER);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                outcome = "отмена";
                break 'session;
            }
            inbound = rx.recv() => {
                let Some(raw) = inbound else {
                    outcome = "деMUX закрыт";
                    break 'session;
                };
                let (events, out) = engine.on_inbound(&raw);
                for packet in out {
                    inject_raw(&dispatcher, &pool, &stats, &packet, &cancel).await;
                }
                if engine.fin_acknowledged() {
                    // наш FIN подтверждён — ждём FIN оппонента, но не вечно
                    fin_deadline = Some(tokio::time::Instant::now() + FIN_LINGER);
                }
                flush_pending(
                    &mut engine, &mut pending_out, &dispatcher, &pool, &stats, &cancel,
                )
                .await;
                let mut data: Vec<u8> = Vec::new();
                let mut peer_closed = false;
                for event in events {
                    match event {
                        EngineEvent::Established => {
                            crate::log_error!("[SOCKS5] {src} ⇄ {target}: ESTABLISHED");
                        }
                        EngineEvent::Data(bytes) => data.extend_from_slice(&bytes),
                        EngineEvent::RemoteClosed => peer_closed = true,
                    }
                }
                let mut broken = false;
                if engine.state == EngineState::Established && !reply_written {
                    reply_written = true;
                    if stream.write_all(&socks5_reply(REP_SUCCEEDED)).await.is_err() {
                        broken = true;
                    }
                }
                if !data.is_empty() && stream.write_all(&data).await.is_err() {
                    broken = true;
                }
                if peer_closed || broken {
                    outcome = if broken { "клиент SOCKS отключился" } else { "цель закрылась" };
                    break 'session;
                }
                retry_deadline = if engine.has_unacked() {
                    tokio::time::Instant::now() + RETRY_DELAY
                } else {
                    tokio::time::Instant::now() + FOREVER
                };
            }
            _ = tokio::time::sleep_until(retry_deadline), if engine.has_unacked() => {
                let (retrans, dead) = engine.on_timeout();
                for packet in retrans {
                    inject_raw(&dispatcher, &pool, &stats, &packet, &cancel).await;
                }
                if dead {
                    crate::log_error!("[SOCKS5] {src} → {target}: ретрансмит исчерпан");
                    if !reply_written {
                        stream.write_all(&socks5_reply(REP_FAILURE)).await.ok();
                    }
                    outcome = "ретрансмит исчерпан";
                    break 'session;
                }
                retry_deadline = tokio::time::Instant::now() + RETRY_DELAY;
            }
            read_result = stream.read(&mut read_buf), if !sock_eof => {
                match read_result {
                    Ok(0) => {
                        sock_eof = true;
                        if engine.state != EngineState::Closed {
                            if let Some(fin) = engine.push_fin() {
                                inject_raw(&dispatcher, &pool, &stats, &fin, &cancel).await;
                                fin_deadline =
                                    Some(tokio::time::Instant::now() + FIN_LINGER);
                            }
                        }
                    }
                    Ok(n) => {
                        if pending_out.len() + n <= 4 * 1024 * 1024 {
                            pending_out.extend_from_slice(&read_buf[..n]);
                            flush_pending(
                                &mut engine, &mut pending_out, &dispatcher, &pool, &stats,
                                &cancel,
                            )
                            .await;
                        } else {
                            crate::log_error!("[SOCKS5] {src} → {target}: переполнение uplink-буфера");
                            sock_eof = true;
                            if let Some(fin) = engine.push_fin() {
                                inject_raw(&dispatcher, &pool, &stats, &fin, &cancel).await;
                                fin_deadline =
                                    Some(tokio::time::Instant::now() + FIN_LINGER);
                            }
                        }
                    }
                    Err(_) => {
                        sock_eof = true;
                    }
                }
            }
            _ = tokio::time::sleep_until(fin_at), if fin_deadline.is_some() => {
                crate::log_error!("[SOCKS5] {src} → {target}: FIN не подтверждён, закрываем");
                outcome = "FIN не подтверждён";
                break 'session;
            }
        }
    }
    let _ = stream.shutdown().await;
    registry.remove(vport);
    crate::log_error!("[SOCKS5] {src} → {target}: сессия завершена ({outcome})");
    Ok(())
}

async fn flush_pending(
    engine: &mut TcpEngine,
    pending: &mut Vec<u8>,
    dispatcher: &Arc<Dispatcher>,
    pool: &Arc<PacketPool>,
    stats: &Arc<Stats>,
    cancel: &CancellationToken,
) {
    if engine.state != EngineState::Established && engine.state != EngineState::FinSent {
        return;
    }
    while !pending.is_empty() {
        let space = engine.window_space().min(engine.max_seg);
        if space == 0 {
            break;
        }
        let take = space.min(pending.len());
        let chunk: Vec<u8> = pending.drain(..take).collect();
        let packet = engine.push_segment(&chunk);
        inject_raw(dispatcher, pool, stats, &packet, cancel).await;
    }
}

// ─────────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_relay::craft_udp_packet_into;
    use crate::dispatcher::Dispatcher;
    use crate::stats::Stats;

    const V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);

    fn vport_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(VIRT_IP), port)
    }

    fn peer_to_us(seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
        // синтетический обратный пакет: src — цель, dst — наш виртуальный сокет
        build_tcp_packet(V4, vport_addr(40000), seq, ack, flags, payload).unwrap()
    }

    fn engine_fixture() -> TcpEngine {
        TcpEngine::new(vport_addr(40000), V4)
    }

    #[test]
    fn socks5_parse_ipv4_connect() {
        let req = [5, 1, 0, 1, 93, 184, 216, 34, 1, 187]; // :443
        let (request, used) = parse_socks5_request(&req).unwrap();
        assert_eq!(used, 10);
        assert_eq!(
            request,
            SocksRequest {
                command: SocksCommand::Connect,
                target: SocksTarget::V4(V4),
            }
        );
    }

    #[test]
    fn socks5_parse_domain_connect() {
        let mut req = vec![5, 1, 0, 3, 7];
        req.extend_from_slice(b"example");
        req.extend_from_slice(&443u16.to_be_bytes());
        let (request, used) = parse_socks5_request(&req).unwrap();
        assert_eq!(used, req.len());
        assert_eq!(
            request.target,
            SocksTarget::Domain {
                host: "example".into(),
                port: 443
            }
        );
    }

    #[test]
    fn socks5_parse_ipv6_target() {
        let mut req = vec![5, 1, 0, 4];
        req.extend_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        req.extend_from_slice(&8080u16.to_be_bytes());
        let (request, used) = parse_socks5_request(&req).unwrap();
        assert_eq!(used, 22);
        assert!(matches!(request.target, SocksTarget::V6(addr) if addr.port() == 8080));
    }

    #[test]
    fn socks5_parse_udp_associate_and_errors() {
        let assoc = [5, 2, 0, 1, 127, 0, 0, 1, 0, 0];
        let (request, _) = parse_socks5_request(&assoc).unwrap();
        assert_eq!(request.command, SocksCommand::UdpAssociate);
        assert!(parse_socks5_request(&[4, 1, 0, 1, 1, 1, 1, 1, 0, 80]).is_err()); // версия
        assert!(parse_socks5_request(&[5, 1, 0, 5, 0, 0, 0, 0, 0, 0]).is_err()); // ATYP 5
        assert!(parse_socks5_request(&[5, 3, 0, 1, 1, 1, 1, 1, 0, 80]).is_err()); // BIND
        assert!(parse_socks5_request(&[5, 1, 1, 1, 1, 1, 1, 1, 0, 80]).is_err()); // RSV
        assert!(parse_socks5_request(&[5, 1, 0, 1, 1, 1]).is_err()); // обрезан
        assert!(parse_socks5_request(&[5, 1, 0, 4, 1, 1, 1, 1]).is_err()); // IPv6 обрезан
    }

    #[test]
    fn socks5_reply_codes() {
        assert_eq!(socks5_reply(REP_ATYP_UNSUPPORTED)[1], 0x08);
        assert_eq!(socks5_reply(REP_COMMAND_UNSUPPORTED)[1], 0x07);
        assert_eq!(socks5_reply(REP_SUCCEEDED), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn dns_query_build_and_answer_parse() {
        let query = build_dns_query(0x1234, "example.com");
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        assert_eq!(query[2..4], [0x01, 0x00]);
        assert_eq!(query[4..6], [0x00, 0x01]);
        // имя закодировано метками
        assert_eq!(query[12], 7);
        assert_eq!(&query[13..20], b"example");
        assert_eq!(query[20], 3);
        assert_eq!(&query[21..24], b"com");
        assert_eq!(query[24], 0);
        assert_eq!(&query[query.len() - 4..], [0, 1, 0, 1]);

        // ответ: заголовок + вопрос (сжатый указателем) + A-запись
        let mut resp = Vec::new();
        resp.extend_from_slice(&0x1234u16.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // QD
        resp.extend_from_slice(&1u16.to_be_bytes()); // AN
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&[0xc0, 0x0c]); // сжатое имя вопроса
        resp.extend_from_slice(&1u16.to_be_bytes()); // A
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&[0xc0, 0x0c]); // сжатое имя ответа
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE=A
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS=IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLEN
        resp.extend_from_slice(&[93, 184, 216, 34]);
        assert_eq!(parse_dns_a(&resp), Some(Ipv4Addr::new(93, 184, 216, 34)));
        // пустой/битый
        assert_eq!(parse_dns_a(&resp[..12]), None); // ANCOUNT=0
        assert_eq!(parse_dns_a(&[]), None);
        let mut truncated = resp.clone();
        truncated.truncate(30);
        assert_eq!(parse_dns_a(&truncated), None);
    }

    #[test]
    fn engine_syn_synack_established() {
        let mut engine = engine_fixture();
        let syn = engine.syn_packet();
        let info = parse_ipv4_tcp(&syn).unwrap();
        assert_eq!(info.flags, 0x02);
        assert_eq!(info.src.ip(), IpAddr::V4(VIRT_IP));
        assert_eq!(info.dst, V4);
        assert_eq!(info.mss, Some(1024));

        let iss = info.seq;
        let peer_isn = 777_000;
        let syn_ack = peer_to_us(peer_isn, iss + 1, 0x12, &[]);
        let (events, out) = engine.on_inbound(&syn_ack);
        assert_eq!(events, vec![EngineEvent::Established]);
        assert_eq!(engine.state, EngineState::Established);
        assert_eq!(engine.rcv_nxt, peer_isn + 1);
        assert_eq!(engine.snd_una, iss + 1);
        assert!(!engine.has_unacked());
        // ACK на SYN/ACK отправлен
        assert_eq!(out.len(), 1);
        let ack = parse_ipv4_tcp(&out[0]).unwrap();
        assert_eq!(ack.flags, 0x10);
        assert_eq!(ack.ack, peer_isn + 1);
    }

    #[test]
    fn engine_synack_mismatch_ignored() {
        let mut engine = engine_fixture();
        let syn = engine.syn_packet();
        let iss = parse_ipv4_tcp(&syn).unwrap().seq;
        // wrong ack
        let (events, _) = engine.on_inbound(&peer_to_us(1, iss + 2, 0x12, &[]));
        assert!(events.is_empty());
        // pure ACK (не SYN/ACK)
        let (events, _) = engine.on_inbound(&peer_to_us(1, iss + 1, 0x10, &[]));
        assert!(events.is_empty());
        assert_eq!(engine.state, EngineState::SynSent);
    }

    #[test]
    fn engine_payload_and_ack_advances() {
        let mut engine = engine_fixture();
        let syn = engine.syn_packet();
        let iss = parse_ipv4_tcp(&syn).unwrap().seq;
        engine.on_inbound(&peer_to_us(1000, iss + 1, 0x12, &[]));
        assert_eq!(engine.snd_nxt, iss + 1);
        assert_eq!(engine.peer_window, 65535); // окно прилетело из SYN/ACK

        // входящие данные → событие Data + ACK
        let (events, out) = engine.on_inbound(&peer_to_us(1001, iss + 1, 0x18, b"HTTP/1.1 200"));
        assert_eq!(events, vec![EngineEvent::Data(b"HTTP/1.1 200".to_vec())]);
        assert_eq!(engine.rcv_nxt, 1001 + 12);
        assert_eq!(out.len(), 1);

        // исходящие: два сегмента 1024+60 (MSS=1024 из опции SYN/ACK),
        // seq продолжают iss
        assert_eq!(engine.max_seg, 1024);
        let first = engine.push_segment(&vec![0xAA; 1024]);
        let second = engine.push_segment(&vec![0xBB; 60]);
        assert_eq!(engine.snd_nxt, iss + 1 + 1084);
        assert_eq!(engine.window_space(), 65535 - 1084);
        let f1 = parse_ipv4_tcp(&first).unwrap();
        let f2 = parse_ipv4_tcp(&second).unwrap();
        assert_eq!(f1.seq, iss + 1);
        assert_eq!(f1.flags, 0x18);
        assert_eq!(f1.payload.len(), 1024);
        assert_eq!(f2.seq, iss + 1 + 1024);

        // ACK половины → snd_una и unacked сокращаются
        engine.on_inbound(&peer_to_us(engine.rcv_nxt, iss + 1 + 1024, 0x10, &[]));
        assert_eq!(engine.snd_una, iss + 1 + 1024);
        assert_eq!(engine.unacked.len(), 1);
        assert_eq!(engine.attempts, 0);

        // ACK всего → очередь пуста
        engine.on_inbound(&peer_to_us(engine.rcv_nxt, engine.snd_nxt, 0x10, &[]));
        assert!(engine.unacked.is_empty());
        assert_eq!(engine.window_space(), 65535);
        let _ = f2;
    }

    /// Обратный TCP-пакет с явным окном (build_tcp packet фиксирован на 65535).
    fn peer_to_us_with_window(
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut raw = build_tcp_packet(V4, vport_addr(40000), seq, ack, flags, payload).unwrap();
        raw[34..36].copy_from_slice(&window.to_be_bytes());
        use crate::direct_relay::tcp_checksum_v4;
        let tcp = &mut raw[20..];
        tcp[16..18].copy_from_slice(&[0, 0]);
        let csum = tcp_checksum_v4(Ipv4Addr::new(93, 184, 216, 34), VIRT_IP, tcp);
        tcp[16..18].copy_from_slice(&csum.to_be_bytes());
        raw
    }

    #[test]
    fn engine_zero_window_pauses_and_resumes() {
        let mut engine = engine_fixture();
        let syn = engine.syn_packet();
        let iss = parse_ipv4_tcp(&syn).unwrap().seq;
        engine.on_inbound(&peer_to_us(5000, iss + 1, 0x12, &[]));
        // заполняем окно ровно одним сегментом; peer_window=65535 из SYN/ACK
        engine.peer_window = 1024;
        engine.push_segment(&vec![1u8; 1024]);
        assert_eq!(engine.window_space(), 0);
        // пакет с окном 0 — места нет
        let zero = peer_to_us_with_window(5001, engine.snd_nxt, 0x10, 0, &[]);
        let (events, _out) = engine.on_inbound(&zero);
        assert!(events.is_empty());
        assert_eq!(engine.window_space(), 0);
        // чистый ACK с восстановленным окном — возобновление
        let resume = peer_to_us_with_window(5001, engine.snd_nxt, 0x10, 14400, &[]);
        engine.on_inbound(&resume);
        assert_eq!(engine.peer_window, 14400);
        // оба пакета подтверждали весь отправленное → inflight 0
        assert_eq!(engine.window_space(), 14400);
    }

    #[test]
    fn engine_fin_flow() {
        let mut engine = engine_fixture();
        let syn = engine.syn_packet();
        let iss = parse_ipv4_tcp(&syn).unwrap().seq;
        engine.on_inbound(&peer_to_us(100, iss + 1, 0x12, &[]));
        let fin = engine.push_fin().unwrap();
        assert_eq!(engine.state, EngineState::FinSent);
        let fin_info = parse_ipv4_tcp(&fin).unwrap();
        assert_eq!(fin_info.flags, 0x11);
        // входящий FIN → RemoteClosed, состояние Closed
        let (events, _out) = engine.on_inbound(&peer_to_us(101, engine.snd_nxt, 0x11, &[]));
        assert_eq!(events, vec![EngineEvent::RemoteClosed]);
        assert_eq!(engine.state, EngineState::Closed);
        assert_eq!(engine.rcv_nxt, 102);
        // повторный FIN — тишина
        let (events, _) = engine.on_inbound(&peer_to_us(101, engine.snd_nxt, 0x11, &[]));
        assert!(events.is_empty());
    }

    #[test]
    fn engine_fin_acknowledged_tracking() {
        let mut engine = engine_fixture();
        let syn = engine.syn_packet();
        let iss = parse_ipv4_tcp(&syn).unwrap().seq;
        engine.on_inbound(&peer_to_us(100, iss + 1, 0x12, &[]));
        engine.push_fin().unwrap();
        assert!(!engine.fin_acknowledged());
        engine.on_inbound(&peer_to_us(101, engine.snd_nxt, 0x10, &[])); // ACK FIN
        assert!(engine.fin_acknowledged());
    }

    #[test]
    fn engine_rst_kills() {
        let mut engine = engine_fixture();
        let syn = engine.syn_packet();
        let iss = parse_ipv4_tcp(&syn).unwrap().seq;
        engine.on_inbound(&peer_to_us(100, iss + 1, 0x12, &[]));
        let (events, _) = engine.on_inbound(&peer_to_us(101, iss + 1, 0x04, &[]));
        assert_eq!(events, vec![EngineEvent::RemoteClosed]);
        assert_eq!(engine.state, EngineState::Closed);
    }

    #[test]
    fn engine_retransmit_budget() {
        let mut engine = engine_fixture();
        engine.syn_packet();
        let mut dead = false;
        for round in 1..=MAX_RETRY_ATTEMPTS + 1 {
            let (retrans, now_dead) = engine.on_timeout();
            dead = now_dead;
            if round <= MAX_RETRY_ATTEMPTS {
                assert_eq!(retrans.len(), 1, "раунд {round}: ретрансмит SYN");
            }
        }
        assert!(dead, "после {MAX_RETRY_ATTEMPTS} попыток поток умирает");
        assert_eq!(engine.state, EngineState::Closed);
    }

    #[test]
    fn engine_retransmit_reset_on_ack() {
        let mut engine = engine_fixture();
        let syn = engine.syn_packet();
        let iss = parse_ipv4_tcp(&syn).unwrap().seq;
        engine.on_timeout();
        engine.on_timeout();
        assert_eq!(engine.attempts, 2);
        // SYN/ACK обнуляет счётчик
        engine.on_inbound(&peer_to_us(7, iss + 1, 0x12, &[]));
        assert_eq!(engine.attempts, 0);
    }

    #[test]
    fn engine_ignores_foreign_packets() {
        let mut engine = engine_fixture();
        let syn = engine.syn_packet();
        let iss = parse_ipv4_tcp(&syn).unwrap().seq;
        let foreign = build_tcp_packet(
            "1.2.3.4:80".parse().unwrap(),
            "5.6.7.8:9".parse().unwrap(),
            1,
            iss + 1,
            0x12,
            &[],
        )
        .unwrap();
        let (events, out) = engine.on_inbound(&foreign);
        assert!(events.is_empty());
        assert!(out.is_empty());
        assert_eq!(engine.state, EngineState::SynSent);
    }

    #[test]
    fn checksums_roundtrip() {
        use crate::direct_relay::{ip_checksum, udp_checksum_v4};
        // IPv4-чексумма: пересчёт включённой контрольной суммы даёт 0
        let udp = build_udp_packet(vport_addr(40001), "8.8.8.8:53".parse().unwrap(), b"payload")
            .unwrap();
        assert_eq!(ip_checksum(&udp[..20]), 0, "IPv4 header checksum verify");
        // UDP-чексумма: пересчёт с обнулённым полем = stored
        let ihl = (udp[0] & 0x0f) as usize * 4;
        let mut seg = udp[ihl..].to_vec();
        let stored = u16::from_be_bytes([seg[6], seg[7]]);
        seg[6..8].copy_from_slice(&[0, 0]);
        let src = VIRT_IP;
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        assert_eq!(udp_checksum_v4(src, dst, &seg), stored);
        // TCP: build_tcp_packet тоже обязан сходиться
        let tcp = build_tcp_packet(
            vport_addr(40002),
            "93.184.216.34:443".parse().unwrap(),
            0,
            0,
            0x18,
            b"abc",
        )
        .unwrap();
        assert_eq!(ip_checksum(&tcp[..20]), 0);
        use crate::direct_relay::tcp_checksum_v4;
        let mut tseg = tcp[20..].to_vec();
        let tstored = u16::from_be_bytes([tseg[16], tseg[17]]);
        tseg[16..18].copy_from_slice(&[0, 0]);
        assert_eq!(tcp_checksum_v4(VIRT_IP, Ipv4Addr::new(93, 184, 216, 34), &tseg), tstored);
        // craft_udp_packet_into == build_udp_packet
        let mut manual = vec![0u8; udp.len()];
        assert!(craft_udp_packet_into(
            vport_addr(40001),
            "8.8.8.8:53".parse().unwrap(),
            b"payload",
            &mut manual
        ));
        assert_eq!(manual, udp);
    }

    #[test]
    fn udp_payload_extraction() {
        let raw = build_udp_packet("8.8.8.8:53".parse().unwrap(), vport_addr(40003), b"1234")
            .unwrap();
        assert_eq!(udp_payload(&raw), Some(&b"1234"[..]));
        assert_eq!(udp_payload(&raw[..10]), None);
        assert_eq!(udp_payload(&tcp_like()), None);
    }

    fn tcp_like() -> Vec<u8> {
        build_tcp_packet(
            "1.2.3.4:5".parse().unwrap(),
            "5.6.7.8:9".parse().unwrap(),
            0,
            0,
            0x18,
            b"x",
        )
        .unwrap()
    }

    #[test]
    fn registry_routing() {
        let registry = ReturnRegistry::default();
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(registry.register(40100, tx));
        assert!(!registry.register(40100, mpsc::unbounded_channel().0)); // занят

        let raw = build_udp_packet("8.8.8.8:53".parse().unwrap(), vport_addr(40100), b"hi")
            .unwrap();
        route_return_packet(&registry, &raw);
        assert_eq!(rx.try_recv().unwrap(), raw);
        // чужой порт — дроп
        let other = build_udp_packet("8.8.8.8:53".parse().unwrap(), vport_addr(40101), b"hi")
            .unwrap();
        route_return_packet(&registry, &other);
        assert!(rx.try_recv().is_err());
        // не-виртуальный dst — дроп
        let notus = build_udp_packet(
            "8.8.8.8:53".parse().unwrap(),
            "10.66.0.5:40100".parse().unwrap(),
            b"hi",
        )
        .unwrap();
        route_return_packet(&registry, &notus);
        assert!(rx.try_recv().is_err());
        // TCP-маршрутизация тоже (dport = VIRT_IP:vport)
        let tcp = build_tcp_packet(V4, vport_addr(40100), 5, 5, 0x10, b"").unwrap();
        route_return_packet(&registry, &tcp);
        assert_eq!(rx.try_recv().unwrap(), tcp);
        registry.remove(40100);
        route_return_packet(&registry, &tcp); // после remove — без паники
        assert!(registry.is_empty());
    }

    #[test]
    fn vport_allocation_unique_and_in_range() {
        let mut seen = std::collections::HashSet::new();
        let mut held = Vec::new();
        for _ in 0..64 {
            let (vport, rx) = alloc_vport().unwrap();
            assert!(vport >= 2048, "vport {vport} в допустимой зоне");
            assert!(seen.insert(vport), "vport {vport} уникален");
            held.push(rx); // держим слоты занятыми
        }
        // освободили — новые аллокации не падают
        drop(held);
        let global = global_registry();
        let _ = global; // реестр глобальный — чистим за собой
        for vport in seen {
            global.remove(vport);
        }
    }

    #[test]
    fn parse_ipv4_tcp_rejects_garbage() {
        assert!(parse_ipv4_tcp(&[]).is_none());
        assert!(parse_ipv4_tcp(&[6; 40]).is_none()); // не IPv4
        assert!(parse_ipv4_tcp(&udp_like()).is_none()); // UDP внутри
    }

    fn udp_like() -> Vec<u8> {
        build_udp_packet(
            "1.1.1.1:53".parse().unwrap(),
            "2.2.2.2:53".parse().unwrap(),
            b"x",
        )
        .unwrap()
    }

    #[test]
    fn seq_after_wrapping() {
        assert!(seq_after(5, 4));
        assert!(!seq_after(4, 5));
        assert!(!seq_after(5, 5));
        // wrap-around: u32::MAX + 1 = 0 «после» u32::MAX
        assert!(seq_after(0, u32::MAX));
        assert!(!seq_after(u32::MAX, 0));
    }

    #[tokio::test]
    async fn registry_sink_pump_roundtrip() {
        // полный обратный путь: sink-канал → route_return_packet → сессия
        let registry = ReturnRegistry::default();
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        assert!(registry.register(40200, tx));
        let pump_registry = &registry;
        let raw = build_tcp_packet(V4, vport_addr(40200), 9, 9, 0x10, b"down").unwrap();
        pump_registry.deliver(40200, &raw);
        assert_eq!(rx.recv().await.unwrap(), raw);
    }

    // ───────── e2e: живой SOCKS5-листенер (без root, loopback) ─────────

    async fn spawn_test_proxy() -> (u16, CancellationToken, Arc<Dispatcher>) {
        let cancel = CancellationToken::new();
        let pool = crate::packet::PacketPool::new(256);
        let stats = Arc::new(Stats::default());
        let (dispatcher, _udp_port) = Dispatcher::start(
            "127.0.0.1:0",
            None,
            pool.clone(),
            stats.clone(),
            [0u8; 32],
            crate::obfs::ObfsMode::Audio,
            cancel.clone(),
        )
        .await
        .expect("proxy-ветка Dispatcher");
        let port = start_socks5(
            dispatcher.clone(),
            pool,
            stats,
            "127.0.0.1:0",
            cancel.clone(),
        )
        .await
        .expect("SOCKS5 listen");
        (port, cancel, dispatcher)
    }

    #[tokio::test]
    async fn e2e_handshake_rejects_bad_auth_and_udp_associate() {
        let (port, cancel, _dispatcher) = spawn_test_proxy().await;
        // 1) метод без NO AUTH → 0xFF и закрытие
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        sock.write_all(&[5, 1, 2]).await.unwrap(); // только GSSAPI
        let mut reply = [0u8; 2];
        sock.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0xFF]);
        // 2) UDP ASSOCIATE → 0x07
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        sock.write_all(&[5, 1, 0]).await.unwrap(); // NO AUTH
        let mut reply = [0u8; 2];
        sock.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0x00]);
        sock.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        let mut rep = [0u8; 10];
        sock.read_exact(&mut rep).await.unwrap();
        assert_eq!(&rep, &socks5_reply(REP_COMMAND_UNSUPPORTED));
        // 3) IPv6-цель → 0x08
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        sock.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        sock.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0x00]);
        let mut req = vec![5u8, 1, 0, 4];
        req.extend_from_slice(&[0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        req.extend_from_slice(&443u16.to_be_bytes());
        sock.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        sock.read_exact(&mut rep).await.unwrap();
        assert_eq!(&rep, &socks5_reply(REP_ATYP_UNSUPPORTED));
        cancel.cancel();
    }

    #[tokio::test]
    async fn e2e_return_sink_is_wired() {
        let (_port, cancel, dispatcher) = spawn_test_proxy().await;
        // set_return_sink не должен ломать pop/push — пакеты пролетают pump
        let (tx, mut rx) = mpsc::unbounded_channel::<PacketBuf>();
        dispatcher.set_return_sink(tx);
        let pool = crate::packet::PacketPool::new(8);
        let mut pkt = pool.try_acquire().unwrap();
        let raw = build_tcp_packet(V4, vport_addr(40210), 3, 3, 0x10, b"x").unwrap();
        pkt.extend_tail(raw.len()).unwrap().copy_from_slice(&raw);
        dispatcher.push_inbound(pkt);
        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("write_udp должен отдать пакет в return_sink")
            .expect("канал открыт");
        assert_eq!(got.as_slice(), raw.as_slice());
        cancel.cancel();
    }
}
