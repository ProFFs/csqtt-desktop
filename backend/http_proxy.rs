// [DESKTOP] HTTP CONNECT-прокси (v1.5.1, «прокси как в Happ»): второй вход
// proxy-режима рядом с SOCKS5. Windows-браузеры через системный прокси
// (WinINet/IE-механизм) SOCKS5 не умеют — HTTP-прокси надёжнее.
//
// Протокол: клиент шлёт «CONNECT host:port HTTP/1.1 [...]» (или пустой
// метод — некоторые клиенты просто бросают соединение: игнорим молча).
// На CONNECT: парсим host:port, домен — через туннельный DNS, цель —
// в общий TCP-движок (socks5::run_tcp_session), сразу после SYN/ACK
// отдаём «HTTP/1.1 200 Connection Established» и трубитим байты в обе
// стороны. Обычные GET-ы (HTTP-трафик через прокси) в туннель не ведут:
// CONNECT-only-прокси обязан их отвергать — 501.

use crate::dispatcher::Dispatcher;
use crate::packet::PacketPool;
use crate::socks5::{resolve_via_tunnel, run_tcp_session};
use crate::stats::Stats;
use anyhow::{Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

const TAG: &str = "HTTP";
const MAX_HEADER_LINE: usize = 8 * 1024;
const CONNECT_OK: &[u8] =
    b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: csqtt\r\n\r\n";
const BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nProxy-Agent: csqtt\r\n\
     Connection: close\r\n\r\n";
const NOT_SUPPORTED: &[u8] = b"HTTP/1.1 501 Not Implemented\r\nProxy-Agent: csqtt\r\n\
     Connection: close\r\n\r\n";
const BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: csqtt\r\n\
     Connection: close\r\n\r\n";

/// Разбор request-line: «METHOD SP TARGET SP HTTP/x.y» → (method, target).
pub fn parse_request_line(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.splitn(3, ' ');
    let method = parts.next()?.trim();
    let target = parts.next()?;
    let version = parts.next()?;
    if method.is_empty() || target.is_empty() || !version.starts_with("HTTP/") {
        return None;
    }
    Some((method, target))
}

/// Разбор authority из CONNECT-цели: «host:port» (скобки IPv6) или «host port»
/// (форме CONNECT прокси часто прилетает без двоеточия — порт тогда берём из
/// второго аргумента). Возвращает (host, port-или-None).
pub fn parse_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if authority.starts_with('[') {
        // IPv6-литерал: [::1]:443
        let close = authority.find(']')?;
        let rest = &authority[close + 1..];
        let port = rest.strip_prefix(':')?.parse::<u16>().ok();
        Some((&authority[1..close], port))
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().ok()),
            None => (authority, None),
        };
        if host.is_empty() {
            return None;
        }
        Some((host, port))
    }
}

/// Поднять HTTP CONNECT-прокси на `listen` (TCP, loopback). Возвращает порт.
/// Требует уже активный return_sink SOCKS5-режима (общий реестр vport).
pub async fn start_http_proxy(
    dispatcher: Arc<Dispatcher>,
    pool: Arc<PacketPool>,
    stats: Arc<Stats>,
    listen: &str,
    cancel: CancellationToken,
) -> Result<u16> {
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| anyhow::anyhow!("HTTP: bind {listen}: {error}"))?;
    let port = listener.local_addr()?.port();
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
                        if let Err(error) =
                            handle_connection(stream, dispatcher, pool, stats, cancel).await
                        {
                            crate::log_error!("[{TAG}] {error:#}");
                        }
                    });
                }
                Err(error) => {
                    consecutive_errors += 1;
                    if consecutive_errors >= 8 {
                        crate::log_error!("[{TAG}] accept сыпется ошибками ({error}) — стоп");
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    });
    crate::log_error!("[{TAG}] CONNECT слушает {listen} (порт {port})");
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
    // Читаем заголовки ПО БАЙТУ прямо из сокета: CONNECT-клиент не шлёт тело
    // до ответа, но построчное чтение без буфера гарантирует, что в сокет
    // не останется непрочитанных байк, которые потеряет BufReader::into_inner.
    let line = match read_line(&mut stream).await {
        Ok(Some(line)) => line,
        Ok(None) => return Ok(()), // EOF до запроса — игнор
        Err(error) => return Err(error.context("HTTP: чтение request-line")),
    };
    if line.trim().is_empty() {
        return Ok(());
    }
    // проглотить заголовки до пустой строки
    loop {
        match read_line(&mut stream).await {
            Ok(Some(header)) => {
                if header.trim().is_empty() {
                    break;
                }
            }
            Ok(None) => break,
            Err(error) => return Err(error),
        }
    }
    let (method, target) = match parse_request_line(line.trim_end()) {
        Some(parsed) => parsed,
        None => {
            // не-HTTP мусор или пустой метод — молча закрываем
            stream.shutdown().await.ok();
            return Ok(());
        }
    };
    if !method.eq_ignore_ascii_case("CONNECT") {
        stream.write_all(NOT_SUPPORTED).await.ok();
        stream.shutdown().await.ok();
        bail!("HTTP: метод {method} не поддерживается (только CONNECT)");
    }
    let (host, port) = match parse_authority(target) {
        Some(parsed) => parsed,
        None => {
            stream.write_all(BAD_REQUEST).await.ok();
            stream.shutdown().await.ok();
            bail!("HTTP: неразбираемая цель CONNECT {target:?}");
        }
    };
    let port = match port {
        Some(port) if port > 0 => port,
        _ => {
            stream.write_all(BAD_REQUEST).await.ok();
            stream.shutdown().await.ok();
            bail!("HTTP: CONNECT без порта: {target:?}");
        }
    };
    let target_addr: SocketAddr = if let Ok(ip) = host.parse::<Ipv4Addr>() {
        SocketAddr::new(IpAddr::V4(ip), port)
    } else if host.parse::<Ipv6Addr>().is_ok() {
        stream.write_all(BAD_GATEWAY).await.ok();
        stream.shutdown().await.ok();
        bail!("HTTP: IPv6-цель {host} не поддерживается");
    } else {
        match resolve_via_tunnel(&dispatcher, &pool, &stats, host, &cancel, TAG).await {
            Ok(ip) => SocketAddr::new(IpAddr::V4(ip), port),
            Err(error) => {
                stream.write_all(BAD_GATEWAY).await.ok();
                stream.shutdown().await.ok();
                return Err(error);
            }
        }
    };
    run_tcp_session(
        stream,
        dispatcher,
        pool,
        stats,
        target_addr,
        cancel,
        TAG,
        CONNECT_OK,
        BAD_GATEWAY,
    )
    .await
}

/// Читает строку до \n по байтам (макс MAX_HEADER_LINE). None — EOF до данных.
async fn read_line(stream: &mut TcpStream) -> Result<Option<String>> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        if byte[0] == b'\n' {
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        if byte[0] != b'\r' {
            buf.push(byte[0]);
        }
        if buf.len() >= MAX_HEADER_LINE {
            bail!("HTTP: заголовок длиннее {MAX_HEADER_LINE} байт");
        }
    }
}

// ─────────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_line_parsing() {
        assert_eq!(
            parse_request_line("CONNECT example.com:443 HTTP/1.1"),
            Some(("CONNECT", "example.com:443"))
        );
        assert_eq!(
            parse_request_line("GET http://example.com/ HTTP/1.1"),
            Some(("GET", "http://example.com/"))
        );
        assert_eq!(parse_request_line("CONNECT"), None);
        assert_eq!(parse_request_line(" CONNECT x "), None);
        assert_eq!(parse_request_line("CONNECT x HTTPS/2"), None);
    }

    #[test]
    fn authority_parsing() {
        assert_eq!(
            parse_authority("example.com:443"),
            Some(("example.com", Some(443)))
        );
        assert_eq!(parse_authority("93.184.216.34:80"), Some(("93.184.216.34", Some(80))));
        assert_eq!(parse_authority("[::1]:8080"), Some(("::1", Some(8080))));
        assert_eq!(parse_authority("example.com"), Some(("example.com", None)));
        assert_eq!(parse_authority("example.com:abc"), Some(("example.com", None)));
        assert_eq!(parse_authority(""), None);
        assert_eq!(parse_authority(":443"), None);
    }

    // ───────── e2e: живой HTTP-листенер (без root, loopback) ─────────

    async fn spawn_test_http() -> (u16, CancellationToken) {
        let cancel = CancellationToken::new();
        let pool = crate::packet::PacketPool::new(256);
        let stats = Arc::new(Stats::default());
        let (dispatcher, _udp_port) = crate::dispatcher::Dispatcher::start(
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
        // return_sink SOCKS5-режима поднимает сам run_client; в тесте — no-op sink
        let (sink_tx, _sink_rx) = tokio::sync::mpsc::unbounded_channel();
        dispatcher.set_return_sink(sink_tx);
        let port = start_http_proxy(dispatcher, pool, stats, "127.0.0.1:0", cancel.clone())
            .await
            .expect("HTTP listen");
        (port, cancel)
    }

    #[tokio::test]
    async fn e2e_http_rejects_get_and_garbage() {
        let (port, cancel) = spawn_test_http().await;
        // GET → 501
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        sock.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut rep = [0u8; 64];
        let n = sock.read(&mut rep).await.unwrap();
        assert!(String::from_utf8_lossy(&rep[..n]).starts_with("HTTP/1.1 501"), "{n}");
        // мусор → молчаливое закрытие (EOF или RST — остатки заголовков в буфере)
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        sock.write_all(b"\r\n\r\n").await.unwrap();
        let result = sock.read(&mut rep).await;
        match result {
            Ok(n) => assert_eq!(n, 0),
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ),
                "{error}"
            ),
        }
        // пустое соединение → EOF, никакого ответа
        let sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        drop(sock);
        cancel.cancel();
    }

    #[tokio::test]
    async fn e2e_http_connect_bad_authority() {
        let (port, cancel) = spawn_test_http().await;
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        sock.write_all(b"CONNECT :443 HTTP/1.1\r\n\r\n").await.unwrap();
        let mut rep = [0u8; 64];
        let n = sock.read(&mut rep).await.unwrap();
        assert!(String::from_utf8_lossy(&rep[..n]).starts_with("HTTP/1.1 400"));
        // IPv6-цель → 502
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        sock.write_all(b"CONNECT [::1]:443 HTTP/1.1\r\n\r\n").await.unwrap();
        let n = sock.read(&mut rep).await.unwrap();
        assert!(String::from_utf8_lossy(&rep[..n]).starts_with("HTTP/1.1 502"));
        cancel.cancel();
    }
}
