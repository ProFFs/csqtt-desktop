// csqtt-desktop — десктопный клиент csqtt.
//
// Интерфейс: сине-серая тема (светлая/тёмная по системе), нижняя навигация-пилюля,
// экраны Подключение / Логи / Настройки; профили, VK-токен, авто-режимы хешей.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{
    self, Align, Align2, Color32, CornerRadius, FontId, Frame, Layout, Margin, Painter, Pos2,
    Rect, RichText, ScrollArea, Sense, Stroke, StrokeKind, Vec2,
    text::LayoutJob,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

// ───────────────────────────── палитра ─────────────────────────────
// Сине-серая тема (светлая/тёмная по системе) живёт в theme.rs; доступ: th().ИМЯ.

mod theme;
mod vk_login;

use theme::th;
const EVENT_PREFIX: &str = "__CSQTT_EVENT__|";
const VK_AUTH_URL: &str = "https://oauth.vk.ru/authorize?client_id=7793118&scope=1073737727\
    &redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html&display=page&response_type=token\
    &v=5.199";
const VK_API: &str = "https://api.vk.ru/method/";
const DEFAULT_CLIENT_IDS: &str = "8202606,6287487";
const LISTEN: &str = "127.0.0.1:9000";
const WORKERS_PER_GROUP: usize = 9;
const MAX_VK_HASHES: usize = 6;
// Единый внутренний отступ секционных карточек (AppSectionCard padding).
const SP: i8 = 16;
// Полные описания непонятных сокращений (подсказка по кнопке ⓘ).
const DOC_SRTP: &str = "SRTP — шифрование медиапотока в туннеле.\nAUTO — ядро само выбирает режим.\nWRAP — ключи передаются через VK-обёртку: надёжнее и совместимо со всеми серверами.\nDTLS — классический DTLS 1.2 (ECDSA P-256): быстрее, но некоторые прокси его режут.";
const DOC_CAPTCHA: &str = "Как клиент решает капчу VK при установке туннелей.\nСистемный выбор — ядро перебирает решатели само: собственный Rust-решатель, затем фолбэки, при необходимости попросит решить вручную.\nRJS — только собственный Rust/JS-решатель.\nWV — решение через WebView: на десктопе недоступно, выбери систему или RJS.";
const DOC_TURN: &str = "TURN — резервный relay-сервер: если прямое соединение с пирами не проходит, трафик идёт через TURN. Пусто = ядро подберёт серверы само.";
const DOC_TURN_TRANSPORT: &str = "Транспорт до TURN-сервера.\nUDP — быстрее и меньше задержка, но некоторые провайдеры режут TURN по UDP.\nTCP — стабильнее через DPI и файрволы, ценой небольшой задержки.";
const DOC_LISTEN: &str = "LISTEN — локальный адрес (host:port), на котором клиент поднимает прокси-сервер: к нему подключаются приложения, чей трафик идёт в туннель.";

// ───────────────────────────── утилиты ─────────────────────────────

fn app_dir() -> PathBuf {
    #[cfg(windows)]
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    #[cfg(not(windows))]
    let base = std::env::var("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".local/share")
    });
    base.join("csqtt-desktop")
}

fn time_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
}

struct XorShift(u64);
impl XorShift {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn hex(&mut self, nibbles: usize) -> String {
        let mut s = String::with_capacity(nibbles);
        for _ in 0..nibbles {
            s.push(char::from_digit((self.next_u64() % 16) as u32, 16).unwrap());
        }
        s
    }
}

fn now_secs_f32() -> f32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64() as f32)
        .unwrap_or(0.0)
}

fn fmt_bytes(b: u64) -> String {
    if b >= 1 << 30 {
        format!("{:.1} ГБ", b as f64 / (1u64 << 30) as f64)
    } else if b >= 1 << 20 {
        format!("{:.1} МБ", b as f64 / (1u64 << 20) as f64)
    } else if b >= 1024 {
        format!("{} КБ", b / 1024)
    } else {
        format!("{b} Б")
    }
}

// ───────────────────────────── модель ─────────────────────────────

#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct Profile {
    id: u64,
    name: String,
    ip: String,
    port: String,
    password: String,
    power: usize,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: 0,
            name: "Профиль".into(),
            ip: String::new(),
            port: String::new(),
            password: String::new(),
            power: 9,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(default)]
struct Settings {
    work_mode: String,   // Капча | Звонки | Авто ВК
    hashes: String,      // Ручной | Авто API | Авто ВК
    custom_hashes: String,
    masking: String,     // Простая | Средняя
    fingerprint: String, // Firefox | Safari | Chrome
    extra_threads: bool,
    // расширенные опции ядра
    turn: String,
    custom_turn_ips: String,
    turn_transport: String, // udp | tcp
    srtp_mode: String,      // auto | wrap | dtls
    captcha_mode: String,   // auto | rjs | wv
    listen: String,         // пусто = LISTEN по умолчанию
    validate_hashes: bool,
    domain_routing: bool,
    exclude_ru_zones: bool,
    template_domains: bool,
    domain_whitelist: bool,
    direct_domains: String,
    ip_routing: bool,
    ip_whitelist: bool,
    direct_ips: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            work_mode: "Звонки".into(),
            hashes: "Авто ВК".into(),
            custom_hashes: String::new(),
            masking: "Простая".into(),
            fingerprint: "Firefox".into(),
            extra_threads: false,
            turn: String::new(),
            custom_turn_ips: String::new(),
            turn_transport: "udp".into(),
            srtp_mode: "auto".into(),
            captcha_mode: "auto".into(),
            listen: String::new(),
            validate_hashes: false,
            domain_routing: false,
            exclude_ru_zones: false,
            template_domains: false,
            domain_whitelist: false,
            direct_domains: String::new(),
            ip_routing: false,
            ip_whitelist: false,
            direct_ips: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Store {
    profiles: Vec<Profile>,
    active_profile_id: Option<u64>,
    settings: Option<Settings>,
    device_id: String,
    generation: u64,
    next_profile_id: u64,
}

impl Store {
    fn save(&self) {
        let _ = std::fs::create_dir_all(app_dir());
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(app_dir().join("config.json"), s);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

#[derive(Clone)]
enum UiEvent {
    State(ConnState),
    Alert(String),
    PasteTokenOpen,
    PasteTokenSaved,
    ConnectError(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Page {
    Connect,
    Logs,
    Settings,
    Info,
}

// ───────────────────────────── лог-канал ─────────────────────────────

fn log_tx_slot() -> &'static Mutex<Option<Sender<String>>> {
    static SLOT: OnceLock<Mutex<Option<Sender<String>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

fn push_log(line: String) {
    if let Ok(g) = log_tx_slot().lock()
        && let Some(tx) = g.as_ref()
    {
        let _ = tx.send(line);
    }
}

// ───────────────────────────── VK токен ─────────────────────────────

fn token_path() -> PathBuf {
    app_dir().join("vk_token")
}

fn read_vk_token() -> Option<String> {
    let t = std::fs::read_to_string(token_path()).ok()?;
    let t = t.trim().to_string();
    (!t.is_empty()).then_some(t)
}

fn save_vk_token(raw: &str) -> bool {
    let raw = raw.trim();
    if raw.is_empty() {
        return false;
    }
    let token = if let Some(pos) = raw.find("access_token=") {
        raw[pos + "access_token=".len()..].split(['&', '#', ' ']).next().unwrap_or("").trim().to_string()
    } else {
        raw.to_string()
    };
    if token.is_empty() || token.contains('/') || token.contains(':') {
        return false;
    }
    let _ = std::fs::create_dir_all(app_dir());
    let res = std::fs::File::create(token_path()).and_then(|mut f| f.write_all(token.as_bytes()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(token_path(), std::fs::Permissions::from_mode(0o600));
    }
    if res.is_ok() {
        push_log("[ВК] Токен применён".into());
    }
    res.is_ok()
}

fn delete_vk_token() {
    let _ = std::fs::remove_file(token_path());
    push_log("[ВК] Токен удалён".into());
}

fn open_browser(url: &str) {
    #[cfg(windows)]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(not(windows))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

// ───────────────────── VK API: авто-звонки (Авто API) ─────────────────────

fn call_count_for_workers(workers: usize) -> usize {
    for n in 1..=MAX_VK_HASHES {
        if workers <= n * 3 * WORKERS_PER_GROUP {
            return n;
        }
    }
    MAX_VK_HASHES
}

fn token_invalid_code(code: i64) -> bool {
    matches!(code, 4 | 5 | 27 | 28)
}

fn http_client() -> primp::Client {
    primp::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| primp::Client::new())
}

/// Проверка токена по ответу users.get: Some(true) — валиден,
/// Some(false) — VK ответил error_code 5 (authorization failed),
/// None — сетевая/иная ошибка (невалидным не считаем).
fn parse_users_get_check(body: &str) -> Option<bool> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    if v.get("response").is_some() {
        return Some(true);
    }
    match v.get("error_code").and_then(|c| c.as_i64()) {
        Some(5) => Some(false),
        _ => None,
    }
}

async fn vk_token_check(client: &primp::Client, raw: &str) -> Option<bool> {
    let url = format!(
        "{VK_API}users.get?v=5.199&{}{raw}",
        concat!("access", "_token=")
    );
    let resp = client.get(url).send().await.ok()?;
    let text = resp.text().await.ok()?;
    parse_users_get_check(&text)
}

async fn vk_api_post(
    client: &primp::Client,
    method: &str,
    token: &str,
    body: &str,
) -> Option<serde_json::Value> {
    let resp = client
        .post(format!("{VK_API}{method}"))
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .send()
        .await
        .ok()?;
    let text = resp.text().await.ok()?;
    if text.is_empty() {
        return None;
    }
    serde_json::from_str(&text).ok()
}

/// Создаёт звонки VK под токеном; возвращает (hashes, call_ids, token_invalid).
async fn create_auto_calls(
    client: &primp::Client,
    token: &str,
    workers: usize,
) -> (Vec<String>, Vec<String>, bool) {
    let count = call_count_for_workers(workers);
    let delay = if count <= 4 { 80 } else { 202 };
    let mut hashes = Vec::new();
    let mut call_ids = Vec::new();
    let mut token_invalid = false;

    for slot in 0..count {
        if slot > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        for attempt in 0..3 {
            let Some(json) = vk_api_post(client, "calls.start", token, "v=5.199").await else {
                push_log(format!(
                    "[АВТО API] Звонок не создан · нет ответа VK API (попытка {})",
                    attempt + 1
                ));
                continue;
            };
            if let Some(err) = json.get("error") {
                let code = err
                    .get("error_code")
                    .and_then(|c| c.as_i64())
                    .unwrap_or(1);
                let msg = err
                    .get("error_msg")
                    .and_then(|m| m.as_str())
                    .unwrap_or("");
                push_log(format!("[АВТО API] Звонок не создан · код={code} {msg}"));
                if token_invalid_code(code) {
                    token_invalid = true;
                }
                break;
            }
            let resp = json.get("response");
            let call_id = resp
                .and_then(|r| r.get("call_id"))
                .map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .unwrap_or_default();
            let ok_link = resp
                .and_then(|r| r.get("ok_join_link"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let join_link = resp
                .and_then(|r| r.get("join_link"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mut hash = ok_link.trim().to_string();
            if hash.is_empty() && !join_link.is_empty() {
                hash = join_link
                    .trim()
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
            }
            if !call_id.is_empty() && !hash.is_empty() {
                hashes.push(hash);
                call_ids.push(call_id);
                push_log(format!("[АВТО API] Звонок создан: {}/{}", hashes.len(), count));
                break;
            }
            push_log("[АВТО API] Звонок не создан · пустой call_id/hash".into());
        }
        if token_invalid {
            break;
        }
    }
    (hashes, call_ids, token_invalid)
}

async fn finish_auto_calls(client: primp::Client, token: String, call_ids: Vec<String>) {
    let total = call_ids.len();
    let mut finished = 0usize;
    for id in call_ids {
        if let Some(json) = vk_api_post(
            &client,
            "calls.forceFinish",
            &token,
            &format!("call_id={id}&v=5.199"),
        )
        .await
            && json.get("error").is_none()
        {
            finished += 1;
        }
    }
    push_log(format!("[АВТО API] Звонки завершены {finished}/{total}"));
}

// ───────────────────────────── wintun (Windows) ─────────────────────────────

#[cfg(windows)]
fn install_embedded_wintun() {
    static DLL: &[u8] = include_bytes!("../assets/wintun.dll");
    let dir = std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir())
        .join("csqtt-desktop");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("wintun.dll");
    let need = std::fs::metadata(&path)
        .map(|m| m.len() as usize != DLL.len())
        .unwrap_or(true);
    if need {
        let _ = std::fs::write(&path, DLL);
    }
    csqtt_core::tun_win::set_dll_path_override(path.to_string_lossy().into_owned());
}

#[cfg(not(windows))]
fn install_embedded_wintun() {}

/// True, если процесс запущен с повышенными правами (UAC-элевация).
/// На не-Windows — всегда true (проверка не нужна).
#[cfg(windows)]
fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    // В windows-rs 0.62 OpenProcessToken экспортируется из Win32::System::Threading
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::addr_of_mut!(elev).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elev.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    true
}


// ───────────────────────────── виджеты csqtt ─────────────────────────────

use std::time::Instant;

fn format_uptime(total: u64) -> String {
    format!("{:02}:{:02}:{:02}", total / 3600, (total % 3600) / 60, total % 60)
}

/// AppSectionCard: Surface(Card shape, color lerp(bg,surface,.82), border outlineVariant@32%)
fn cs_card(inner: Margin) -> Frame {
    Frame::new()
        .fill(th().CARD)
        .corner_radius(CornerRadius::same(26))
        .inner_margin(inner)
        .stroke(Stroke::new(1.0, th().CARD_BORDER))
}

fn cs_dialog(inner: Margin) -> Frame {
    Frame::new()
        .fill(th().CARD)
        .corner_radius(CornerRadius::same(26))
        .inner_margin(inner)
        .stroke(Stroke::new(1.0, th().CARD_BORDER))
}

/// CsqttSegmentedControl: pill row; selected = primary fill + check + onPrimary text.
/// options: (значение, отображаемая подпись). Сверху — невидимые настоящие кнопки:
/// доступность (AccessKit/kittest) и hover-курсор.
fn segmented(
    ui: &mut egui::Ui,
    _id: &str,
    value: &str,
    options: &[(&str, &str)],
    on_change: &mut dyn FnMut(&str),
) {
    let n = options.len().max(1) as f32;
    let gap = 8.0f32;
    let h = 46.0f32;
    let avail = ui.available_width();
    let w = ((avail - gap * (n - 1.0)) / n).max(40.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(avail, h), Sense::hover());
    {
        let painter = ui.painter();
    for (i, (opt, label)) in options.iter().enumerate() {
        let r = Rect::from_min_size(
            rect.min + Vec2::new(i as f32 * (w + gap), 0.0),
            Vec2::new(w, h),
        );
        let sel = *opt == value;
        let fill = if sel { th().PRIMARY } else { th().SURF_VAR };
        let fg = if sel { th().ON_PRIMARY } else { th().ON_SURF_VAR };
        painter.rect_filled(r, CornerRadius::same((h / 2.0) as u8), fill);
        let galley = painter.layout_no_wrap(label.to_string(), FontId::proportional(13.0), fg);
        let check_w = if sel { 16.0 } else { 0.0 };
        let total_w = galley.size().x + check_w;
        let x0 = r.center().x - total_w / 2.0;
        if sel {
            let cy = r.center().y;
            let cx = x0 + 2.0;
            painter.line_segment(
                [Pos2::new(cx, cy), Pos2::new(cx + 3.5, cy + 3.5)],
                Stroke::new(1.8, fg),
            );
            painter.line_segment(
                [Pos2::new(cx + 3.5, cy + 3.5), Pos2::new(cx + 9.5, cy - 4.0)],
                Stroke::new(1.8, fg),
            );
        }
        painter.galley(
            Pos2::new(x0 + check_w, r.center().y - galley.size().y / 2.0),
            galley,
            Color32::TRANSPARENT,
        );
    }
    }
    for (i, (opt, label)) in options.iter().enumerate() {
        let r = Rect::from_min_size(
            rect.min + Vec2::new(i as f32 * (w + gap), 0.0),
            Vec2::new(w, h),
        );
        let btn = egui::Button::new(RichText::new(*label).color(Color32::TRANSPARENT).size(13.0))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::NONE)
            .corner_radius(CornerRadius::same((h / 2.0) as u8));
        if ui.put(r, btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            on_change(opt);
        }
    }
}

/// Помощник: варианты без отдельной подписи (значение = подпись).
fn seg_opts(vals: &[&'static str]) -> Vec<(&'static str, &'static str)> {
    vals.iter().map(|v| (*v, *v)).collect()
}

/// Material3-style switch (track 52x32, thumb + check).
/// label — доступное имя (скринридеры/kittest).
fn switch_pill(ui: &mut egui::Ui, on: bool, label: &str, on_toggle: &mut dyn FnMut(bool)) {
    let resp = ui
        .add_sized(
            Vec2::new(52.0, 32.0),
            egui::Button::new(
                RichText::new(format!("{label}: {}", if on { "включено" } else { "выключено" }))
                    .color(Color32::TRANSPARENT)
                    .size(1.0),
            )
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::NONE)
            .corner_radius(16.0),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if resp.clicked() {
        on_toggle(!on);
    }
    let p = ui.painter();
    let track = resp.rect.shrink(4.0);
    let cy = track.center().y;
    if on {
        p.rect_filled(track, CornerRadius::same(12), th().PRIMARY);
        let cx = track.right() - 12.0;
        p.circle_filled(Pos2::new(cx, cy), 9.0, th().ON_PRIMARY);
        p.line_segment(
            [Pos2::new(cx - 4.0, cy), Pos2::new(cx - 1.0, cy + 3.0)],
            Stroke::new(1.6, th().PRIMARY),
        );
        p.line_segment(
            [Pos2::new(cx - 1.0, cy + 3.0), Pos2::new(cx + 4.0, cy - 3.0)],
            Stroke::new(1.6, th().PRIMARY),
        );
    } else {
        p.rect_filled(track, CornerRadius::same(12), th().SURF_VAR);
        p.rect_stroke(
            track,
            CornerRadius::same(12),
            Stroke::new(1.0, th().OUTLINE),
            StrokeKind::Inside,
        );
        // тот же отступ, что у включённого: центр в 12 от края дорожки
        p.circle_filled(Pos2::new(track.left() + 12.0, cy), 9.0, th().OUTLINE);
    }
}

/// OutlinedTextField (pill, outline).
fn pill_field(ui: &mut egui::Ui, value: &mut String, hint: &str, width: f32) {
    let w = width.max(140.0);
    Frame::new()
        .fill(Color32::TRANSPARENT)
        .corner_radius(CornerRadius::same(20))
        .inner_margin(Margin::symmetric(14, 10))
        .stroke(Stroke::new(1.2, th().OUTLINE.linear_multiply(0.45)))
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::singleline(value)
                    .hint_text(RichText::new(hint).color(th().ON_SURF_VAR.linear_multiply(0.6)))
                    .text_color(th().ON_SURF)
                    .desired_width(w - 30.0)
                    .frame(false)
                    .vertical_align(Align::Center),
            );
        });
}

/// CsqttBanner (pill surface + icon dot).
fn banner(ui: &mut egui::Ui, text: &str, cont: Color32, fg: Color32) -> egui::Response {
    let ir = Frame::new()
        .fill(cont)
        .corner_radius(CornerRadius::same(18))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("!").strong().color(fg).size(14.0));
                ui.label(RichText::new(text).color(fg).size(12.5));
            });
        });
    ir.response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn setting_label(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).strong().color(th().ON_SURF_VAR).size(12.0));
    ui.add_space(6.0);
}

/// ⓘ — кнопка с полным описанием сокращения (всплывающая подсказка).
fn info_dot(ui: &mut egui::Ui, id: &str, text: &str) {
    let r = ui
        .add_sized(
            Vec2::splat(20.0),
            egui::Button::new(RichText::new("i").color(th().ON_SURF_VAR).size(12.5))
                .fill(Color32::TRANSPARENT)
                .stroke(Stroke::new(1.0, th().OUTLINE_VAR))
                .corner_radius(10.0),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let pid = egui::Id::new(("doc-pop", id));
    let mut open = ui.ctx().data_mut(|d| *d.get_persisted_mut_or(pid, false));
    if r.clicked() {
        open = !open;
    }
    r.on_hover_text(RichText::new(text).size(12.0).color(th().ON_SURF));
    if open {
        let mut is_open = true;
        egui::Window::new("doc")
            .id(egui::Id::new(("doc-win", id)))
            .frame(cs_dialog(Margin::symmetric(16, 14)))
            .title_bar(false)
            .resizable(false)
            .movable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ui.ctx(), |ui| {
                ui.set_max_width(360.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Справка").strong().color(th().ON_SURF).size(14.0));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if icon_button(ui, "close", 30.0).clicked() {
                            is_open = false;
                        }
                    });
                });
                ui.add_space(8.0);
                for line in text.split('\n') {
                    if !line.is_empty() {
                        ui.label(RichText::new(line).color(th().ON_SURF_VAR).size(12.5));
                        ui.add_space(3.0);
                    }
                }
            });
        open = is_open;
    }
    ui.ctx().data_mut(|d| *d.get_persisted_mut_or(pid, false) = open);
}

/// setting_label + ⓘ рядом (клик — окно справки, hover — подсказка).
fn setting_label_i(ui: &mut egui::Ui, text: &str, doc: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(text).strong().color(th().ON_SURF_VAR).size(12.0));
        info_dot(ui, text, doc);
    });
    ui.add_space(6.0);
}

fn separator(ui: &mut egui::Ui) {
    ui.add_space(12.0);
    let (r, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 1.0), Sense::hover());
    ui.painter().line_segment(
        [r.left_center(), r.right_center()],
        Stroke::new(1.0, th().OUTLINE_VAR.linear_multiply(0.5)),
    );
    ui.add_space(12.0);
}

/// CsqttSettingRow: title+description left, control right.
fn setting_row(ui: &mut egui::Ui, title: &str, desc: Option<&str>, content: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(title).strong().color(th().ON_SURF).size(14.5));
            if let Some(d) = desc {
                ui.label(RichText::new(d).color(th().ON_SURF_VAR).size(11.5));
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            content(ui);
        });
    });
}

/// Filled pill button (primary).
fn pill_button(ui: &mut egui::Ui, label: &str, size: Vec2) -> egui::Response {
    ui.add_sized(
        size,
        egui::Button::new(RichText::new(label).strong().color(th().ON_PRIMARY).size(13.0))
            .fill(th().PRIMARY)
            .corner_radius(size.y / 2.0),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Мелкое действие — скруглённый чип (не квадратная ui.button).
fn chip(ui: &mut egui::Ui, label: &str, fg: Color32) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).color(fg).size(12.0))
            .fill(th().SURF_VAR)
            .corner_radius(13.0)
            .min_size(Vec2::new(0.0, 26.0)),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Outlined pill button.
fn pill_button_outlined(ui: &mut egui::Ui, label: &str, size: Vec2, fg: Color32) -> egui::Response {
    ui.add_sized(
        size,
        egui::Button::new(RichText::new(label).color(fg).size(13.0))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::new(1.0, th().OUTLINE_VAR))
            .corner_radius(size.y / 2.0),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Header icon button (drawn glyph).
fn icon_button(ui: &mut egui::Ui, kind: &str, size: f32) -> egui::Response {
    let resp = ui.add_sized(
        Vec2::splat(size),
        egui::Button::new("").fill(Color32::TRANSPARENT).corner_radius(size / 2.0),
    );
    let c = resp.rect.center();
    let p = ui.painter();
    let col = th().ON_SURF_VAR;
    let sw = Stroke::new(1.8, col);
    match kind {
        "close" => {
            p.line_segment([c + Vec2::new(-6.0, -6.0), c + Vec2::new(6.0, 6.0)], sw);
            p.line_segment([c + Vec2::new(6.0, -6.0), c + Vec2::new(-6.0, 6.0)], sw);
        }
        _ => {
            p.circle_stroke(c, 4.5, sw);
            for i in 0..6 {
                let a = i as f32 * std::f32::consts::TAU / 6.0;
                let d = Vec2::angled(a);
                p.line_segment([c + d * 7.0, c + d * 10.0], sw);
            }
        }
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Power-символ: дуга с разрывом сверху + штырёк (Material power icon).
/// В egui 0.31 нет ArcShape, поэтому дуга — полилиния из 28 сегментов.
fn power_glyph(p: &Painter, c: Pos2, r: f32, sw: Stroke) {
    let gap = 0.62f32;
    let a0 = -std::f32::consts::FRAC_PI_2 + gap;
    let a1 = -std::f32::consts::FRAC_PI_2 - gap + std::f32::consts::TAU;
    let n = 28;
    let mut prev = c + Vec2::angled(a0) * r;
    for i in 1..=n {
        let a = a0 + (a1 - a0) * i as f32 / n as f32;
        let pt = c + Vec2::angled(a) * r;
        p.line_segment([prev, pt], sw);
        prev = pt;
    }
    p.line_segment(
        [c + Vec2::new(0.0, -(r + sw.width * 2.0)), c + Vec2::new(0.0, -r * 0.18)],
        sw,
    );
}

fn draw_nav_icon(p: &Painter, c: Pos2, icon: &str, col: Color32) {
    let sw = Stroke::new(1.9, col);
    match icon {
        "power" => {
            power_glyph(p, c + Vec2::new(0.0, 2.0), 6.5, sw);
        }
        "info" => {
            p.circle_filled(c + Vec2::new(0.0, -7.0), 1.7, col);
            p.line_segment([c + Vec2::new(0.0, -2.5), c + Vec2::new(0.0, 8.0)], sw);
        }
        "term" => {
            p.line_segment([c + Vec2::new(-7.0, -5.0), c + Vec2::new(-2.0, 0.0)], sw);
            p.line_segment([c + Vec2::new(-2.0, 0.0), c + Vec2::new(-7.0, 5.0)], sw);
            p.line_segment([c + Vec2::new(1.0, 5.0), c + Vec2::new(8.0, 5.0)], sw);
        }
        _ => {
            p.circle_stroke(c, 4.0, sw);
            for i in 0..6 {
                let a = i as f32 * std::f32::consts::TAU / 6.0;
                let d = Vec2::angled(a);
                p.line_segment([c + d * 6.5, c + d * 9.5], sw);
            }
        }
    }
}

/// ProxyNavigationBar: floating pill bar with primary indicator + icon/label per tab.
fn nav_bar(ui: &mut egui::Ui, page: Page) -> Option<Page> {
    let items: [(Page, &str, &str); 4] = [
        (Page::Connect, "Подключение", "power"),
        (Page::Logs, "Логи", "term"),
        (Page::Settings, "Настройки", "gear"),
        (Page::Info, "Инфо", "info"),
    ];
    let avail = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(Vec2::new(avail, 66.0), Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(26), th().CARD);
    p.rect_stroke(
        rect,
        CornerRadius::same(26),
        Stroke::new(1.0, th().NAV_BORDER),
        StrokeKind::Inside,
    );
    let pad = 6.0f32;
    let iw = (rect.width() - pad * 2.0) / items.len() as f32;
    let sel = items.iter().position(|(pg, _, _)| *pg == page).unwrap_or(0);
    let ind = Rect::from_min_size(
        rect.min + Vec2::new(pad + iw * sel as f32, 7.0),
        Vec2::new(iw, 52.0),
    );
    p.rect_filled(ind.shrink(1.0), CornerRadius::same(20), th().PRIMARY);
    for (i, (_pg, label, icon)) in items.iter().enumerate() {
        let r = Rect::from_min_size(rect.min + Vec2::new(pad + iw * i as f32, 7.0), Vec2::new(iw, 52.0));
        let on = i == sel;
        let col = if on { th().ON_PRIMARY } else { th().ON_SURF_VAR.linear_multiply(0.55) };
        let c = r.center();
        draw_nav_icon(p, c + Vec2::new(0.0, -8.0), icon, col);
        p.text(
            c + Vec2::new(0.0, 8.0),
            Align2::CENTER_TOP,
            *label,
            FontId::proportional(10.5),
            col,
        );
    }
    let mut goto = None;
    for (i, (pg, label, _icon)) in items.iter().enumerate() {
        let r = Rect::from_min_size(rect.min + Vec2::new(pad + iw * i as f32, 7.0), Vec2::new(iw, 52.0));
        let btn = egui::Button::new(RichText::new(*label).color(Color32::TRANSPARENT).size(10.5))
            .fill(Color32::TRANSPARENT)
            .stroke(Stroke::NONE)
            .corner_radius(20.0);
        if ui.put(r, btn).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            goto = Some(*pg);
        }
    }
    goto
}

/// TunnelWorkersSlider: непрерывный ползунок 1..=max (шаг 1) + knob.
/// Перетаскивание плавное: значение = round по дорожке, без квантования группами.
fn power_dots(ui: &mut egui::Ui, power: &mut usize, max: usize, on_change: &mut dyn FnMut()) {
    let max = max.max(2);
    let before = *power;
    ui.horizontal(|ui| {
        ui.label(RichText::new("Мощность").strong().color(th().ON_SURF).size(14.5));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(format!("потоки: {power}")).color(th().ON_SURF_VAR).size(12.5));
        });
    });
    let (rect, resp) =
        ui.allocate_exact_size(Vec2::new(ui.available_width(), 28.0), Sense::click_and_drag());
    let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
    let painter = ui.painter();
    let knob = 9.0f32;
    let pad = knob + 3.0;
    let track_l = rect.left() + pad;
    let track_w = (rect.width() - 2.0 * pad).max(1.0);
    let cy = rect.center().y;
    let mut frac_drag: Option<f32> = None;
    if resp.dragged() || resp.clicked() {
        if let Some(pos) = resp.interact_pointer_pos() {
            let f = ((pos.x - track_l) / track_w).clamp(0.0, 1.0);
            frac_drag = Some(f);
            // непрерывно: 1 у левого края, max у правого, шаг 1
            *power = (1 + (f * (max - 1) as f32).round() as usize).clamp(1, max);
        }
    }
    painter.line_segment(
        [Pos2::new(track_l, cy), Pos2::new(track_l + track_w, cy)],
        Stroke::new(2.0, th().OUTLINE_VAR),
    );
    let groups = (max / WORKERS_PER_GROUP).max(2);
    for i in 0..groups {
        let gx = track_l + track_w * (i as f32 / (groups - 1) as f32);
        let filled = (i + 1) * WORKERS_PER_GROUP <= *power;
        painter.circle_filled(
            Pos2::new(gx, cy),
            3.0,
            if filled { th().PRIMARY } else { th().OUTLINE_VAR },
        );
    }
    let frac = frac_drag.unwrap_or({
        // knob непрерывно по значению: минимум у левого края, максимум у правого
        ((*power).clamp(1, max) - 1) as f32 / (max - 1) as f32
    });
    let kx = track_l + track_w * frac;
    painter.line_segment(
        [Pos2::new(track_l, cy), Pos2::new(kx, cy)],
        Stroke::new(2.5, th().PRIMARY),
    );
    painter.circle_filled(Pos2::new(kx, cy), knob, th().PRIMARY);
    painter.circle_filled(Pos2::new(kx, cy), 4.0, th().ON_PRIMARY);
    if *power != before {
        on_change();
        ui.ctx().request_repaint();
    }
}

// ───────────────────────────── приложение ─────────────────────────────

struct Session {
    cancel: CancellationToken,
    call_ids: Arc<Mutex<Vec<String>>>,
    auto_token: String,
    had_auto_api: bool,
}

struct App {
    store: Store,
    page: Page,
    state: ConnState,
    stats: (usize, u64, u64),
    logs: VecDeque<String>,
    log_rx: Receiver<String>,
    ui_rx: Receiver<UiEvent>,
    ui_tx: Sender<UiEvent>,
    rt: tokio::runtime::Runtime,
    session: Option<Session>,
    editor: Option<u64>,
    alert: Option<String>,
    adv_open: bool,
    picker_open: bool,
    paste_open: bool,
    paste_text: String,
    connect_error: Option<String>,
    captcha_answer: String,
    connected_at: Option<Instant>,
    /// момент последней СМЕНЫ ConnState (None до первого перехода) — фаза
    /// анимации центральной кнопки; при None анимации нет
    state_anim_at: Option<Instant>,
    anim_prev_state: ConnState,
    dark: bool,
    vk_rx: Option<Receiver<Result<String, String>>>,
    /// Иконка системного трея (Windows); создаётся при первом сворачивании.
    /// Дроп последней ссылки удаляет иконку из трея (tray-icon 0.19).
    #[cfg(windows)]
    tray: Option<tray_icon::TrayIcon>,
    /// Окно скрыто в трей (закрытие отменено), а не закрыто.
    tray_hidden: bool,
    /// «Выйти» из меню трея: закрытие больше не перехватываем.
    quitting: bool,
    /// Момент сворачивания в трей — автозакрытие тоста через ~3.5 с.
    #[cfg(windows)]
    toast_at: Option<Instant>,
    /// Клон первого пункта меню трея («Потоки: …») — muda MenuItem Clone;
    /// текст обновляется из tray_tick по self.stats.
    #[cfg(windows)]
    tray_stats_item: Option<tray_icon::menu::MenuItem>,
    /// Момент последней записи статистики в меню трея (троттлинг ~1 с).
    #[cfg(windows)]
    tray_stats_at: Option<Instant>,
    /// Статистика, уже записанная в пункт меню трея (чтобы не дёргать set_text).
    #[cfg(windows)]
    tray_stats_written: (usize, u64, u64),
}

impl App {
    fn new(dark: bool) -> Self {
        let (log_tx, log_rx) = mpsc::channel::<String>();
        *log_tx_slot().lock().unwrap() = Some(log_tx);
        csqtt_core::set_log_callback(Box::new(push_log));
        csqtt_core::set_events_enabled(true);

        let (ui_tx, ui_rx) = mpsc::channel();
        let store = Self::load_store();
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

        Self {
            store,
            page: Page::Connect,
            state: ConnState::Disconnected,
            stats: (0, 0, 0),
            logs: VecDeque::new(),
            log_rx,
            ui_rx,
            ui_tx,
            rt,
            session: None,
            editor: None,
            alert: None,
            adv_open: false,
            picker_open: false,
            paste_open: false,
            paste_text: String::new(),
            connect_error: None,
            captcha_answer: String::new(),
            connected_at: None,
            state_anim_at: None,
            anim_prev_state: ConnState::Disconnected,
            dark,
            vk_rx: None,
            #[cfg(windows)]
            tray: None,
            tray_hidden: false,
            quitting: false,
            #[cfg(windows)]
            toast_at: None,
            #[cfg(windows)]
            tray_stats_item: None,
            #[cfg(windows)]
            tray_stats_at: None,
            #[cfg(windows)]
            tray_stats_written: (0, 0, 0),
        }
    }

    fn load_store() -> Store {
        let path = app_dir().join("config.json");
        let mut store = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Store>(&s).ok())
            .unwrap_or_default();
        if store.settings.is_none() {
            store.settings = Some(Settings::default());
        }
        if store.profiles.is_empty() {
            let mut p = Profile::default();
            p.id = 1;
            p.name = "Основной".into();
            store.profiles.push(p);
            store.active_profile_id = Some(1);
            store.next_profile_id = 1;
            store.save();
        }
        if store.active_profile_id.is_none() {
            store.active_profile_id = store.profiles.first().map(|p| p.id);
        }
        if store.device_id.is_empty() {
            let mut rng = XorShift(time_seed());
            let h = rng.hex(32);
            store.device_id =
                format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]);
            store.save();
        }
        store
    }

    fn settings(&self) -> Settings {
        self.store.settings.clone().unwrap_or_default()
    }

    fn active_profile(&self) -> Option<Profile> {
        let id = self.store.active_profile_id?;
        self.store.profiles.iter().find(|p| p.id == id).cloned()
    }

    fn drain_channels(&mut self) {
        while let Ok(line) = self.log_rx.try_recv() {
            if let Some(rest) = line.strip_prefix(EVENT_PREFIX) {
                let (kind, payload) = rest.split_once('|').unwrap_or((rest, ""));
                match kind {
                    "STATS" => {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
                            self.stats = (
                                v.get("active").and_then(|a| a.as_u64()).unwrap_or(0) as usize,
                                v.get("bytes_up").and_then(|a| a.as_u64()).unwrap_or(0),
                                v.get("bytes_down").and_then(|a| a.as_u64()).unwrap_or(0),
                            );
                            if self.stats.0 > 0 && self.state == ConnState::Connecting {
                                self.state = ConnState::Connected;
                            }
                        }
                    }
                    "READY" => self.state = ConnState::Connected,
                    "STOPPED" => {
                        self.state = ConnState::Disconnected;
                        self.stats = (0, 0, 0);
                    }
                    "ACTIVE_ZERO" => self.logs.push_back("· нет активных туннелей".into()),
                    "TUN_LOST" => {
                        self.logs.push_back("[ТЮН] канал потерян".into());
                        self.state = ConnState::Disconnected;
                        self.stats = (0, 0, 0);
                    }
                    "ERROR" => {
                        let msg = serde_json::from_str::<serde_json::Value>(payload)
                            .ok()
                            .and_then(|v| {
                                v.get("message").and_then(|m| m.as_str()).map(String::from)
                            })
                            .unwrap_or_else(|| payload.to_string());
                        self.logs.push_back(format!("[ОШИБКА] {msg}"));
                        self.connect_error = Some(msg);
                        self.state = ConnState::Disconnected;
                        self.stats = (0, 0, 0);
                    }
                    _ => {}
                }
            } else {
                // «[СТАТИСТИКА]» — живая строка: не плодим новые, а обновляем
                // последнюю, если она тоже статистическая (трафик на месте).
                let replaced = line.starts_with("[СТАТИСТИКА]")
                    && self
                        .logs
                        .back_mut()
                        .is_some_and(|last| {
                            if last.starts_with("[СТАТИСТИКА]") {
                                *last = line.clone();
                                true
                            } else {
                                false
                            }
                        });
                if !replaced {
                    if self.logs.len() >= 3000 {
                        self.logs.pop_front();
                    }
                    self.logs.push_back(line);
                }
            }
        }
        while let Ok(ev) = self.ui_rx.try_recv() {
            match ev {
                UiEvent::State(s) => {
                    self.state = s;
                    // после отключения статистика под кнопкой обнуляется
                    if s == ConnState::Disconnected {
                        self.stats = (0, 0, 0);
                    }
                }
                UiEvent::Alert(msg) => self.alert = Some(msg),
                UiEvent::PasteTokenOpen => self.paste_open = true,
                UiEvent::PasteTokenSaved => {
                    self.paste_open = false;
                    self.paste_text.clear();
                }
                UiEvent::ConnectError(e) => self.connect_error = Some(e),
            }
        }
    }

    /// VK-вход: в Windows — маленькое WebView2-окошко с автоперехватом токена;
    /// иначе — системный браузер + ручная вставка ссылки.
    fn start_vk_login(&mut self) {
        #[cfg(windows)]
        {
            let (tx, rx) = mpsc::channel();
            vk_login::start(VK_AUTH_URL.to_string(), tx);
            self.vk_rx = Some(rx);
            // без попапов: только строка в лог
            push_log("[ВК] Открываю окошко входа…".into());
        }
        #[cfg(not(windows))]
        {
            open_browser(VK_AUTH_URL);
            self.paste_open = true;
        }
    }

    fn start(&mut self) {
        if !is_elevated() {
            self.alert = Some(
                "Нужен запуск от администратора: закрой программу, нажми правой кнопкой на csqtt-desktop.exe \u{2192} \u{ab}Запуск от имени администратора\u{bb}".into(),
            );
            push_log("[СТАРТ] нет прав администратора".into());
            return;
        }
        let Some(profile) = self.active_profile() else {
            push_log("[СТАРТ] нет профиля — добавьте его кнопкой «+ Добавить»".into());
            self.alert = Some("Нет профиля — добавьте его кнопкой «+ Добавить»".into());
            return;
        };
        if profile.ip.trim().is_empty() || profile.port.trim().is_empty() {
            push_log("[СТАРТ] не заполнены IP и порт профиля".into());
            self.alert = Some("Заполните IP и порт в профиле".into());
            return;
        }
        if profile.password.trim().is_empty() {
            push_log("[СТАРТ] не заполнен пароль профиля".into());
            self.alert = Some("Заполните пароль профиля".into());
            return;
        }

        let s = self.settings();
        let mut hash_mode = match s.hashes.as_str() {
            "Авто ВК" => "auto_js",
            "Авто API" => "auto_api",
            _ => "manual",
        };
        let auth_mode = match s.work_mode.as_str() {
            "Авто ВК" => "auto_js",
            "Капча" => "legacy",
            _ => "vkcalls",
        };
        if auth_mode == "auto_js" {
            hash_mode = "auto_js";
        }

        let needs_token = matches!(hash_mode, "auto_api" | "auto_js") || auth_mode == "auto_js";
        let token = if needs_token {
            match read_vk_token() {
                Some(t) => t,
                None => {
                    push_log("[СТАРТ] нет токена ВК — нужен вход (Настройки → Аккаунт ВКонтакте)".into());
                    self.alert =
                        Some("Нужен токен ВК: Настройки → Аккаунт ВКонтакте → Логин".into());
                    return;
                }
            }
        } else {
            String::new()
        };

        let mut vk_value = s.custom_hashes.trim().to_string();
        if hash_mode == "manual" && vk_value.is_empty() {
            push_log("[СТАРТ] ручной режим хешей: список хешей пуст".into());
            self.alert = Some("Ручной режим хешей: заполни хеши в Настройках".into());
            return;
        }

        let cancel = CancellationToken::new();
        let call_ids = Arc::new(Mutex::new(Vec::<String>::new()));
        let ui_tx = self.ui_tx.clone();
        let device_id = self.store.device_id.clone();
        let generation = {
            self.store.generation += 1;
            self.store.save();
            self.store.generation
        };
        let mut rng = XorShift(time_seed());
        let salt = rng.hex(16);
        let fingerprint = s.fingerprint.to_lowercase();
        let obfs = if s.masking == "Средняя" { "unified" } else { "audio" };
        let peer = format!("{}:{}", profile.ip.trim(), profile.port.trim());
        let password = profile.password.trim().to_string();
        let workers = profile.power.max(1);
        let vk_token_for_core = token.clone();
        let auto_api = hash_mode == "auto_api";
        let hash_mode_owned = hash_mode.to_string();
        let adv = s.clone();

        self.session = Some(Session {
            cancel: cancel.clone(),
            call_ids: call_ids.clone(),
            auto_token: token.clone(),
            had_auto_api: auto_api,
        });
        self.state = ConnState::Connecting;
        self.connect_error = None;

        self.rt.spawn(async move {
            let client = http_client();

            if auto_api {
                let (hashes, ids, token_invalid) = create_auto_calls(&client, &token, workers).await;
                if token_invalid {
                    delete_vk_token();
                    let _ = ui_tx.send(UiEvent::Alert(
                        "Токен ВК недействителен — выполни вход заново".into(),
                    ));
                    let _ = ui_tx.send(UiEvent::State(ConnState::Disconnected));
                    return;
                }
                if hashes.is_empty() {
                    let _ = ui_tx.send(UiEvent::Alert(
                        "Не удалось создать звонки VK — проверь интернет и токен".into(),
                    ));
                    let _ = ui_tx.send(UiEvent::State(ConnState::Disconnected));
                    return;
                }
                if hashes.len() < call_count_for_workers(workers) {
                    push_log("[АВТО API] Звонки частично · потоки перераспределены".into());
                }
                vk_value = hashes.join(",");
                if let Ok(mut g) = call_ids.lock() {
                    *g = ids;
                }
            }

            let listen = if adv.listen.trim().is_empty() {
                LISTEN.to_string()
            } else {
                adv.listen.trim().to_string()
            };
            let config = csqtt_core::ClientConfig {
                turn: adv.turn.trim().to_string(),
                custom_turn_ips: adv.custom_turn_ips.trim().to_string(),
                port: String::new(),
                listen,
                vk: vk_value,
                vk_hash_mode: hash_mode_owned,
                peer,
                workers,
                runtime_threads: 0,
                exact_workers: false,
                allow_hash_redistribution: auto_api,
                device_id,
                password,
                vk_auth_mode: auth_mode.to_string(),
                captcha_mode: adv.captcha_mode.clone(),
                fingerprint,
                client_ids: DEFAULT_CLIENT_IDS.to_string(),
                obfs: obfs.to_string(),
                turn_transport: adv.turn_transport.clone(),
                srtp_mode: adv.srtp_mode.clone(),
                generation,
                salt,
                tun_uds: if cfg!(windows) { "wintun" } else { "tun" }.to_string(),
                validate_vk_hashes: adv.validate_hashes,
                vk_js_token: vk_token_for_core,
                domain_routing: adv.domain_routing,
                exclude_ru_zones: adv.exclude_ru_zones,
                template_domains: adv.template_domains,
                domain_whitelist: adv.domain_whitelist,
                direct_domains: adv.direct_domains.trim().to_string(),
                domains_file: Vec::new(),
                ip_routing: adv.ip_routing,
                ip_whitelist: adv.ip_whitelist,
                direct_ips: adv.direct_ips.trim().to_string(),
            };

            let result = csqtt_core::run_client(config, Some(cancel)).await;
            if let Err(e) = &result {
                push_log(format!("[КЛИЕНТ] Остановка: {e}"));
                let _ = ui_tx.send(UiEvent::ConnectError(e.to_string()));
            }
            let _ = ui_tx.send(UiEvent::State(ConnState::Disconnected));
        });
    }

    fn stop(&mut self) {
        let Some(session) = self.session.take() else {
            return;
        };
        session.cancel.cancel();
        self.state = ConnState::Disconnecting;
        if session.had_auto_api && !session.auto_token.is_empty() {
            let ids = session
                .call_ids
                .lock()
                .map(|g| g.clone())
                .unwrap_or_default();
            if !ids.is_empty() {
                let token = session.auto_token.clone();
                let handle = self.rt.handle().clone();
                handle.spawn(async move {
                    finish_auto_calls(http_client(), token, ids).await;
                });
            }
        }
    }

    // ─────────────────────────── трей (Windows) ───────────────────────────
    //
    // Закрытие окна не выходит из приложения: close-запрос отменяется, окно
    // скрывается (ViewportCommand::Visible(false)), в трее создаётся иконка с
    // меню «Подключиться / Отключиться / Выйти» и показывается тост-
    // уведомление. Двойной клик (или клик ЛКМ) по иконке восстанавливает окно.
    // События трея опрашиваются в update() — main-поток, как требует tray-icon.

    /// Создать иконку трея с меню. Повторный вызов — no-op.
    #[cfg(windows)]
    fn make_tray(&mut self) {
        if self.tray.is_some() {
            return;
        }
        use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
        let menu = Menu::new();
        let mi_stats = MenuItem::with_id("tray_stats", "Потоки: — · ↑ — · ↓ —", false, None);
        let mi_conn = MenuItem::with_id("tray_connect", "Подключиться", true, None);
        let mi_disc = MenuItem::with_id("tray_disconnect", "Отключиться", true, None);
        let sep = PredefinedMenuItem::separator();
        let mi_quit = MenuItem::with_id("tray_quit", "Выйти", true, None);
        if menu
            .append_items(&[&mi_stats, &mi_conn, &mi_disc, &sep, &mi_quit])
            .is_err()
        {
            push_log("[ТРЕЙ] Не удалось собрать меню трея".into());
            return;
        }
        self.tray_stats_item = Some(mi_stats.clone());
        self.tray_stats_at = None;
        self.tray_stats_written = (0, 0, 0);
        let mut b = tray_icon::TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            // Тултип — ровно «csqtt-desktop», выставляется один раз здесь;
            // больше нигде не меняется (set_tooltip в других местах удалён).
            .with_tooltip("csqtt-desktop");
        match tray_icon::Icon::from_rgba(
            include_bytes!("../assets/tray_icon.bin").to_vec(),
            32,
            32,
        ) {
            Ok(ic) => b = b.with_icon(ic),
            Err(e) => push_log(format!("[ТРЕЙ] Иконка не принята: {e}")),
        }
        match b.build() {
            Ok(t) => self.tray = Some(t),
            Err(e) => push_log(format!("[ТРЕЙ] Иконка не создана: {e}")),
        }
    }

    /// Перехват закрытия окна: отменить, «спрятать» в трей, уведомить.
    ///
    /// ВАЖНО: вместо ViewportCommand::Visible(false) окно уносится за пределы
    /// экрана минимальным размером («off-screen hide»). Visible(false) делает
    /// окно невидимым для Windows → перестают приходить redraw-события →
    /// eframe не вызывает update() → tray_tick зависает («Выйти» и клик по
    /// иконке перестают работать). Off-screen окно остаётся «видимым» для
    /// ОС, и цикл репейнта живёт.
    #[cfg(windows)]
    fn tray_on_close(&mut self, ctx: &egui::Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        self.make_tray();
        ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(
            32000.0, 32000.0,
        )));
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1.0, 1.0)));
        self.tray_hidden = true;
        self.toast_at = Some(Instant::now());
        // Нативное уведомление Windows (ошибки игнорируем — egui-тост ниже
        // остаётся фолбэком, теперь он реально отрисуется: цикл жив).
        let _ = notify_rust::Notification::new()
            .appname("csqtt-desktop")
            .summary("csqtt-desktop")
            .body("Приложение свёрнуто в трей — иконка рядом с часами")
            .show();
        push_log("[ТРЕЙ] Приложение свёрнуто в трей".into());
    }

    /// Опрос событий меню/иконки трея + обновление статистики + тост. Вызывается из update().
    #[cfg(windows)]
    fn tray_tick(&mut self, ctx: &egui::Context) {
        // Статистика первым пунктом меню: не чаще раза в секунду и только при
        // изменении self.stats (клон MenuItem живёт в поле App).
        if let Some(mi) = &self.tray_stats_item {
            let changed = self.stats != self.tray_stats_written;
            let due = self
                .tray_stats_at
                .map_or(true, |t| t.elapsed().as_secs_f32() >= 1.0);
            if changed && due {
                mi.set_text(format!(
                    "Потоки: {} · ↑ {} · ↓ {}",
                    self.stats.0,
                    fmt_bytes(self.stats.1),
                    fmt_bytes(self.stats.2)
                ));
                self.tray_stats_written = self.stats;
                self.tray_stats_at = Some(Instant::now());
            }
        }
        // меню трея
        while let Ok(ev) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            match ev.id.0.as_str() {
                "tray_connect" => {
                    if self.state == ConnState::Disconnected {
                        self.start();
                    }
                }
                "tray_disconnect" => {
                    if matches!(self.state, ConnState::Connected | ConnState::Connecting) {
                        self.stop();
                    }
                }
                "tray_quit" => {
                    self.quitting = true;
                    if let Some(session) = self.session.take() {
                        session.cancel.cancel();
                    }
                    self.tray = None; // дроп удаляет иконку из трея
                    // Штатный Close ждёт, пока tokio-рантайм дождётся
                    // блокирующих wintun/TUN-циклов ядра — поэтому выход
                    // «очень долгий». Выходим сразу: OS сама закроет хендлы.
                    std::process::exit(0);
                }
                _ => {}
            }
        }
        // клики по иконке: ЛКМ-up или двойной клик — восстановить окно
        while let Ok(ev) = tray_icon::TrayIconEvent::receiver().try_recv() {
            let restore = match &ev {
                tray_icon::TrayIconEvent::Click {
                    button,
                    button_state,
                    ..
                } => {
                    *button == tray_icon::MouseButton::Left
                        && *button_state == tray_icon::MouseButtonState::Up
                }
                tray_icon::TrayIconEvent::DoubleClick { button, .. } => {
                    *button == tray_icon::MouseButton::Left
                }
                _ => false,
            };
            if restore && self.tray_hidden {
                self.tray_hidden = false;
                // Возврат из «off-screen hide»: размер по умолчанию 560×880,
                // центр экрана, фокус. ViewportCommand::Center в egui 0.31
                // нет — центрируем вручную через OuterPosition. Visible(true)
                // не нужен — окно и так было видимым для Windows.
                let sz = egui::vec2(560.0, 880.0);
                let center = ctx.screen_rect().center() - sz * 0.5;
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(sz));
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(center));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                ctx.request_repaint();
            }
        }
        // тост «CSQTT работает в трее» — borderless always-on-top, ~3.5 с
        if let Some(at) = self.toast_at {
            let expired = at.elapsed().as_secs_f32() >= 3.5;
            let vp = egui::ViewportId::from_hash_of("csqtt-tray-toast");
            let builder = egui::ViewportBuilder::default()
                .with_title("CSQTT")
                .with_inner_size([340.0, 100.0])
                .with_decorations(false)
                .with_always_on_top();
            ctx.show_viewport_immediate(vp, builder, |c, _class| {
                egui::CentralPanel::default()
                    .frame(
                        egui::Frame::new()
                            .fill(th().CARD)
                            .stroke(Stroke::new(1.0, th().CARD_BORDER))
                            .corner_radius(egui::CornerRadius::same(14))
                            .inner_margin(Margin::same(14)),
                    )
                    .show(c, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.add_space(8.0);
                            ui.label(
                                RichText::new("CSQTT работает в трее")
                                    .strong()
                                    .size(15.0)
                                    .color(th().ON_BG),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new("иконка рядом с часами · клик по ней — открыть")
                                    .size(12.0)
                                    .color(th().ON_SURF_VAR),
                            );
                        });
                    });
                if expired {
                    c.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            if expired {
                self.toast_at = None;
            }
        }
    }

    // ─────────────────────────── экран: Подключение ───────────────────────────

    fn ui_connect(&mut self, ui: &mut egui::Ui) {
        // header: wordmark; выбор профиля и добавление — сразу под ним
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("CSQTT").strong().color(th().ON_BG).size(21.0));
                ui.label(RichText::new("v2.5.0 · desktop").color(th().ON_SURF_VAR).size(11.0));
            });
        });
        ui.add_space(12.0);
        self.profile_bar(ui);
        // карточка с кнопкой подключения — по центру оставшейся высоты
        let card_h = 330.0f32;
        let slack = (ui.available_height() - card_h).max(0.0);
        ui.add_space(slack / 2.0);

        let active = !matches!(self.state, ConnState::Disconnected);
        let status = match self.state {
            ConnState::Connected => ("Подключено", th().PRIMARY),
            ConnState::Connecting => ("Подключение", th().PRIMARY),
            ConnState::Disconnecting => ("Ожидание", th().TERTIARY),
            ConnState::Disconnected => ("Отключено", th().ON_SURF_VAR),
        };

        // центральная кнопка подключения — без карточки, прямо на фоне экрана
        let mut toggle = false;
        ui.vertical_centered(|ui| {
            let (c_rect, resp) = ui.allocate_exact_size(Vec2::splat(176.0), Sense::click());
            let c = c_rect.center();
            let p = ui.painter();
            // анимация: «дыхание» при переходе + финальный импульс-кольцо
            // (elapsed огромен до первой смены состояния — анимации нет)
            let elapsed = self
                .state_anim_at
                .map(|t| t.elapsed().as_secs_f32())
                .unwrap_or(f32::MAX);
            let breathing =
                matches!(self.state, ConnState::Connecting | ConnState::Disconnecting);
            let impulse = matches!(self.state, ConnState::Connected | ConnState::Disconnected)
                && elapsed < 0.6;
            let base_r = 84.0f32 * if active { 1.06 } else { 0.96 };
            let r = if breathing {
                base_r * (1.0 + 0.03 * (elapsed * std::f32::consts::TAU * 1.2).sin())
            } else {
                base_r
            };
            if active {
                p.circle_filled(c, r + 12.0, th().PRIMARY.linear_multiply(0.10));
            }
            p.circle_filled(c, r, if active { th().PRIMARY } else { th().SURF_VAR });
            let ring = match self.state {
                ConnState::Connected | ConnState::Connecting => th().PRIMARY,
                ConnState::Disconnecting => th().TERTIARY,
                ConnState::Disconnected => th().OUTLINE_VAR,
            };
            p.circle_stroke(c, r, Stroke::new(2.0, ring));
            if impulse {
                // расходящееся кольцо: r → r*1.45, прозрачность линейно к 0
                let t = elapsed / 0.6;
                let col = if active { th().PRIMARY } else { th().OUTLINE_VAR };
                p.circle_stroke(c, r * (1.0 + 0.45 * t), Stroke::new(2.5, col.linear_multiply(1.0 - t)));
            }
            if breathing || impulse {
                ui.ctx().request_repaint();
            }
            let gc = c + Vec2::new(0.0, 4.0);
            let gr = r * 0.32;
            let gcol = if active { th().ON_PRIMARY } else { th().ON_SURF_VAR.linear_multiply(0.55) };
            power_glyph(p, gc, gr, Stroke::new(3.0, gcol));
            if resp.clicked() {
                toggle = true;
            }
            ui.add_space(14.0);
            ui.label(RichText::new(status.0).strong().color(status.1).size(14.5));
            let up = self
                .connected_at
                .map(|t| format_uptime(t.elapsed().as_secs()))
                .unwrap_or_else(|| "00:00:00".into());
            ui.label(
                RichText::new(up)
                    .strong()
                    .color(if matches!(self.state, ConnState::Connected) {
                        th().PRIMARY
                    } else {
                        th().ON_SURF_VAR.linear_multiply(0.7)
                    })
                    .size(14.0),
            );
            // бейдж туннелей: пилюля с числом + мелкая серая подпись
            if self.stats.0 > 0 || self.state == ConnState::Connected {
                ui.add_space(2.0);
                let gal_n = ui.fonts(|f| {
                    f.layout_no_wrap(self.stats.0.to_string(), FontId::proportional(11.5), th().ON_PRIMARY)
                });
                let pw = (gal_n.size().x + 18.0).max(30.0);
                let ph = 20.0;
                let gal_s = ui.fonts(|f| {
                    f.layout_no_wrap(
                        format!(
                            "туннели · ↑ {} · ↓ {}",
                            fmt_bytes(self.stats.1),
                            fmt_bytes(self.stats.2)
                        ),
                        FontId::proportional(11.0),
                        th().ON_SURF_VAR,
                    )
                });
                let total = pw + 8.0 + gal_s.size().x;
                let (rect, _) = ui.allocate_exact_size(Vec2::new(total, ph), Sense::hover());
                let pb = ui.painter();
                let pill = Rect::from_min_size(rect.min, Vec2::new(pw, ph));
                let fill = if self.stats.0 > 0 { th().SUCCESS } else { th().ERR };
                pb.rect_filled(pill, CornerRadius::same(10), fill);
                pb.galley(pill.center() - gal_n.size() / 2.0, gal_n, Color32::TRANSPARENT);
                let sub_pos =
                    Pos2::new(rect.right() - gal_s.size().x, rect.center().y - gal_s.size().y / 2.0);
                pb.galley(sub_pos, gal_s, Color32::TRANSPARENT);
            }
        });
        if toggle {
            match self.state {
                ConnState::Disconnected => self.start(),
                ConnState::Connected | ConnState::Connecting => self.stop(),
                ConnState::Disconnecting => {}
            }
        }

        if let Some(err) = self.connect_error.clone() {
            ui.add_space(12.0);
            if banner(ui, &err, th().ERR_CONT, th().ON_ERR_CONT).clicked() {
                self.connect_error = None;
            }
        }

    }

    fn profile_bar(&mut self, ui: &mut egui::Ui) {
        let active_name = self
            .active_profile()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "нет профиля".into());
        let mut selected: Option<u64> = None;
        let mut edit_active = false;
        let mut add_new = false;

        ui.horizontal(|ui| {
            let resp = ui.add_sized(
                Vec2::new((ui.available_width() - 160.0).max(120.0), 44.0),
                egui::Button::new(RichText::new(active_name).color(th().ON_SURF_VAR).size(13.0))
                    .fill(th().SURF_VAR)
                    .corner_radius(22.0),
            );
            let r = resp.rect;
            let p = ui.painter();
            let cx = r.right() - 18.0;
            let cy = r.center().y;
            let ch = if self.picker_open { -3.0 } else { 3.0 };
            p.line_segment(
                [Pos2::new(cx - 4.0, cy - ch), Pos2::new(cx, cy + ch * 0.4)],
                Stroke::new(1.6, th().ON_SURF_VAR),
            );
            p.line_segment(
                [Pos2::new(cx, cy + ch * 0.4), Pos2::new(cx + 4.0, cy - ch)],
                Stroke::new(1.6, th().ON_SURF_VAR),
            );
            let popup_id = ui.id().with("profile-popup");
            if resp.clicked() {
                self.picker_open = !self.picker_open;
                if self.picker_open {
                    ui.memory_mut(|m| m.open_popup(popup_id));
                }
            }
            egui::popup::popup_below_widget(
                ui,
                popup_id,
                &resp,
                egui::PopupCloseBehavior::CloseOnClick,
                |ui| {
                    ui.set_min_width(220.0);
                    for p in &self.store.profiles {
                        let on = Some(p.id) == self.store.active_profile_id;
                        if ui
                            .selectable_label(on, RichText::new(&p.name).color(th().ON_SURF).size(13.0))
                            .clicked()
                        {
                            selected = Some(p.id);
                        }
                    }
                },
            );

            if pill_button_outlined(ui, "Изменить", Vec2::new(96.0, 44.0), th().ON_SURF_VAR).clicked() {
                edit_active = true;
            }
            let pr = ui.add_sized(
                Vec2::splat(44.0),
                egui::Button::new(RichText::new("+").strong().color(th().ON_PRIMARY).size(20.0))
                    .fill(th().PRIMARY)
                    .corner_radius(22.0),
            );
            if pr.clicked() {
                add_new = true;
            }
        });

        if let Some(id) = selected {
            self.store.active_profile_id = Some(id);
            self.store.save();
            self.picker_open = false;
        }
        if edit_active {
            self.editor = self.store.active_profile_id;
        }
        if add_new {
            let id = self.store.next_profile_id + 1;
            self.store.next_profile_id = id;
            let mut p = Profile::default();
            p.id = id;
            p.name = format!("Профиль {id}");
            self.store.profiles.push(p);
            self.store.active_profile_id = Some(id);
            self.store.save();
            self.editor = Some(id);
        }
    }

    // ─────────────────────────── экран: Логи ───────────────────────────

    fn ui_logs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Логи").strong().color(th().ON_BG).size(19.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if chip(ui, "Очистить", th().ON_SURF_VAR).clicked()
                {
                    self.logs.clear();
                }
                if chip(ui, "Копировать", th().ON_SURF_VAR).clicked()
                {
                    let text = self.logs.iter().cloned().collect::<Vec<_>>().join("\n");
                    ui.output_mut(|o| o.copied_text = text);
                }
            });
        });
        ui.add_space(10.0);

        let term_h = (ui.available_height() - 110.0).max(140.0);
        Frame::new()
            .fill(th().TERM_BG)
            .corner_radius(CornerRadius::same(24))
            .inner_margin(Margin::symmetric(14, 12))
            .stroke(Stroke::new(1.0, th().CARD_BORDER))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::AlwaysHidden)
                    .stick_to_bottom(true)
                    .max_height(term_h - 24.0)
                    .show(ui, |ui| {
                        for line in &self.logs {
                            let color = if line.contains("[ОШИБКА]") || line.contains("FATAL") {
                                th().TERM_ERR
                            } else if line.contains("[ВК]") || line.contains("[АВТО API]") {
                                th().INFO
                            } else if line.contains("[КАПЧА]") {
                                th().WARNING
                            } else if line.contains("сохранён")
                                || line.contains("создан")
                                || line.contains("заверш")
                            {
                                th().TERM_OK
                            } else {
                                th().TERM_MUTED
                            };
                            ui.label(RichText::new(line).monospace().size(11.5).color(color));
                        }
                    });
            });

        if csqtt_core::captcha_active() {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let mut ans = self.captcha_answer.clone();
                pill_field(
                    ui,
                    &mut ans,
                    "токен или error:код",
                    (ui.available_width() - 130.0).max(200.0),
                );
                let send = pill_button(ui, "Отправить", Vec2::new(112.0, 40.0)).clicked();
                self.captcha_answer = ans;
                if send && !self.captcha_answer.trim().is_empty() {
                    let a = self.captcha_answer.trim().to_string();
                    if !csqtt_core::submit_captcha_result(a) {
                        push_log("[КАПЧА] ядро не приняло ответ (нет ожидания)".into());
                    }
                    self.captcha_answer.clear();
                }
            });
        }
    }

    // ─────────────────────────── экран: Настройки ───────────────────────────

    fn ui_settings(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Настройки").strong().color(th().ON_BG).size(19.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if icon_button(ui, "close", 36.0).clicked() {
                    self.page = Page::Connect;
                }
            });
        });
        ui.add_space(12.0);

        let mut s = self.settings();
        let has_token = read_vk_token().is_some();
        let mut changed = false;

        // карточка: аккаунт ВК
        cs_card(Margin::symmetric(SP, SP)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let mut login = false;
            setting_row(
                ui,
                "Аккаунт ВКонтакте",
                Some("нужен для режимов «Авто API» и «Авто ВК»"),
                |ui| {
                    if has_token {
                        if chip(ui, "Сброс ВК", th().ERR).clicked()
                        {
                            delete_vk_token();
                        }
                    } else if pill_button(ui, "Логин", Vec2::new(96.0, 36.0)).clicked() {
                        login = true;
                    }
                },
            );
            if login {
                self.start_vk_login();
            }
            let (dot, txt) = if has_token {
                (th().SUCCESS, "токен установлен")
            } else {
                (th().ON_SURF_VAR.linear_multiply(0.6), "токен не установлен")
            };
            ui.label(RichText::new(format!("● {txt}")).color(dot).size(12.0));
            if self.paste_open {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let mut txt = self.paste_text.clone();
                    pill_field(
                        ui,
                        &mut txt,
                        "access_token… или ссылка blank.html",
                        (ui.available_width() - 116.0).max(140.0),
                    );
                    let ok = pill_button(ui, "Сохранить", Vec2::new(104.0, 36.0)).clicked();
                    self.paste_text = txt;
                    if ok {
                        let raw = self.paste_text.clone();
                        let client = http_client();
                        let ui_tx = self.ui_tx.clone();
                        self.rt.spawn(async move {
                            let key = concat!("access", "_token=");
                            let r = raw.trim();
                            let parsed = match r.find(key) {
                                Some(pos) => r[pos + key.len()..]
                                    .split(['&', '#', ' '])
                                    .next()
                                    .unwrap_or("")
                                    .trim()
                                    .to_string(),
                                None => r.to_string(),
                            };
                            if parsed.is_empty() {
                                push_log("[ВК] Не удалось разобрать токен".into());
                                return;
                            }
                            match vk_token_check(&client, &parsed).await {
                                Some(false) => {
                                    push_log("[ВК] Токен не прошёл проверку VK".into());
                                }
                                _ => {
                                    if !save_vk_token(&parsed) {
                                        push_log("[ВК] Не удалось сохранить токен".into());
                                    }
                                    let _ = ui_tx.send(UiEvent::PasteTokenSaved);
                                }
                            }
                        });
                        ui.ctx().request_repaint_after(Duration::from_millis(600));
                    }
                });
            }
        });
        ui.add_space(12.0);

        // карточка: туннель
        cs_card(Margin::symmetric(SP, SP)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            setting_label(ui, "Режим работы");
            let cur = s.work_mode.clone();
            segmented(
                ui,
                "work",
                &cur,
                &seg_opts(&["Капча", "Звонки", "Авто ВК"]),
                &mut |v: &str| {
                    changed = true;
                    s.work_mode = v.to_string();
                    if v == "Авто ВК" {
                        s.hashes = "Авто ВК".into();
                    }
                },
            );
            let need_work_token = s.work_mode == "Авто ВК";
            if need_work_token && !has_token {
                ui.add_space(8.0);
                banner(ui, "требуется авторизация ВКонтакте", th().WARN_CONT, th().ON_WARN_CONT);
            }
            separator(ui);

            setting_label(ui, "Хеши");
            let cur = s.hashes.clone();
            segmented(
                ui,
                "hashes",
                &cur,
                &seg_opts(&["Ручной", "Авто API", "Авто ВК"]),
                &mut |v: &str| {
                    changed = true;
                    s.hashes = v.to_string();
                },
            );
            if s.hashes == "Ручной" {
                ui.add_space(8.0);
                let old = s.custom_hashes.clone();
                Frame::new()
                    .fill(Color32::TRANSPARENT)
                    .corner_radius(CornerRadius::same(18))
                    .inner_margin(Margin::symmetric(14, 10))
                    .stroke(Stroke::new(1.2, th().OUTLINE.linear_multiply(0.45)))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.add(
                            egui::TextEdit::multiline(&mut s.custom_hashes)
                                .hint_text(RichText::new("Хеши через запятую").color(th().ON_SURF_VAR.linear_multiply(0.6)))
                                .text_color(th().ON_SURF)
                                .desired_width(f32::INFINITY)
                                .desired_rows(2)
                                .frame(false),
                        );
                    });
                changed |= s.custom_hashes != old;
            }
            if (s.hashes == "Авто API" || s.hashes == "Авто ВК") && !has_token {
                ui.add_space(8.0);
                banner(ui, "требуется авторизация ВКонтакте", th().WARN_CONT, th().ON_WARN_CONT);
            }
            separator(ui);

            setting_label(ui, "Маскировка");
            let cur = s.masking.clone();
            segmented(ui, "mask", &cur, &seg_opts(&["Простая", "Средняя"]), &mut |v: &str| {
                changed = true;
                s.masking = v.to_string();
            });
            separator(ui);

            setting_label(ui, "Отпечаток");
            let cur = s.fingerprint.clone();
            segmented(
                ui,
                "fp",
                &cur,
                &seg_opts(&["Firefox", "Safari", "Chrome"]),
                &mut |v: &str| {
                    changed = true;
                    s.fingerprint = v.to_string();
                },
            );
            separator(ui);

            setting_row(ui, "Экстра потоки", Some("максимум мощности профиля до 162"), |ui| {
                let on = s.extra_threads;
                switch_pill(ui, on, "Экстра потоки", &mut |v| {
                    changed = true;
                    s.extra_threads = v;
                });
            });
        });
        ui.add_space(12.0);

        // карточка: расширенные опции ядра
        cs_card(Margin::symmetric(SP, SP)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            let head = ui.add_sized(
                Vec2::new(ui.available_width(), 30.0),
                egui::Button::new(
                    RichText::new(if self.adv_open { "▾  Расширенные" } else { "▸  Расширенные" })
                        .strong()
                        .color(th().ON_SURF)
                        .size(14.5),
                )
                .fill(Color32::TRANSPARENT)
                .corner_radius(12.0),
            );
            if head.clicked() {
                self.adv_open = !self.adv_open;
            }
            if self.adv_open {
                separator(ui);
                setting_label_i(ui, "TURN", DOC_TURN);
                let old = s.turn.clone();
                ui.horizontal_wrapped(|ui| {
                    pill_field(ui, &mut s.turn, "TURN host[:port] · пусто = авто-подбор", 380.0);
                });
                changed |= s.turn != old;
                ui.add_space(6.0);
                setting_label(ui, "Свои TURN IP");
                let old = s.custom_turn_ips.clone();
                ui.horizontal_wrapped(|ui| {
                    pill_field(ui, &mut s.custom_turn_ips, "IP через запятую — только они", 380.0);
                });
                changed |= s.custom_turn_ips != old;
                ui.add_space(6.0);
                setting_label_i(ui, "Транспорт TURN", DOC_TURN_TRANSPORT);
                let cur = s.turn_transport.clone();
                segmented(ui, "turntr", &cur, &[("udp", "UDP"), ("tcp", "TCP")], &mut |v: &str| {
                    changed = true;
                    s.turn_transport = v.to_string();
                });
                separator(ui);

                setting_label_i(ui, "SRTP", DOC_SRTP);
                let cur = s.srtp_mode.clone();
                segmented(ui, "srtp", &cur, &[("auto", "AUTO"), ("wrap", "WRAP"), ("dtls", "DTLS")], &mut |v: &str| {
                    changed = true;
                    s.srtp_mode = v.to_string();
                });
                ui.add_space(6.0);
                setting_label_i(ui, "Капча", DOC_CAPTCHA);
                let auto = s.captcha_mode == "auto";
                setting_row(
                    ui,
                    "Системный выбор",
                    Some("ядро само подберёт решатель капчи"),
                    |ui| {
                        let on = auto;
                        switch_pill(ui, on, "Капча системный выбор", &mut |v| {
                            changed = true;
                            s.captcha_mode = if v { "auto".into() } else { "rjs".into() };
                        });
                    },
                );
                if auto {
                    ui.label(
                        RichText::new("вид капчи выбирает система")
                            .color(th().ON_SURF_VAR.linear_multiply(0.7))
                            .size(11.0),
                    );
                } else {
                    ui.add_space(4.0);
                    let cur = s.captcha_mode.clone();
                    segmented(
                        ui,
                        "cap",
                        &cur,
                        &[("rjs", "RJS"), ("wv", "WV")],
                        &mut |v: &str| {
                            changed = true;
                            s.captcha_mode = v.to_string();
                        },
                    );
                }
                ui.add_space(6.0);
                setting_label_i(ui, "Локальный адрес (LISTEN)", DOC_LISTEN);
                let old = s.listen.clone();
                ui.horizontal_wrapped(|ui| {
                    pill_field(ui, &mut s.listen, "127.0.0.1:9000", 380.0);
                });
                changed |= s.listen != old;
                ui.add_space(6.0);
                setting_row(
                    ui,
                    "Проверять хеши ВК",
                    Some("отсеивать мёртвые хеши до запуска туннелей"),
                    |ui| {
                        let on = s.validate_hashes;
                        switch_pill(ui, on, "Проверять хеши ВК", &mut |v| {
                            changed = true;
                            s.validate_hashes = v;
                        });
                    },
                );
                separator(ui);

                setting_row(
                    ui,
                    "Маршрутизация по доменам",
                    Some("часть трафика идёт напрямую, минуя туннель"),
                    |ui| {
                        let on = s.domain_routing;
                        switch_pill(ui, on, "Маршрутизация по доменам", &mut |v| {
                            changed = true;
                            s.domain_routing = v;
                        });
                    },
                );
                if s.domain_routing {
                    ui.add_space(4.0);
                    setting_row(ui, "Исключить RU-зоны", None, |ui| {
                        let on = s.exclude_ru_zones;
                        switch_pill(ui, on, "Исключить RU-зоны", &mut |v| {
                            changed = true;
                            s.exclude_ru_zones = v;
                        });
                    });
                    setting_row(ui, "Шаблонные домены", None, |ui| {
                        let on = s.template_domains;
                        switch_pill(ui, on, "Шаблонные домены", &mut |v| {
                            changed = true;
                            s.template_domains = v;
                        });
                    });
                    setting_row(ui, "Только белый список", None, |ui| {
                        let on = s.domain_whitelist;
                        switch_pill(ui, on, "Белый список доменов", &mut |v| {
                            changed = true;
                            s.domain_whitelist = v;
                        });
                    });
                    ui.add_space(4.0);
                    let old = s.direct_domains.clone();
                    ui.horizontal_wrapped(|ui| {
                        pill_field(ui, &mut s.direct_domains, "домены через запятую", 380.0);
                    });
                    changed |= s.direct_domains != old;
                }
                separator(ui);

                setting_row(
                    ui,
                    "Маршрутизация по IP",
                    Some("часть подсетей идёт напрямую, минуя туннель"),
                    |ui| {
                        let on = s.ip_routing;
                        switch_pill(ui, on, "Маршрутизация по IP", &mut |v| {
                            changed = true;
                            s.ip_routing = v;
                        });
                    },
                );
                if s.ip_routing {
                    ui.add_space(4.0);
                    setting_row(ui, "Только белый список", None, |ui| {
                        let on = s.ip_whitelist;
                        switch_pill(ui, on, "Белый список IP", &mut |v| {
                            changed = true;
                            s.ip_whitelist = v;
                        });
                    });
                    ui.add_space(4.0);
                    let old = s.direct_ips.clone();
                    ui.horizontal_wrapped(|ui| {
                        pill_field(ui, &mut s.direct_ips, "CIDR через запятую", 380.0);
                    });
                    changed |= s.direct_ips != old;
                }
            }
        });
        ui.add_space(10.0);
        ui.label(
            RichText::new("настройки применяются автоматически, кнопка «Сохранить» не нужна")
                .italics()
                .color(th().ON_SURF_VAR.linear_multiply(0.7))
                .size(11.0),
        );

        if changed {
            self.store.settings = Some(s);
            self.store.save();
        }
    }

    // ─────────────────────────── экран: Инфо ───────────────────────────

    fn ui_info(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Инфо").strong().color(th().ON_BG).size(19.0));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if icon_button(ui, "close", 36.0).clicked() {
                    self.page = Page::Connect;
                }
            });
        });
        ui.add_space(12.0);

        cs_card(Margin::symmetric(SP, SP)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new(format!(
                    "csqtt-desktop · v{} (ядро csqtt 2.5.0)",
                    env!("CARGO_PKG_VERSION")
                ))
                    .strong()
                    .color(th().ON_SURF)
                    .size(14.5),
            );
            ui.add_space(8.0);
            for line in [
                "Неофициальный десктопный клиент csqtt: собственное GUI на Rust \
                 (eframe/egui), интерфейс в стиле основного клиента.",
                "Ядро обновлено до csqtt v2.5.0. Бренд и ассеты оригинального \
                 проекта не используются.",
                "Профили, настройки и VK-токен хранятся только на этом компьютере.",
            ] {
                ui.label(RichText::new(line).color(th().ON_SURF_VAR).size(12.5));
                ui.add_space(6.0);
            }
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                if pill_button(ui, "Репозиторий GitHub", Vec2::new(196.0, 42.0)).clicked() {
                    open_browser("https://github.com/ProFFs/csqtt-desktop");
                }
                if pill_button_outlined(
                    ui,
                    "Скачать новую версию",
                    Vec2::new(196.0, 42.0),
                    th().ON_SURF_VAR,
                )
                .clicked()
                {
                    open_browser("https://github.com/ProFFs/csqtt-desktop/releases/latest");
                }
            });
        });
    }

    // ─────────────────────────── оверлеи ───────────────────────────

    fn ui_editor(&mut self, ctx: &egui::Context) {
        let Some(id) = self.editor else { return };
        let Some(idx) = self.store.profiles.iter().position(|p| p.id == id) else {
            self.editor = None;
            return;
        };
        let s = self.settings();
        let max_power = if s.extra_threads { 162 } else { 81 };
        let mut deleted = false;
        let mut close = false;

        egui::Window::new("profile")
            .id(egui::Id::new("profile-editor"))
            .frame(cs_dialog(Margin::same(20)))
            .title_bar(false)
            .resizable(false)
            .movable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                // Единая ширина контента 360 + рамка 20 со всех сторон:
                // все поля растянуты, отступы симметричны, пустого права нет.
                ui.set_width(360.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Редактировать профиль")
                            .strong()
                            .color(th().ON_SURF)
                            .size(15.0),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if icon_button(ui, "close", 34.0).clicked() {
                            close = true;
                        }
                    });
                });
                ui.add_space(12.0);
                let w_all = ui.available_width();
                pill_field(ui, &mut self.store.profiles[idx].name, "Название профиля", w_all);
                ui.add_space(8.0);
                {
                    let gap = ui.spacing().item_spacing.x;
                    let ip_w = (w_all - 110.0 - gap).max(140.0);
                    ui.horizontal(|ui| {
                        pill_field(ui, &mut self.store.profiles[idx].ip, "IP или домен", ip_w);
                        pill_field(ui, &mut self.store.profiles[idx].port, "порт", 110.0);
                    });
                }
                ui.add_space(8.0);
                pill_field(ui, &mut self.store.profiles[idx].password, "Пароль", w_all);
                ui.add_space(12.0);
                power_dots(ui, &mut self.store.profiles[idx].power, max_power, &mut || {});
                ui.add_space(16.0);
                {
                    let off = ((w_all - (104.0 * 2.0 + 12.0)) / 2.0).max(0.0);
                    ui.horizontal(|ui| {
                        ui.add_space(off);
                        if pill_button(ui, "Готово", Vec2::new(104.0, 40.0)).clicked() {
                            close = true;
                        }
                        ui.add_space(12.0);
                        if ui
                            .add_sized(
                                Vec2::new(104.0, 40.0),
                                egui::Button::new(
                                    RichText::new("Удалить")
                                        .strong()
                                        .color(th().ON_ERR_CONT)
                                        .size(13.0),
                                )
                                .fill(th().ERR_CONT)
                                .corner_radius(20.0),
                            )
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            deleted = true;
                        }
                    });
                }
                ui.add_space(4.0);
            });

        if close || deleted {
            if deleted {
                self.store.profiles.remove(idx);
                if self.store.active_profile_id == Some(id) {
                    self.store.active_profile_id = self.store.profiles.first().map(|p| p.id);
                }
            }
            self.store.save();
            self.editor = None;
        }
    }

    fn ui_alert(&mut self, ctx: &egui::Context) {
        let Some(msg) = self.alert.clone() else { return };
        egui::Window::new("alert")
            .id(egui::Id::new("alert"))
            .frame(cs_dialog(Margin::symmetric(18, 16)))
            .title_bar(false)
            .resizable(false)
            .movable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
                ui.set_max_width(360.0);
                ui.label(RichText::new(msg).color(th().ON_SURF).size(13.5));
                ui.add_space(10.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if pill_button(ui, "ОК", Vec2::new(88.0, 36.0)).clicked() {
                        self.alert = None;
                    }
                });
            });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut visuals = if self.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        visuals.panel_fill = th().BG;
        visuals.window_fill = th().CARD;
        visuals.extreme_bg_color = th().SURFACE;
        visuals.window_stroke = Stroke::new(1.0, th().CARD_BORDER);
        visuals.menu_corner_radius = CornerRadius::same(18);
        visuals.faint_bg_color = th().SURF_VAR;
        visuals.widgets.noninteractive.fg_stroke.color = th().ON_BG;
        visuals.widgets.inactive.bg_fill = th().SURF_VAR;
        visuals.widgets.hovered.bg_fill = th().PRIMARY_CONT;
        visuals.selection.bg_fill = th().PRIMARY_CONT;
        visuals.selection.stroke = Stroke::new(1.0, th().PRIMARY);
        ctx.set_visuals(visuals);

        self.drain_channels();

        // трей (Windows): события иконки/меню + тост; затем перехват закрытия
        // окна — если это не «Выйти» из трея, отменяем закрытие и сворачиваем
        #[cfg(windows)]
        self.tray_tick(ctx);
        #[cfg(windows)]
        if !self.quitting && ctx.input(|i| i.viewport().close_requested()) {
            self.tray_on_close(ctx);
        }

        if let Some(rx) = &self.vk_rx {
            match rx.try_recv() {
                Ok(Ok(tok)) => {
                    self.vk_rx = None;
                    // молча: сначала проверяем токен через VK API, пишем только валидный
                    let client = http_client();
                    let ui_tx = self.ui_tx.clone();
                    self.rt.spawn(async move {
                        match vk_token_check(&client, &tok).await {
                            Some(false) => {
                                push_log(
                                    "[ВК] Полученный токен не прошёл проверку VK — вставь вручную"
                                        .into(),
                                );
                                let _ = ui_tx.send(UiEvent::PasteTokenOpen);
                            }
                            None => {
                                push_log(
                                    "[ВК] токен не удалось проверить VK (сеть) — сохраняем как есть"
                                        .into(),
                                );
                                if !save_vk_token(&tok) {
                                    push_log("[ВК] Не удалось сохранить токен".into());
                                }
                            }
                            Some(true) => {
                                if !save_vk_token(&tok) {
                                    push_log("[ВК] Не удалось сохранить токен".into());
                                }
                            }
                        }
                    });
                    ctx.request_repaint_after(Duration::from_millis(600));
                }
                Ok(Err(e)) => {
                    self.vk_rx = None;
                    push_log(format!("[ВК] {e}"));
                    self.paste_open = true;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.vk_rx = None,
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            ctx.request_repaint_after(Duration::from_millis(250));
        }
        if self.picker_open
            && (!ctx.input(|i| i.focused) || ctx.input(|i| i.key_pressed(egui::Key::Escape)))
        {
            self.picker_open = false;
            ctx.memory_mut(|m| m.close_popup());
        }

        if self.state != self.anim_prev_state {
            self.anim_prev_state = self.state;
            self.state_anim_at = Some(Instant::now());
        }
        if self.state == ConnState::Connected {
            if self.connected_at.is_none() {
                self.connected_at = Some(Instant::now());
            }
        } else {
            self.connected_at = None;
        }

        let mut goto = None;
        egui::TopBottomPanel::bottom("nav")
            .frame(
                Frame::new()
                    .fill(th().BG)
                    .inner_margin(Margin { left: 20, right: 20, top: 6, bottom: 14 }),
            )
            .show(ctx, |ui| {
                if let Some(p) = nav_bar(ui, self.page) {
                    goto = Some(p);
                }
            });
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(th().BG)
                    .inner_margin(Margin { left: 20, right: 20, top: 12, bottom: 12 }),
            )
            .show(ctx, |ui| match self.page {
                Page::Connect => self.ui_connect(ui),
                Page::Logs => self.ui_logs(ui),
                Page::Settings => {
                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::AlwaysHidden)
                        .show(ui, |ui| self.ui_settings(ui));
                }
                Page::Info => {
                    ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .scroll_bar_visibility(egui::containers::scroll_area::ScrollBarVisibility::AlwaysHidden)
                        .show(ui, |ui| self.ui_info(ui));
                }
            });

        if let Some(p) = goto {
            self.page = p;
            self.picker_open = false;
        }

        self.ui_editor(ctx);
        self.ui_alert(ctx);

        ctx.request_repaint_after(Duration::from_millis(60));
    }
}

/// Inter — основной шрифт (кириллица есть); Bold → Inter SemiBold.
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "inter".into(),
        Arc::new(egui::FontData::from_static(include_bytes!(
            "../assets/fonts/Inter-Regular.ttf"
        ))),
    );
    fonts.font_data.insert(
        "inter_semibold".into(),
        Arc::new(egui::FontData::from_static(include_bytes!(
            "../assets/fonts/Inter-SemiBold.ttf"
        ))),
    );
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "inter".into());
    // egui 0.31: RichText::strong() меняет только цвет; SemBold подключаем
    // как fallback сразу за Regular — тяжёлые галереи сами его не выбирают,
    // поэтому оставляем единый Inter Regular.
    let _ = &fonts.font_data["inter_semibold"];
    ctx.set_fonts(fonts);
    // чуть шире антиалиасинг-переход: мелкие элементы не выглядят «квадратными»
    ctx.tessellation_options_mut(|o| {
        o.feathering = true;
        o.feathering_size_in_pixels = 1.5;
    });
}

fn main() -> eframe::Result {
    force_dpi_awareness();
    install_embedded_wintun();
    let dark = theme::detect_dark();
    theme::install(dark);
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 880.0])
            .with_min_inner_size([520.0, 700.0])
            .with_title("csqtt-desktop"),
        ..Default::default()
    };
    eframe::run_native(
        "csqtt-desktop",
        opts,
        Box::new(move |cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(App::new(dark)))
        }),
    )
}

// Если процесс запустился без DPI-awareness (например, из планировщика/WMI),
// winit получает scale 1.0 и egui раскладывает UI в физических пикселях —
// интерфейс обрезается справа/снизу. Форсим Per-Monitor V2 до создания окна.
// Если контекст уже задан — вызов безопасно отказывается.
#[cfg(windows)]
fn force_dpi_awareness() {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn SetProcessDpiAwarenessContext(value: isize) -> i32;
    }
    const DPI_AWARE_PER_MONITOR_V2: isize = -4;
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARE_PER_MONITOR_V2);
    }
}

#[cfg(not(windows))]
fn force_dpi_awareness() {}


// ───────────────────────────── UI-тесты (egui_kittest) ─────────────────────────────
#[cfg(test)]
mod token_check_tests {
    use super::parse_users_get_check;

    #[test]
    fn users_get_check_valid_invalid_unknown() {
        assert_eq!(
            parse_users_get_check(r#"{"response":[{"id":1,"first_name":"x"}]}"#),
            Some(true)
        );
        assert_eq!(
            parse_users_get_check(r#"{"error_code":5,"error_text":"User authorization failed"}"#),
            Some(false)
        );
        assert_eq!(parse_users_get_check("не json"), None);
        assert_eq!(parse_users_get_check(""), None);
        assert_eq!(
            parse_users_get_check(r#"{"error_code":6,"error_text":"too many requests"}"#),
            None
        );
    }
}

#[cfg(test)]
mod ui_tests {
    use super::*;
    use accesskit::{Role, Toggled};
    use egui_kittest::kittest::{Key, Node, Queryable};
    use egui_kittest::Harness;

    fn harness<'a>() -> Harness<'a, App> {
        theme::install(true);
        isolate_data_dir();
        Harness::builder()
            .with_size(Vec2::new(560.0, 900.0))
            // фоновый request_repaint_after(60ms) в update() иначе бесконечно
            // продлевает жизнь try_run(): шаг должен быть короче таймера.
            .with_step_dt(0.01)
            .build_eframe(|_cc| App::new(true))
    }

    fn settings<'a, 'b>(h: &'b Harness<'a, App>) -> &'b Settings {
        h.state().store.settings.as_ref().unwrap()
    }

    /// Тесты не трогают реальный ~/.local/share/csqtt-desktop: config.json и
    /// vk_token лежат во временном каталоге и затираются перед каждым тестом
    /// (запуск строго `--test-threads=1`, переменные среды — на весь процесс).
    fn isolate_data_dir() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let dir = std::env::temp_dir().join("csqtt-desktop-tests");
            std::fs::create_dir_all(&dir).ok();
            #[cfg(not(windows))]
            unsafe {
                std::env::set_var("XDG_DATA_HOME", &dir);
            }
            #[cfg(windows)]
            unsafe {
                std::env::set_var("APPDATA", &dir);
            }
        });
        std::fs::remove_file(app_dir().join("config.json")).ok();
        std::fs::remove_file(token_path()).ok();
    }

    /// Снапшоты пиксель-в-пиксель сверяем только на Linux (генерация:
    /// `UPDATE_SNAPSHOTS=1 cargo test -p csqtt-desktop -- --test-threads=1`).
    fn snap(h: &mut Harness<'_, App>, name: &str) {
        #[cfg(target_os = "linux")]
        {
            let img = h.render().expect("headless-рендер (wgpu)");
            egui_kittest::image_snapshot(&img, name);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (h, name);
    }

    /// Клик по первому узлу дерева доступности, подходящему под предикат.
    fn click_where(h: &mut Harness<'_, App>, pred: impl Fn(&Node<'_>) -> bool) {
        h.query_all_by(|n| pred(n))
            .next()
            .expect("matching a11y node not found")
            .click();
    }

    /// Настоящий (мышью) клик по единственному узлу заданной высоты —
    /// нужен для кастомных виджетов, читающих позицию курсора (ползунок).
    fn simulate_click_by_height(h: &mut Harness<'_, App>, height: f64) {
        h.query_all_by(|n| {
            n.raw_bounds()
                .is_some_and(|b| (b.y1 - b.y0 - height).abs() < 0.5)
        })
        .next()
        .expect("matching a11y node not found")
        .simulate_click();
    }

    /// Поля ввода редактора профиля сверху вниз: имя, IP, порт, пароль.
    fn editor_fields<'a>(h: &'a Harness<'a, App>) -> Vec<Node<'a>> {
        let mut v: Vec<Node<'_>> = h
            .query_all_by(|n| matches!(n.role(), Role::TextInput))
            .collect();
        v.sort_by(|a, b| {
            let (ra, rb) = (a.raw_bounds().unwrap(), b.raw_bounds().unwrap());
            (ra.y0, ra.x0).partial_cmp(&(rb.y0, rb.x0)).unwrap()
        });
        v
    }

    /// Число открытых окон egui (редактор, алерт, справка) — у label-текста
    /// узлов доступности нет, поэтому окна считаем по Role::Window.
    fn open_windows(h: &Harness<'_, App>) -> usize {
        h.query_all_by(|n| matches!(n.role(), Role::Window)).count()
    }

    #[test]
    fn nav_switches_pages_and_info_has_repo_button() {
        let mut h = harness();
        h.run_steps(2);
        assert_eq!(h.state().page, Page::Connect);
        h.get_by_label("Настройки").click();
        h.run_steps(2);
        assert_eq!(h.state().page, Page::Settings);
        h.get_by_label("Инфо").click();
        h.run_steps(2);
        assert_eq!(h.state().page, Page::Info);
        assert!(h.query_by_label("Репозиторий GitHub").is_some());
        assert!(h.query_by_label("Скачать новую версию").is_some());
    }

    #[test]
    fn adv_srtp_segmented_is_caps_and_changes_value() {
        let mut h = harness();
        h.run_steps(2);
        h.get_by_label("Настройки").click();
        h.run_steps(2);
        h.get_by_label_contains("Расширенные").click();
        h.run_steps(2);
        assert!(h.state().adv_open);
        // Аббревиатуры — большими буквами.
        assert!(h.query_by_label("AUTO").is_some());
        assert!(h.query_by_label("WRAP").is_some());
        assert!(h.query_by_label("DTLS").is_some());
        assert!(h.query_by_label("UDP").is_some());
        assert!(h.query_by_label("TCP").is_some());
        h.get_by_label("WRAP").click();
        h.run_steps(2);
        assert_eq!(settings(&h).srtp_mode, "wrap");
        h.get_by_label("DTLS").click();
        h.run_steps(2);
        assert_eq!(settings(&h).srtp_mode, "dtls");
    }

    #[test]
    fn captcha_segmented_hidden_until_switch_off() {
        let mut h = harness();
        h.run_steps(2);
        h.get_by_label("Настройки").click();
        h.run_steps(2);
        h.get_by_label_contains("Расширенные").click();
        h.run_steps(2);
        // По умолчанию «система»: сегментов RJS/WV нет, switch включён.
        assert_eq!(settings(&h).captcha_mode, "auto");
        assert!(h.query_by_label("RJS").is_none());
        assert!(h.query_by_label("WV").is_none());
        // Выключаем системный выбор → появляются RJS/WV, значение rjs.
        h.get_by_label_contains("Капча системный выбор").click();
        h.run_steps(2);
        assert_eq!(settings(&h).captcha_mode, "rjs");
        assert!(h.query_by_label("RJS").is_some());
        h.get_by_label("WV").click();
        h.run_steps(2);
        assert_eq!(settings(&h).captcha_mode, "wv");
        // Включаем систему обратно → сегменты снова скрыты.
        h.get_by_label_contains("Капча системный выбор").click();
        h.run_steps(2);
        assert_eq!(settings(&h).captcha_mode, "auto");
        assert!(h.query_by_label("RJS").is_none());
    }

    #[test]
    fn switches_toggle_state() {
        let mut h = harness();
        h.run_steps(2);
        h.get_by_label("Настройки").click();
        h.run_steps(2);
        h.get_by_label_contains("Расширенные").click();
        h.run_steps(2);
        let before = settings(&h).validate_hashes;
        // двоеточие отличает кнопку-switch от текстовой подписи строки
        h.get_by_label_contains("Проверять хеши ВК:").click();
        h.run_steps(2);
        assert_eq!(settings(&h).validate_hashes, !before);
    }

    #[test]
    fn info_dot_popups_exist() {
        let mut h = harness();
        h.run_steps(2);
        h.get_by_label("Настройки").click();
        h.run_steps(2);
        h.get_by_label_contains("Расширенные").click();
        h.run_steps(2);
        // Кнопки ⓘ существуют (по одной на TURN/Транспорт/SRTP/Капча/LISTEN).
        let dots = h
            .query_all_by(|n| n.label().is_some_and(|l| l == "i"))
            .count();
        assert!(dots >= 5, "info dots: {dots}");
    }

    // ─────────────────────── навигация и снапшоты ───────────────────────

    #[test]
    fn all_pages_snapshots() {
        let mut h = harness();
        h.run_steps(2);
        snap(&mut h, "connect");
        h.get_by_label("Логи").click();
        h.run_steps(2);
        assert_eq!(h.state().page, Page::Logs);
        snap(&mut h, "logs_empty");
        h.get_by_label("Настройки").click();
        h.run_steps(2);
        assert_eq!(h.state().page, Page::Settings);
        snap(&mut h, "settings");
        h.get_by_label_contains("Расширенные").click();
        h.run_steps(6);
        snap(&mut h, "settings_advanced");
        h.get_by_label("Инфо").click();
        h.run_steps(2);
        assert_eq!(h.state().page, Page::Info);
        snap(&mut h, "info");
    }

    // ─────────────────────── профиль: редактор ───────────────────────

    #[test]
    fn profile_editor_add_edit_delete() {
        let mut h = harness();
        h.run_steps(2);
        // «Изменить» открывает редактор активного профиля
        h.get_by_label("Изменить").click();
        h.run_steps(6);
        assert_eq!(h.state().editor, Some(1));
        assert_eq!(open_windows(&h), 1);
        // Ввод в пустые поля: IP, порт, пароль
        {
            let f = editor_fields(&h);
            assert_eq!(f.len(), 4, "редактор: 4 поля ввода");
            f[1].type_text("example.org");
            f[2].type_text("443");
            f[3].type_text("s3cret");
        }
        h.run_steps(2);
        {
            let p = &h.state().store.profiles[0];
            assert_eq!(p.ip, "example.org");
            assert_eq!(p.port, "443");
            assert_eq!(p.password, "s3cret");
        }
        // Переименование: выделить всё и заменить
        {
            let f = editor_fields(&h);
            f[0].focus();
            f[0].key_combination(&[Key::Command, Key::A]);
            f[0].type_text("Основной 2");
        }
        h.run_steps(2);
        assert_eq!(h.state().store.profiles[0].name, "Основной 2");
        // Ползунок мощности: непрерывный 1..=81, клик в центр дорожки → ≈41
        simulate_click_by_height(&mut h, 28.0);
        h.run_steps(2);
        assert!((40..=42).contains(&h.state().store.profiles[0].power), "power={}", h.state().store.profiles[0].power);
        snap(&mut h, "editor");
        // «Готово» — закрыть и сохранить
        h.get_by_label("Готово").click();
        h.run_steps(2);
        assert_eq!(h.state().editor, None);
        assert!(app_dir().join("config.json").exists());
        // «Удалить» — профиль и активный указатель исчезают
        h.get_by_label("Изменить").click();
        h.run_steps(6);
        h.get_by_label("Удалить").click();
        h.run_steps(2);
        assert!(h.state().store.profiles.is_empty());
        assert_eq!(h.state().store.active_profile_id, None);
        assert_eq!(h.state().editor, None);
        assert!(h.query_by_label("нет профиля").is_some());
        // «+» создаёт новый профиль и сразу открывает его редактор
        h.get_by_label("+").click();
        h.run_steps(6);
        assert_eq!(h.state().store.profiles.len(), 1);
        assert_eq!(h.state().store.profiles[0].name, "Профиль 2");
        assert_eq!(h.state().editor, Some(2));
        h.get_by_label("Готово").click();
        h.run_steps(2);
        assert_eq!(h.state().editor, None);
    }

    // ─────────────────────── профиль: поповер выбора ───────────────────────

    #[test]
    fn profile_picker_opens_and_selects() {
        let mut h = harness();
        h.run_steps(2);
        // Второй профиль — сразу в store (без UI), чтобы в поповере был выбор
        h.state_mut().store.profiles.push(Profile {
            id: 2,
            name: "Второй".into(),
            ..Profile::default()
        });
        h.run_steps(2);
        // Кнопка активного профиля открывает поповер
        click_where(&mut h, |n| n.label().is_some_and(|l| l == "Основной"));
        h.run_steps(2);
        assert!(h.state().picker_open);
        snap(&mut h, "picker");
        // Выбор «Второй» в поповере: элемент поповера — selectable_label с
        // toggled=False; жмём настоящей мышью (a11y-Action не закрывает popup)
        h.query_all_by(|n| {
            n.label().is_some_and(|l| l == "Второй") && n.toggled() == Some(Toggled::False)
        })
        .next()
        .expect("пункт поповера «Второй»")
        .simulate_click();
        h.run_steps(2);
        assert_eq!(h.state().store.active_profile_id, Some(2));
        assert!(!h.state().picker_open);
        // Кнопка показывает новый профиль
        assert!(h.query_by_label("Второй").is_some());
    }

    // ─────────────────────── кнопка подключения ───────────────────────

    #[test]
    fn connect_requires_ip_and_password() {
        let mut h = harness();
        h.run_steps(2);
        // Круг подключения — кастомный виджет 176x176 с Sense::click
        let circle = |n: &Node<'_>| {
            n.raw_bounds()
                .is_some_and(|b| (b.x1 - b.x0 - 176.0).abs() < 1.0 && (b.y1 - b.y0 - 176.0).abs() < 1.0)
        };
        click_where(&mut h, circle);
        h.run_steps(6);
        let alert = h.state().alert.clone().expect("алерт про IP");
        assert!(alert.contains("IP"), "{alert}");
        assert_eq!(open_windows(&h), 1);
        snap(&mut h, "alert");
        h.get_by_label("ОК").click();
        h.run_steps(2);
        assert!(h.state().alert.is_none());
        // IP/порт есть, пароля нет → алерт про пароль (соединение не стартует)
        h.state_mut().store.profiles[0].ip = "example.org".into();
        h.state_mut().store.profiles[0].port = "443".into();
        click_where(&mut h, circle);
        h.run_steps(6);
        let alert = h.state().alert.clone().expect("алерт про пароль");
        assert!(alert.contains("пароль"), "{alert}");
        h.get_by_label("ОК").click();
        h.run_steps(2);
        assert!(h.state().alert.is_none());
    }

    // ─────────────────────── логи и капча ───────────────────────

    #[test]
    fn logs_copy_clear_and_captcha_field_hidden() {
        let mut h = harness();
        h.run_steps(2);
        h.get_by_label("Логи").click();
        h.run_steps(2);
        // Активной капчи нет → поля ответа и кнопки «Отправить» нет
        assert!(!csqtt_core::captcha_active());
        assert!(h.query_by_label("Отправить").is_none());
        h.state_mut().logs.extend([
            "[ОШИБКА] туннель упал".to_string(),
            "обычная строка".to_string(),
        ]);
        h.run_steps(2);
        snap(&mut h, "logs");
        h.get_by_label("Копировать").click();
        h.run_steps(1);
        assert_eq!(
            h.output().platform_output.copied_text,
            "[ОШИБКА] туннель упал\nобычная строка"
        );
        h.get_by_label("Очистить").click();
        h.run_steps(2);
        assert!(h.state().logs.is_empty());
    }

    // ─────────────────────── настройки: сегменты и ВК-токен ───────────────────────

    #[test]
    fn settings_segments_and_vk_token_reset() {
        let mut h = harness();
        h.run_steps(2);
        h.get_by_label("Настройки").click();
        h.run_steps(2);
        // Режим работы
        h.get_by_label("Звонки").click();
        h.run_steps(2);
        assert_eq!(settings(&h).work_mode, "Звонки");
        // Хеши: «Ручной» показывает поле хешей, «Авто API» скрывает
        h.get_by_label("Ручной").click();
        h.run_steps(2);
        assert_eq!(settings(&h).hashes, "Ручной");
        assert!(h
            .query_all_by(|n| matches!(n.role(), Role::MultilineTextInput))
            .next()
            .is_some());
        h.get_by_label("Авто API").click();
        h.run_steps(2);
        assert_eq!(settings(&h).hashes, "Авто API");
        // «Авто ВК» есть в обеих строках — берём верхнюю (режим работы);
        // он же переключает и хеши в «Авто ВК»
        {
            let mut v: Vec<_> = h
                .query_all_by(|n| n.label().is_some_and(|l| l == "Авто ВК"))
                .collect();
            v.sort_by_key(|n| n.raw_bounds().map(|b| b.y0 as i64).unwrap_or(0));
            assert_eq!(v.len(), 2);
            v[0].click();
        }
        h.run_steps(2);
        assert_eq!(settings(&h).work_mode, "Авто ВК");
        assert_eq!(settings(&h).hashes, "Авто ВК");
        // ВК-токен: без него — «Логин», с ним — чип «Сброс ВК»
        assert!(read_vk_token().is_none());
        assert!(h.query_by_label("Логин").is_some());
        assert!(h.query_by_label("Сброс ВК").is_none());
        assert!(save_vk_token("testtoken123"));
        h.run_steps(2);
        assert!(h.query_by_label("Сброс ВК").is_some());
        snap(&mut h, "settings_token");
        h.get_by_label("Сброс ВК").click();
        h.run_steps(2);
        assert!(read_vk_token().is_none());
        assert!(h.query_by_label("Логин").is_some());
    }

    // ─────────────────────── окно справки (ⓘ) ───────────────────────

    #[test]
    fn help_window_opens_and_closes() {
        let mut h = harness();
        h.run_steps(2);
        h.get_by_label("Настройки").click();
        h.run_steps(2);
        h.get_by_label_contains("Расширенные").click();
        h.run_steps(2);
        assert_eq!(open_windows(&h), 0);
        // Первая ⓘ (TURN) открывает окно «Справка»…
        click_where(&mut h, |n| n.label().is_some_and(|l| l == "i"));
        h.run_steps(20);
        assert_eq!(open_windows(&h), 1);
        snap(&mut h, "help");
        // …та же ⓘ закрывает его
        click_where(&mut h, |n| n.label().is_some_and(|l| l == "i"));
        h.run_steps(20);
        assert_eq!(open_windows(&h), 0);
    }
}
