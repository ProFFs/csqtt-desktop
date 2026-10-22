// csqtt-desktop — десктопный клиент csqtt.
//
// Интерфейс: тёмная тема, анимированный mesh-фон, «жидкая» лента волн,
// профили (имя/IP/порт/пароль/мощность), режимы работы (Капча/Звонки/Авто ВК),
// режимы хешей (Ручной/Авто API/Авто ВК), автоприменение настроек.
// VK-токен: WebView2-логин на Windows, ручной ввод на других ОС.
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
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

// ───────────────────────────── палитра ─────────────────────────────

const BG: Color32 = Color32::from_rgb(0x0A, 0x0A, 0x0A);
const MESH_BASE: Color32 = Color32::from_rgb(0x05, 0x05, 0x08);
const CARD: Color32 = Color32::from_rgb(0x1C, 0x1C, 0x1C);
const CARD_HOVER: Color32 = Color32::from_rgb(0x22, 0x22, 0x22);
const FIELD: Color32 = Color32::from_rgb(0x2B, 0x2C, 0x31);
const SUCCESS: Color32 = Color32::from_rgb(0x4C, 0xC3, 0x8A);
const WARNING: Color32 = Color32::from_rgb(0xF2, 0xB8, 0x4B);
const INFO: Color32 = Color32::from_rgb(0x5B, 0x9D, 0xF7);
const ERROR: Color32 = Color32::from_rgb(0xE5, 0x48, 0x4D);
const TEXT: Color32 = Color32::from_rgb(0xF2, 0xF2, 0xF2);
const TEXT_2: Color32 = Color32::from_rgb(0x9A, 0x9D, 0xA3);
const TEXT_3: Color32 = Color32::from_rgb(0x66, 0x66, 0x66);
const BORDER: Color32 = Color32::from_rgb(0x26, 0x26, 0x26);
const BTN_PRIMARY: Color32 = Color32::from_rgb(0xD9, 0xD9, 0xD9);
const BTN_SECONDARY: Color32 = Color32::from_rgb(0x25, 0x25, 0x25);

const EVENT_PREFIX: &str = "__CSQTT_EVENT__|";
const VK_AUTH_URL: &str = "https://oauth.vk.ru/authorize?client_id=7793118&scope=1073737727\
    &redirect_uri=https%3A%2F%2Foauth.vk.ru%2Fblank.html&display=page&response_type=token\
    &revoke=1&v=5.199";
const VK_API: &str = "https://api.vk.ru/method/";
const DEFAULT_CLIENT_IDS: &str = "8202606,6287487";
const LISTEN: &str = "127.0.0.1:9000";
const WORKERS_PER_GROUP: usize = 9;
const MAX_VK_HASHES: usize = 6;

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
            port: "46000".into(),
            password: String::new(),
            power: 9,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct Settings {
    work_mode: String,   // Капча | Звонки | Авто ВК
    hashes: String,      // Ручной | Авто API | Авто ВК
    custom_hashes: String,
    masking: String,     // Простая | Средняя
    fingerprint: String, // Firefox | Safari | Chrome
    extra_threads: bool,
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
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Connect,
    Logs,
    Settings,
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
        push_log("[ВК] Токен сохранён".into());
    }
    res.is_ok()
}

fn delete_vk_token() {
    let _ = std::fs::remove_file(token_path());
    push_log("[ВК] Токен удалён".into());
}

/// Токен либо введён вручную, либо это URL редиректа blank.html#access_token=...
fn extract_token(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(pos) = raw.find("access_token=") {
        let rest = &raw[pos + "access_token=".len()..];
        let tok = rest
            .split(['&', '#', ' '])
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        return (!tok.is_empty()).then_some(tok);
    }
    (!raw.contains('/')).then(|| raw.to_string())
}

fn open_browser(url: &str) {
    #[cfg(windows)]
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .spawn();
    #[cfg(not(windows))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

// ───────────────────── VK-логин: WebView2 (Windows) ─────────────────────

#[cfg(windows)]
fn vk_login_start() -> Receiver<Result<String, String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(run_vk_webview());
    });
    rx
}

#[cfg(windows)]
fn run_vk_webview() -> Result<String, String> {
    use std::time::Instant;
    use winit::application::ApplicationHandler;
    use winit::dpi::LogicalSize;
    use winit::event::WindowEvent;
    use winit::event_loop::{ActiveEventLoop, EventLoop};
    use winit::window::{Window, WindowAttributes, WindowId};

    #[derive(Debug)]
    enum UserEv {
        Token(String),
    }

    struct VkApp {
        window: Option<Window>,
        webview: Option<wry::WebView>,
        result: Option<String>,
        error: Option<String>,
        started: Instant,
    }

    impl ApplicationHandler<UserEv> for VkApp {
        fn resumed(&mut self, el: &ActiveEventLoop) {
            if self.window.is_some() || self.error.is_some() {
                return;
            }
            let attrs = WindowAttributes::default()
                .with_title("Авторизация ВКонтакте")
                .with_inner_size(LogicalSize::new(520.0, 720.0))
                .with_min_inner_size(LogicalSize::new(380.0, 420.0));
            let window = match el.create_window(attrs) {
                Ok(w) => w,
                Err(e) => {
                    self.error = Some(format!("окно: {e}"));
                    el.exit();
                    return;
                }
            };
            let proxy = el.create_proxy();
            let proxy2 = el.create_proxy();
            let init_js = r#"
                setInterval(function () {
                    try {
                        var u = window.location.href || '';
                        if (u.indexOf('blank.html') >= 0 && u.indexOf('access_token') >= 0) {
                            window.ipc.postMessage('VKURL|' + u);
                        }
                    } catch (e) {}
                }, 400);
            "#;
            let built = wry::WebViewBuilder::new()
                .with_url(VK_AUTH_URL)
                .with_initialization_script(init_js)
                .with_navigation_handler(move |url: String| {
                    if url.contains("blank.html")
                        && let Some(tok) = extract_token(&url)
                    {
                        let _ = proxy.send_event(UserEv::Token(tok));
                    }
                    true
                })
                .with_ipc_handler(move |req: wry::http::Request<String>| {
                    if let Some(rest) = req.body().strip_prefix("VKURL|")
                        && let Some(tok) = extract_token(rest)
                    {
                        let _ = proxy2.send_event(UserEv::Token(tok));
                    }
                })
                .build(&window);
            match built {
                Ok(w) => {
                    self.webview = Some(w);
                    self.window = Some(window);
                }
                Err(e) => {
                    self.error =
                        Some(format!("WebView недоступен ({e}); установи WebView2 Runtime"));
                    el.exit();
                }
            }
        }

        fn window_event(&mut self, el: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
            if let WindowEvent::CloseRequested = event {
                el.exit();
            }
        }

        fn user_event(&mut self, el: &ActiveEventLoop, ev: UserEv) {
            match ev {
                UserEv::Token(t) => self.result = Some(t),
            }
            el.exit();
        }

        fn about_to_wait(&mut self, el: &ActiveEventLoop) {
            if self.started.elapsed() > Duration::from_secs(300) {
                el.exit();
            }
        }
    }

    let event_loop = EventLoop::<UserEv>::with_user_event()
        .build()
        .map_err(|e| format!("event loop: {e}"))?;
    let mut app = VkApp {
        window: None,
        webview: None,
        result: None,
        error: None,
        started: Instant::now(),
    };
    let _ = event_loop.run_app(&mut app);
    if let Some(e) = app.error {
        return Err(e);
    }
    app.result
        .ok_or_else(|| "окно закрыто до завершения входа".to_string())
}

#[cfg(not(windows))]
fn vk_login_start() -> Receiver<Result<String, String>> {
    let (tx, rx) = mpsc::channel();
    let _ = tx.send(Err("на этой ОС открой страницу входа и вставь токен вручную".into()));
    rx
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

// ───────────────────────────── виджеты ─────────────────────────────

fn card(fill: Color32, radius: u8, stroke_opt: Option<Stroke>, inner: Margin) -> Frame {
    let f = Frame::new()
        .fill(fill)
        .corner_radius(CornerRadius::same(radius))
        .inner_margin(inner);
    match stroke_opt {
        Some(s) => f.stroke(s),
        None => f,
    }
}

fn mac_dots(painter: &Painter, left: Pos2) {
    for i in 0..3 {
        painter.circle_filled(
            left + Vec2::new(4.5 + i as f32 * 17.0, 4.5),
            4.5,
            Color32::from_rgb(0x55, 0x55, 0x55).linear_multiply(0.85),
        );
    }
}

fn dropdown_pill(
    ui: &mut egui::Ui,
    id: &str,
    value: &str,
    options: &[&'static str],
    on_change: &mut dyn FnMut(&str),
) {
    let label = RichText::new(format!("{value}  ⌄")).color(Color32::BLACK).size(13.0);
    let resp = ui
        .add_sized(
            Vec2::new(128.0, 28.0),
            egui::Button::new(label)
                .fill(BTN_PRIMARY)
                .corner_radius(8.0),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let popup_id = ui.id().with(("dd", id));
    if resp.clicked() {
        ui.memory_mut(|m| m.open_popup(popup_id));
    }
    egui::popup::popup_below_widget(
        ui,
        popup_id,
        &resp,
        egui::PopupCloseBehavior::CloseOnClick,
        |ui| {
            card(CARD_HOVER, 10, Some(Stroke::new(1.0, BORDER)), Margin::symmetric(4, 4))
                .show(ui, |ui| {
                    ui.set_min_width(160.0);
                    for opt in options {
                        let selected = value == *opt;
                        if ui
                            .selectable_label(
                                selected,
                                RichText::new(*opt).color(TEXT).size(13.0),
                            )
                            .clicked()
                        {
                            on_change(opt);
                        }
                    }
                });
        },
    );
}

fn switch_pill(ui: &mut egui::Ui, on: bool, on_toggle: &mut dyn FnMut(bool)) {
    let (_, rect) = ui.allocate_space(Vec2::new(44.0, 24.0));
    let resp = ui.interact(rect, ui.id().with("switch"), Sense::click());
    if resp.clicked() {
        on_toggle(!on);
    }
    let painter = ui.painter();
    let fill = if on { BTN_PRIMARY } else { BTN_SECONDARY };
    painter.rect_filled(rect.shrink(1.0), CornerRadius::same(12), fill);
    if !on {
        painter.rect_stroke(
            rect.shrink(1.0),
            CornerRadius::same(12),
            Stroke::new(1.0, Color32::from_white_alpha(26)),
            StrokeKind::Inside,
        );
    }
    let r = 9.0;
    let cy = rect.center().y;
    let cx = if on {
        rect.right() - 3.0 - r
    } else {
        rect.left() + 3.0 + r
    };
    painter.circle_filled(
        Pos2 { x: cx, y: cy },
        r,
        if on { Color32::BLACK } else { Color32::WHITE },
    );
}

fn text_field(ui: &mut egui::Ui, value: &mut String, hint: &str, width: f32) {
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(RichText::new(hint).color(TEXT_3))
            .desired_width(width)
            .vertical_align(Align::Center),
    );
}

fn setting_row(ui: &mut egui::Ui, title: &str, content: &mut dyn FnMut(&mut egui::Ui)) {
    card(CARD_HOVER, 12, None, Margin::symmetric(16, 12)).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(title).strong().color(TEXT).size(14.5));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                content(ui);
            });
        });
    });
}

/// Анимированная «жидкая» лента волн; при наведении курсора амплитуда растёт.
fn liquid_banner(ui: &mut egui::Ui, size: Vec2, title: &str, subtitle: &str, t: f32) {
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(12), MESH_BASE);

    let mouse = ui
        .input(|i| i.pointer.interact_pos())
        .unwrap_or(rect.center());
    let phase = t * 1.6;
    let w = rect.width();
    let h = rect.height();
    let cy = rect.center().y + 6.0;

    let mut x = 0.0f32;
    while x < w {
        let gx = rect.left() + x;
        let nx = x / w;
        let env = (-((nx - (0.3 + 0.25 * (phase * 0.35).sin())).powi(2)) / 0.02).exp()
            + 0.8
                * (-((nx - (0.7 + 0.2 * (phase * 0.22 + 1.7).cos())).powi(2)) / 0.03).exp();
        let dx = (mouse.x - gx).abs();
        let boost = if resp.hovered() {
            1.0 + 1.4 * (-((dx / 90.0).powi(2))).exp()
        } else {
            1.0
        };
        let osc = (nx * 14.0 + phase).sin() * 0.5 + (nx * 31.0 - phase * 1.3).sin() * 0.5;
        let amp = h * 0.42 * env * boost * (0.55 + 0.45 * osc.abs());
        let gray = (140.0 + 115.0 * osc).clamp(30.0, 255.0) as u8;
        let alpha = (60.0 + 190.0 * env.min(1.0) * (0.4 + 0.6 * osc.abs())).clamp(0.0, 255.0) as u8;
        painter.line_segment(
            [
                Pos2::new(gx, cy - amp * (0.5 + 0.5 * osc)),
                Pos2::new(gx, cy + amp * (0.5 - 0.5 * osc) * 0.9 + amp * 0.1),
            ],
            Stroke::new(1.6, Color32::from_rgba_premultiplied(gray, gray, gray, alpha)),
        );
        x += 3.0;
    }
    painter.text(
        rect.left_top() + Vec2::new(20.0, 18.0),
        Align2::LEFT_TOP,
        title,
        FontId::proportional(20.0),
        TEXT,
    );
    painter.text(
        rect.left_top() + Vec2::new(20.0, 44.0),
        Align2::LEFT_TOP,
        subtitle,
        FontId::proportional(12.0),
        TEXT_2,
    );
    painter.rect_stroke(
        rect,
        CornerRadius::same(12),
        Stroke::new(1.0, BORDER),
        StrokeKind::Inside,
    );
}

/// Фон «mesh»: мягкие световые пятна по орбитам + статичная зернистость.
fn mesh_background(ui: &mut egui::Ui, rect: Rect, t: f32) {
    let painter = ui.painter();
    painter.rect_filled(rect, 0.0, MESH_BASE);
    let maxd = rect.width().max(rect.height());
    let blobs: [(Color32, f32, f32, f32); 3] = [
        (Color32::from_rgb(0xFF, 0xF4, 0xDF), 0.35, 0.30, 0.90),
        (Color32::from_rgb(0xFF, 0xFF, 0xFF), 0.40, 0.30, 0.55),
        (Color32::from_rgb(0xF7, 0xE9, 0xD2), 0.30, 0.60, 0.30),
    ];
    for (k, (color, size, sx, sy)) in blobs.iter().enumerate() {
        let tt = t * 0.25 + k as f32 * 2.1;
        let fx = (k as f32 - 1.0) * 0.35 + tt.sin() * sx;
        let fy = (tt * 1.3 + k as f32 * 0.7).cos() * sy;
        let center = rect.min
            + Vec2::new(
                (fx * 0.5 + 0.5) * rect.width(),
                (fy * 0.5 + 0.5) * rect.height(),
            );
        let radius = maxd * size;
        for layer in (0..12).rev() {
            let f = layer as f32 / 12.0;
            painter.circle_filled(
                center,
                radius * (0.35 + 0.65 * f),
                color.linear_multiply(0.05 * (1.0 - f)),
            );
        }
    }
    painter.rect_filled(rect, 0.0, Color32::from_black_alpha(110));
    let mut rng = XorShift(0xC5A7_7E12_F00D_D00D);
    for _ in 0..140 {
        let p = rect.min
            + Vec2::new(
                (rng.next_u64() % rect.width().max(1.0) as u64) as f32,
                (rng.next_u64() % rect.height().max(1.0) as u64) as f32,
            );
        painter.circle_filled(p, 0.8, Color32::from_white_alpha(8));
    }
}

fn power_slider(ui: &mut egui::Ui, power: &mut usize, max: usize, on_change: &mut dyn FnMut()) {
    let groups = (max / WORKERS_PER_GROUP).max(2);
    let before = *power;
    ui.horizontal(|ui| {
        ui.label(RichText::new("Мощность").strong().color(TEXT));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(RichText::new(format!("{power} потоков")).color(TEXT).size(13.0));
        });
    });
    let (_, rect) = ui.allocate_space(Vec2::new(ui.available_width(), 26.0));
    let resp = ui.interact(rect, ui.id().with("power-slider"), Sense::click_and_drag());
    let painter = ui.painter();
    let track_l = rect.left() + 8.0;
    let track_w = (rect.width() - 16.0).max(1.0);
    for i in 0..groups {
        let gx = track_l + track_w * (i as f32 / (groups - 1) as f32);
        let filled = (i + 1) * WORKERS_PER_GROUP <= *power;
        painter.circle_filled(
            Pos2::new(gx, rect.center().y),
            3.0,
            if filled { TEXT_2 } else { Color32::from_white_alpha(26) },
        );
    }
    let frac = (*power as f32 / max as f32).clamp(0.0, 1.0);
    let kx = track_l + track_w * frac;
    painter.line_segment(
        [Pos2::new(track_l, rect.center().y), Pos2::new(kx, rect.center().y)],
        Stroke::new(2.0, TEXT_3),
    );
    painter.circle_filled(Pos2::new(kx, rect.center().y), 8.0, BTN_PRIMARY);
    if (resp.dragged() || resp.clicked())
        && let Some(pos) = ui.input(|i| i.pointer.interact_pos())
    {
        let f = ((pos.x - track_l) / track_w).clamp(0.0, 1.0);
        let mut g = (f * groups as f32).round() as usize;
        if g < 1 {
            g = 1;
        }
        *power = (g * WORKERS_PER_GROUP).min(max);
    }
    if *power != before {
        on_change();
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
    vk_pending: Option<Receiver<Result<String, String>>>,
    picker_open: bool,
    paste_open: bool,
    paste_text: String,
    connect_error: Option<String>,
    captcha_answer: String,
}

impl App {
    fn new() -> Self {
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
            vk_pending: None,
            picker_open: false,
            paste_open: false,
            paste_text: String::new(),
            connect_error: None,
            captcha_answer: String::new(),
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
                    "STOPPED" => self.state = ConnState::Disconnected,
                    "ACTIVE_ZERO" => self.logs.push_back("· нет активных туннелей".into()),
                    "TUN_LOST" => {
                        self.logs.push_back("[ТЮН] канал потерян".into());
                        self.state = ConnState::Disconnected;
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
                    }
                    _ => {}
                }
            } else {
                if self.logs.len() >= 3000 {
                    self.logs.pop_front();
                }
                self.logs.push_back(line);
            }
        }
        while let Ok(ev) = self.ui_rx.try_recv() {
            match ev {
                UiEvent::State(s) => self.state = s,
                UiEvent::Alert(msg) => self.alert = Some(msg),
            }
        }
        let mut done: Option<Result<String, String>> = None;
        if let Some(rx) = &self.vk_pending {
            match rx.try_recv() {
                Ok(res) => done = Some(res),
                Err(TryRecvError::Disconnected) => {
                    done = Some(Err("канал входа закрыт".into()))
                }
                Err(TryRecvError::Empty) => {}
            }
        }
        if let Some(res) = done {
            self.vk_pending = None;
            match res {
                Ok(tok) => {
                    if save_vk_token(&tok) {
                        self.alert = Some("Авторизация ВКонтакте пройдена".into());
                    } else {
                        self.alert = Some("Не удалось сохранить токен ВК".into());
                    }
                    self.paste_open = false;
                }
                Err(e) => {
                    push_log(format!("[ВК] Вход не завершён: {e}"));
                    self.paste_open = true;
                }
            }
        }
    }

    fn start(&mut self) {
        let Some(profile) = self.active_profile() else {
            self.alert = Some("Нет профиля — добавьте его кнопкой «+ Добавить»".into());
            return;
        };
        if profile.ip.trim().is_empty() || profile.port.trim().is_empty() {
            self.alert = Some("Заполните IP и порт в профиле".into());
            return;
        }
        if profile.password.trim().is_empty() {
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
        let workers = profile.power.max(WORKERS_PER_GROUP);
        let vk_token_for_core = token.clone();
        let auto_api = hash_mode == "auto_api";
        let hash_mode_owned = hash_mode.to_string();

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

            let config = csqtt_core::ClientConfig {
                turn: String::new(),
                custom_turn_ips: String::new(),
                port: String::new(),
                listen: LISTEN.to_string(),
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
                captcha_mode: "auto".to_string(),
                fingerprint,
                client_ids: DEFAULT_CLIENT_IDS.to_string(),
                obfs: obfs.to_string(),
                turn_transport: "udp".to_string(),
                srtp_mode: "auto".to_string(),
                generation,
                salt,
                tun_uds: if cfg!(windows) { "wintun" } else { "tun" }.to_string(),
                validate_vk_hashes: false,
                vk_js_token: vk_token_for_core,
                domain_routing: false,
                exclude_ru_zones: false,
                template_domains: false,
                domain_whitelist: false,
                direct_domains: String::new(),
                domains_file: Vec::new(),
                ip_routing: false,
                ip_whitelist: false,
                direct_ips: String::new(),
            };

            let result = csqtt_core::run_client(config, Some(cancel)).await;
            if let Err(e) = &result {
                push_log(format!("[КЛИЕНТ] Остановка: {e}"));
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

    // ─────────────────────────── экран: Подключение ───────────────────────────

    fn ui_connect(&mut self, ui: &mut egui::Ui) {
        let t = now_secs_f32();
        let rect = ui.max_rect();
        mesh_background(ui, rect, t);

        let profile_name = self
            .active_profile()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "профиль не выбран".into());
        let subtitle = match self.state {
            ConnState::Disconnected => "не подключено",
            ConnState::Connecting => "подключение...",
            ConnState::Connected => "подключено",
            ConnState::Disconnecting => "отключение...",
        };

        // верхняя строка: liquid-лента + кнопка «+ Добавить»
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_width(rect.width() - 140.0);
                liquid_banner(
                    ui,
                    Vec2::new(rect.width() - 140.0, 96.0),
                    "csqtt",
                    &format!("{profile_name} · {subtitle}"),
                    t,
                );
            });
            ui.with_layout(Layout::top_down(Align::Min), |ui| {
                ui.add_space(4.0);
                if ui
                    .add_sized(
                        Vec2::new(116.0, 30.0),
                        egui::Button::new(RichText::new("+ Добавить").color(TEXT).size(13.0))
                            .fill(CARD)
                            .stroke(Stroke::new(1.0, BORDER))
                            .corner_radius(15.0),
                    )
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                {
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
            });
        });

        // центральная кнопка подключения
        let center = rect.center() + Vec2::new(0.0, -16.0);
        let base_r = 74.0f32;
        let pulse = if self.state == ConnState::Connected {
            1.0 + 0.03 * (t * 4.2).sin()
        } else {
            1.0
        };
        let r = base_r * pulse;
        let painter = ui.painter();
        let ring = match self.state {
            ConnState::Connected => SUCCESS,
            ConnState::Connecting | ConnState::Disconnecting => INFO,
            ConnState::Disconnected => BORDER,
        };
        painter.circle_filled(center, r + 10.0, Color32::from_black_alpha(90));
        painter.circle_filled(center, r, CARD);
        painter.circle_stroke(center, r, Stroke::new(2.0, ring));
        if matches!(self.state, ConnState::Connecting | ConnState::Disconnecting) {
            let a = (t * 2.4) % std::f32::consts::TAU;
            for i in 0..10 {
                let ang = a + i as f32 * (std::f32::consts::TAU / 10.0);
                let p = center + Vec2::angled(ang) * (r + 10.0);
                painter.circle_filled(
                    p,
                    (3.0 - i as f32 * 0.25).max(0.5),
                    INFO.linear_multiply(1.0 - i as f32 / 10.0),
                );
            }
        }
        let ir = r * 0.36;
        let icon_col = if self.state == ConnState::Connected { SUCCESS } else { TEXT };
        painter.circle_stroke(center + Vec2::new(0.0, 3.0), ir, Stroke::new(3.0, icon_col));
        painter.line_segment(
            [
                center + Vec2::new(0.0, 3.0 - ir - 6.0),
                center + Vec2::new(0.0, 3.0 - ir + 12.0),
            ],
            Stroke::new(3.0, icon_col),
        );
        let btn_rect = Rect::from_center_size(center, Vec2::splat(r * 2.1));
        if ui
            .interact(btn_rect, ui.id().with("connect"), Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            match self.state {
                ConnState::Disconnected => self.start(),
                ConnState::Connected | ConnState::Connecting => self.stop(),
                ConnState::Disconnecting => {}
            }
        }
        let status = match self.state {
            ConnState::Disconnected => ("Подключиться", TEXT_2),
            ConnState::Connecting => ("Подключение...", TEXT),
            ConnState::Disconnecting => ("Отключение...", TEXT),
            ConnState::Connected => ("Подключено", SUCCESS),
        };
        painter.text(
            center + Vec2::new(0.0, r + 30.0),
            Align2::CENTER_TOP,
            status.0,
            FontId::proportional(16.0),
            status.1,
        );
        if self.state == ConnState::Connected || self.stats.0 > 0 {
            painter.text(
                center + Vec2::new(0.0, r + 56.0),
                Align2::CENTER_TOP,
                format!(
                    "туннели: {}   ↑ {}   ↓ {}",
                    self.stats.0,
                    fmt_bytes(self.stats.1),
                    fmt_bytes(self.stats.2)
                ),
                FontId::proportional(12.0),
                TEXT_2,
            );
        }

        // карточка ошибки
        if let Some(err) = self.connect_error.clone() {
            let w = 460.0f32;
            let mut job = LayoutJob::simple(err, FontId::proportional(12.0), ERROR, w - 24.0);
            job.wrap.max_rows = 2;
            let galley = painter.layout_job(job);
            let gh = galley.size().y + 20.0;
            let er = Rect::from_center_size(
                center + Vec2::new(0.0, r + 110.0),
                Vec2::new(w, gh),
            );
            painter.rect_filled(er, CornerRadius::same(10), CARD);
            painter.rect_stroke(
                er,
                CornerRadius::same(10),
                Stroke::new(1.0, ERROR.linear_multiply(0.5)),
                StrokeKind::Inside,
            );
            painter.galley(
                er.center() - galley.size() / 2.0,
                galley,
                Color32::TRANSPARENT,
            );
            if ui
                .interact(er, ui.id().with("err-close"), Sense::click())
                .clicked()
            {
                self.connect_error = None;
            }
        }

        // нижний выбор профиля
        let picker_w = 320.0f32;
        let others = self.store.profiles.len().saturating_sub(1);
        let mut picker_h = 44.0f32;
        if self.picker_open && others > 0 {
            picker_h += 44.0 * others.min(5) as f32 + 12.0;
        }
        let picker_rect = Rect::from_min_size(
            Pos2::new(
                rect.center().x - picker_w / 2.0,
                rect.bottom() - picker_h - 14.0,
            ),
            Vec2::new(picker_w, picker_h),
        );
        self.ui_profile_picker(ui, picker_rect);
    }

    fn ui_profile_picker(&mut self, ui: &mut egui::Ui, rect: Rect) {
        let mut selected: Option<u64> = None;
        let mut edited: Option<u64> = None;

        if self.picker_open {
            let others: Vec<(u64, String)> = self
                .store
                .profiles
                .iter()
                .filter(|p| Some(p.id) != self.store.active_profile_id)
                .take(5)
                .map(|p| (p.id, p.name.clone()))
                .collect();
            let list_h = 44.0 * others.len() as f32 + 12.0;
            let list_rect = Rect::from_min_size(
                Pos2::new(rect.left(), rect.top()),
                Vec2::new(rect.width(), list_h),
            );
            {
                let painter = ui.painter();
                painter.rect_filled(list_rect, CornerRadius::same(12), CARD);
                painter.rect_stroke(
                    list_rect,
                    CornerRadius::same(12),
                    Stroke::new(1.0, BORDER.linear_multiply(0.6)),
                    StrokeKind::Inside,
                );
            }
            let mut y = list_rect.top() + 6.0;
            for (pid, name) in others {
                let row_rect = Rect::from_min_size(
                    Pos2::new(list_rect.left() + 4.0, y),
                    Vec2::new(list_rect.width() - 8.0, 38.0),
                );
                let hit = ui.put(row_rect, |ui: &mut egui::Ui| {
                    ui.add_sized(
                        row_rect.size(),
                        egui::Button::new(RichText::new(&name).color(TEXT).size(13.5))
                            .fill(Color32::TRANSPARENT)
                            .corner_radius(8.0),
                    )
                });
                if hit.clicked() {
                    selected = Some(pid);
                }
                let edit_rect = Rect::from_min_size(
                    Pos2::new(row_rect.right() - 36.0, row_rect.top() + 7.0),
                    Vec2::new(28.0, 24.0),
                );
                let hit2 = ui.put(edit_rect, |ui: &mut egui::Ui| {
                    ui.add_sized(
                        edit_rect.size(),
                        egui::Button::new(RichText::new("\u{270E}").color(TEXT_2).size(13.0))
                            .fill(Color32::TRANSPARENT),
                    )
                });
                if hit2.clicked() {
                    edited = Some(pid);
                }
                y += 44.0;
            }
        }

        let cur_rect = Rect::from_min_size(
            Pos2::new(rect.left(), rect.bottom() - 44.0),
            Vec2::new(rect.width(), 44.0),
        );
        let title = self
            .active_profile()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "Нет профилей".into());
        {
            let painter = ui.painter();
            painter.rect_filled(cur_rect, CornerRadius::same(12), CARD);
            painter.rect_stroke(
                cur_rect,
                CornerRadius::same(12),
                Stroke::new(1.0, BORDER.linear_multiply(0.6)),
                StrokeKind::Inside,
            );
            painter.text(
                cur_rect.left_center() + Vec2::new(16.0, 0.0),
                Align2::LEFT_CENTER,
                &title,
                FontId::proportional(13.5),
                TEXT,
            );
            let chevron = if self.picker_open { "\u{25B4}" } else { "\u{25BE}" };
            painter.text(
                cur_rect.right_center() + Vec2::new(-16.0, 0.0),
                Align2::RIGHT_CENTER,
                chevron,
                FontId::proportional(12.0),
                TEXT_2,
            );
        }
        if ui
            .interact(cur_rect, ui.id().with("picker"), Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            self.picker_open = !self.picker_open;
        }

        if let Some(id) = selected {
            self.store.active_profile_id = Some(id);
            self.store.save();
            self.picker_open = false;
        }
        if let Some(id) = edited {
            self.editor = Some(id);
            self.picker_open = false;
        }
    }

    // ─────────────────────────── экран: Логи ───────────────────────────

    fn ui_logs(&mut self, ui: &mut egui::Ui) {
        card(
            CARD,
            12,
            Some(Stroke::new(1.0, BORDER.linear_multiply(0.6))),
            Margin::symmetric(14, 10),
        )
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Логи").strong().color(TEXT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .button(RichText::new("Очистить").color(TEXT_2).size(12.0))
                        .clicked()
                    {
                        self.logs.clear();
                    }
                });
            });
            let h = (ui.available_height() - 52.0).max(80.0);
            ScrollArea::vertical()
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .max_height(h)
                .show(ui, |ui| {
                    for line in &self.logs {
                        let color = if line.contains("[ОШИБКА]") || line.contains("FATAL") {
                            ERROR
                        } else if line.contains("[ВК]") || line.contains("[АВТО API]") {
                            INFO
                        } else {
                            TEXT_2
                        };
                        ui.label(RichText::new(line).monospace().size(11.5).color(color));
                    }
                });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Ответ капчи:").color(TEXT_2).size(12.0));
                let mut ans = self.captcha_answer.clone();
                text_field(ui, &mut ans, "success_token / error:...", 280.0);
                let send = ui
                    .button(RichText::new("Отправить").color(TEXT).size(12.0))
                    .clicked();
                self.captcha_answer = ans;
                if send && !self.captcha_answer.trim().is_empty() {
                    let a = self.captcha_answer.trim().to_string();
                    if !csqtt_core::submit_captcha_result(a) {
                        push_log("[КАПЧА] ядро не приняло ответ (нет ожидания)".into());
                    }
                    self.captcha_answer.clear();
                }
            });
        });
    }

    // ─────────────────────────── экран: Настройки ───────────────────────────

    fn ui_settings(&mut self, ui: &mut egui::Ui) {
        card(
            CARD,
            12,
            Some(Stroke::new(1.0, BORDER.linear_multiply(0.6))),
            Margin::symmetric(16, 16),
        )
        .show(ui, |ui| {
            let mut s = self.settings();
            let has_token = read_vk_token().is_some();
            let mut changed = false;

            // ── Аккаунт ВК ──
            ui.label(RichText::new("Аккаунт ВКонтакте").strong().color(TEXT).size(15.0));
            ui.label(
                RichText::new("Токен нужен для режимов «Авто API» и «Авто ВК»")
                    .color(TEXT_3)
                    .size(12.0),
            );
            ui.horizontal(|ui| {
                if has_token {
                    ui.label(RichText::new("● токен установлен").color(SUCCESS).size(13.0));
                } else if self.vk_pending.is_some() {
                    ui.label(RichText::new("ждём завершения входа...").color(TEXT_3).size(13.0));
                } else {
                    ui.label(RichText::new("● токен не установлен").color(TEXT_3).size(13.0));
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if has_token {
                        if ui
                            .button(
                                RichText::new("Сброс ВК")
                                    .color(Color32::from_rgb(0xFF, 0x8A, 0x80))
                                    .size(13.0),
                            )
                            .clicked()
                        {
                            delete_vk_token();
                        }
                    } else if ui
                        .button(RichText::new("Логин").color(TEXT).size(13.0))
                        .clicked()
                    {
                        #[cfg(not(windows))]
                        open_browser(VK_AUTH_URL);
                        self.vk_pending = Some(vk_login_start());
                        self.paste_open = true;
                    }
                });
            });
            if self.paste_open && !has_token {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("или вставь токен/ссылку:")
                            .color(TEXT_3)
                            .size(11.5),
                    );
                    let mut txt = self.paste_text.clone();
                    text_field(
                        ui,
                        &mut txt,
                        "access_token… или ссылка blank.html",
                        (ui.available_width() - 110.0).max(120.0),
                    );
                    let ok = ui
                        .button(RichText::new("Сохранить").color(TEXT).size(12.0))
                        .clicked();
                    self.paste_text = txt;
                    if ok {
                        if save_vk_token(&self.paste_text.clone()) {
                            self.paste_text.clear();
                            self.paste_open = false;
                            self.alert = Some("Токен ВКонтакте сохранён".into());
                        } else {
                            self.alert = Some("Не удалось разобрать токен".into());
                        }
                    }
                });
            }
            ui.add_space(12.0);

            let warn_token = |ui: &mut egui::Ui, needed: bool| {
                if needed && !has_token {
                    ui.label(
                        RichText::new("⚠ требуется авторизация ВКонтакте")
                            .color(WARNING)
                            .size(11.5),
                    );
                }
            };

            // ── Режим работы ──
            {
                let cur = s.work_mode.clone();
                let mut ch = false;
                setting_row(ui, "Режим работы", &mut |ui| {
                    dropdown_pill(
                        ui,
                        "work",
                        &cur,
                        &["Капча", "Звонки", "Авто ВК"],
                        &mut |v: &str| {
                            ch = true;
                            s.work_mode = v.to_string();
                            if v == "Авто ВК" {
                                s.hashes = "Авто ВК".into();
                            }
                        },
                    );
                });
                changed |= ch;
                warn_token(ui, s.work_mode == "Авто ВК");
                ui.add_space(6.0);
            }

            // ── Хеши ──
            {
                let cur = s.hashes.clone();
                let mut ch = false;
                setting_row(ui, "Хеши", &mut |ui| {
                    dropdown_pill(
                        ui,
                        "hashes",
                        &cur,
                        &["Ручной", "Авто API", "Авто ВК"],
                        &mut |v: &str| {
                            ch = true;
                            s.hashes = v.to_string();
                        },
                    );
                });
                changed |= ch;
                if s.hashes == "Ручной" {
                    let old = s.custom_hashes.clone();
                    ui.add(
                        egui::TextEdit::multiline(&mut s.custom_hashes)
                            .hint_text(RichText::new("Хеши через запятую").color(TEXT_3))
                            .desired_width(f32::INFINITY)
                            .desired_rows(2),
                    );
                    changed |= s.custom_hashes != old;
                }
                warn_token(ui, s.hashes == "Авто API" || s.hashes == "Авто ВК");
                ui.add_space(6.0);
            }

            // ── Маскировка ──
            {
                let cur = s.masking.clone();
                let mut ch = false;
                setting_row(ui, "Маскировка", &mut |ui| {
                    dropdown_pill(ui, "mask", &cur, &["Простая", "Средняя"], &mut |v: &str| {
                        ch = true;
                        s.masking = v.to_string();
                    });
                });
                changed |= ch;
                ui.add_space(6.0);
            }

            // ── Отпечаток ──
            {
                let cur = s.fingerprint.clone();
                let mut ch = false;
                setting_row(ui, "Отпечаток", &mut |ui| {
                    dropdown_pill(
                        ui,
                        "fp",
                        &cur,
                        &["Firefox", "Safari", "Chrome"],
                        &mut |v: &str| {
                            ch = true;
                            s.fingerprint = v.to_string();
                        },
                    );
                });
                changed |= ch;
                ui.add_space(6.0);
            }

            // ── Экстра потоки ──
            {
                let mut ch = false;
                setting_row(ui, "Экстра потоки", &mut |ui| {
                    let on = s.extra_threads;
                    switch_pill(ui, on, &mut |v| {
                        ch = true;
                        s.extra_threads = v;
                    });
                });
                changed |= ch;
                ui.label(
                    RichText::new("увеличивает максимум мощности профиля до 162 потоков")
                        .color(TEXT_3)
                        .size(11.0),
                );
            }

            ui.add_space(10.0);
            ui.label(
                RichText::new("настройки применяются автоматически, кнопка «Сохранить» не нужна")
                    .color(TEXT_3)
                    .italics()
                    .size(11.0),
            );

            if changed {
                self.store.settings = Some(s);
                self.store.save();
            }
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
        let max_power = if s.extra_threads { 162 } else { 90 };
        let mut deleted = false;
        let mut close = false;

        egui::Window::new("profile")
            .id(egui::Id::new("profile-editor"))
            .frame(card(
                CARD,
                14,
                Some(Stroke::new(1.0, Color32::from_white_alpha(10))),
                Margin::same(0),
            ))
            .title_bar(false)
            .resizable(false)
            .movable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
            ui.set_max_width(360.0);
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.add_space(14.0);
                let (_, r) = ui.allocate_space(Vec2::new(52.0, 12.0));
                mac_dots(ui.painter(), r.left_top());
                ui.add_space(10.0);
                ui.label(
                    RichText::new("Редактировать профиль")
                        .strong()
                        .color(TEXT)
                        .size(14.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button(RichText::new("✕").color(TEXT_2)).clicked() {
                        close = true;
                    }
                });
            });
            ui.add_space(6.0);
            let body = card(BG, 12, Some(Stroke::new(1.0, BORDER)), Margin::symmetric(16, 14));
            body.show(ui, |ui| {
                ui.label(
                    RichText::new("——— Данные профиля ———")
                        .color(TEXT_3)
                        .size(12.0),
                );
                ui.add_space(8.0);
                let before = self.store.profiles[idx].clone();
                let p = &mut self.store.profiles[idx];
                text_field(ui, &mut p.name, "Название профиля", f32::INFINITY);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    text_field(ui, &mut p.ip, "31.59.104.110", 210.0);
                    text_field(ui, &mut p.port, "46000", 100.0);
                });
                ui.add_space(8.0);
                text_field(ui, &mut p.password, "Пароль", f32::INFINITY);
                ui.add_space(12.0);
                power_slider(ui, &mut p.power, max_power, &mut || {});
                if self.store.profiles[idx] != before {
                    self.store.save();
                }
            });
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui
                    .add_sized(
                        Vec2::new(88.0, 28.0),
                        egui::Button::new(RichText::new("Готово").color(Color32::BLACK).size(13.5))
                            .fill(BTN_PRIMARY)
                            .corner_radius(8.0),
                    )
                    .clicked()
                {
                    close = true;
                }
                if ui
                    .button(RichText::new("Удалить").color(ERROR).size(13.5))
                    .clicked()
                {
                    deleted = true;
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new("изменения сохраняются сами")
                            .color(TEXT_3)
                            .size(11.0),
                    );
                });
            });
            ui.add_space(12.0);
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
            .frame(card(
                CARD,
                14,
                Some(Stroke::new(1.0, Color32::from_white_alpha(12))),
                Margin::symmetric(18, 16),
            ))
            .title_bar(false)
            .resizable(false)
            .movable(false)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .show(ctx, |ui| {
            ui.set_max_width(380.0);
            ui.label(RichText::new(msg).color(TEXT).size(13.5));
            ui.add_space(8.0);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_sized(
                        Vec2::new(72.0, 26.0),
                        egui::Button::new(RichText::new("ОК").color(Color32::BLACK).size(13.0))
                            .fill(BTN_PRIMARY)
                            .corner_radius(8.0),
                    )
                    .clicked()
                {
                    self.alert = None;
                }
            });
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG;
        visuals.window_fill = CARD;
        visuals.extreme_bg_color = FIELD;
        visuals.faint_bg_color = FIELD;
        visuals.widgets.noninteractive.fg_stroke.color = TEXT;
        visuals.widgets.inactive.bg_fill = FIELD;
        visuals.widgets.hovered.bg_fill = CARD_HOVER;
        visuals.selection.stroke.color = INFO;
        ctx.set_visuals(visuals);

        self.drain_channels();

        let mut goto = None;
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(BG)
                    .inner_margin(Margin { left: 0, right: 16, top: 12, bottom: 16 }),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    // сайдбар
                    card(
                        CARD,
                        14,
                        Some(Stroke::new(1.0, Color32::from_white_alpha(12))),
                        Margin::same(8),
                    )
                    .show(ui, |ui| {
                        ui.set_width(72.0);
                        ui.set_height(ui.available_height());
                        ui.vertical_centered(|ui| {
                            ui.add_space(10.0);
                            for (page, icon, _label) in [
                                (Page::Connect, "power", "Подключение"),
                                (Page::Logs, "logs", "Логи"),
                            ] {
                                if nav_button(ui, page == self.page, icon).clicked() {
                                    goto = Some(page);
                                }
                                ui.add_space(12.0);
                            }
                            ui.add_space((ui.available_height() - 76.0).max(0.0));
                            if nav_button(ui, self.page == Page::Settings, "gear").clicked() {
                                goto = Some(Page::Settings);
                            }
                            ui.add_space(10.0);
                        });
                    });

                    // контент
                    ui.vertical(|ui| {
                        ui.set_width(ui.available_width());
                        ui.set_height(ui.available_height());
                        match self.page {
                            Page::Connect => self.ui_connect(ui),
                            Page::Logs => self.ui_logs(ui),
                            Page::Settings => {
                                ScrollArea::vertical()
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        self.ui_settings(ui);
                                    });
                            }
                        }
                    });
                });
            });

        if let Some(p) = goto {
            self.page = p;
            self.picker_open = false;
        }

        self.ui_editor(ctx);
        self.ui_alert(ctx);

        ctx.request_repaint_after(Duration::from_millis(40));
    }
}

fn nav_button(ui: &mut egui::Ui, selected: bool, icon: &str) -> egui::Response {
    let btn = egui::Button::new("")
        .min_size(Vec2::splat(52.0))
        .fill(if selected { BTN_PRIMARY } else { Color32::TRANSPARENT })
        .corner_radius(14.0);
    let resp = ui.add(btn);
    let p = resp.rect.center();
    let col = if selected { Color32::BLACK } else { TEXT };
    let painter = ui.painter();
    let sw = Stroke::new(2.0, col);
    match icon {
        "power" => {
            painter.circle_stroke(p + Vec2::new(0.0, 2.0), 8.0, sw);
            painter.line_segment([p + Vec2::new(0.0, -12.0), p + Vec2::new(0.0, -1.0)], sw);
        }
        "logs" => {
            for i in 0..3 {
                let y = p.y - 6.0 + i as f32 * 6.0;
                painter.line_segment(
                    [Pos2::new(p.x - 8.0, y), Pos2::new(p.x + 8.0 - i as f32 * 5.0, y)],
                    sw,
                );
            }
        }
        _ => {
            painter.circle_stroke(p, 5.0, sw);
            for i in 0..6 {
                let a = i as f32 * std::f32::consts::TAU / 6.0;
                let d = Vec2::angled(a);
                painter.line_segment([p + d * 7.5, p + d * 10.5], sw);
            }
        }
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn main() -> eframe::Result {
    install_embedded_wintun();
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 680.0])
            .with_min_inner_size([860.0, 560.0])
            .with_title("csqtt-desktop"),
        ..Default::default()
    };
    eframe::run_native(
        "csqtt-desktop",
        opts,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}