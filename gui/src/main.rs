// [CSQTT DESKTOP] Собственный GUI-хост для ядра csqtt-core (eframe/egui).
// Интерфейс вдохновлён мобильным клиентом csqtt (вкладки: подключение, логи,
// настройки, TUN), но реализован с нуля и НЕ использует бренд/дизайн FOCSQ.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, ScrollArea, TextEdit, Ui};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

const MAX_LOG_LINES: usize = 5000;
const EVENT_PREFIX: &str = "__CSQTT_EVENT__|";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct GuiSettings {
    // Подключение
    peer: String,
    turn: String,
    port: String,
    vk: String,
    password: String,
    // Основное
    workers: usize,
    vk_auth_mode: String,
    vk_hash_mode: String,
    captcha_mode: String,
    fingerprint: String,
    obfs: String,
    tun_uds: String,
    // Дополнительно
    client_ids: String,
    device_id: String,
    custom_turn_ips: String,
    turn_transport: String,
    srtp_mode: String,
    generation: u64,
    salt: String,
    vk_js_token: String,
    domain_routing: bool,
    exclude_ru_zones: bool,
    direct_domains: String,
    runtime_threads: usize,
    exact_workers: bool,
    allow_hash_redistribution: bool,
    save_password: bool,
}

impl Default for GuiSettings {
    fn default() -> Self {
        Self {
            peer: String::new(),
            turn: String::new(),
            port: String::new(),
            vk: String::new(),
            password: String::new(),
            workers: 18,
            vk_auth_mode: "vkcalls".to_owned(),
            vk_hash_mode: "manual".to_owned(),
            captcha_mode: "auto".to_owned(),
            fingerprint: "chrome".to_owned(),
            obfs: "unified".to_owned(),
            #[cfg(windows)]
            tun_uds: "wintun".to_owned(),
            #[cfg(not(windows))]
            tun_uds: "csqtt".to_owned(),
            client_ids: String::new(),
            device_id: "unknown".to_owned(),
            custom_turn_ips: String::new(),
            turn_transport: "udp".to_owned(),
            srtp_mode: "auto".to_owned(),
            generation: 0,
            salt: String::new(),
            vk_js_token: String::new(),
            domain_routing: false,
            exclude_ru_zones: true,
            direct_domains: String::new(),
            runtime_threads: 0,
            exact_workers: false,
            allow_hash_redistribution: false,
            save_password: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Status {
    running: bool,
    paused: bool,
    active: i32,
    bytes_up: i64,
    bytes_down: i64,
    started_ms: Option<u64>,
    last_error: Option<String>,
    tun_lost: bool,
}

#[derive(Default)]
struct Shared {
    logs: Mutex<VecDeque<String>>,
    log_generation: AtomicU64,
    status: Mutex<Status>,
    cancel: Mutex<Option<CancellationToken>>,
    result_tx: Mutex<Option<std::sync::mpsc::Sender<Result<(), String>>>>,
}

impl Shared {
    fn push_log(&self, line: String) {
        // События ядра (__CSQTT_EVENT__|KIND|{json}) разбираем в статус,
        // в окно логов пишем только человекочитаемые части.
        if let Some(rest) = line.strip_prefix(EVENT_PREFIX) {
            self.apply_event(rest.trim());
            return;
        }
        let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        if logs.len() >= MAX_LOG_LINES {
            logs.pop_front();
        }
        logs.push_back(line);
        self.log_generation.fetch_add(1, Ordering::Relaxed);
    }

    fn apply_event(&self, encoded: &str) {
        let (kind, payload) = match encoded.split_once('|') {
            Some(pair) => pair,
            None => return,
        };
        let value: serde_json::Value =
            serde_json::from_str(payload).unwrap_or(serde_json::Value::Null);
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        match kind {
            "STATS" => {
                status.active = value["active"].as_i64().unwrap_or(0) as i32;
                status.bytes_up = value["bytes_up"].as_i64().unwrap_or(0);
                status.bytes_down = value["bytes_down"].as_i64().unwrap_or(0);
            }
            "ERROR" => {
                let message = value["message"].as_str().unwrap_or("ошибка").to_owned();
                status.last_error = Some(message);
            }
            "TUN_LOST" => status.tun_lost = true,
            "STOPPED" => {
                status.running = false;
                status.active = 0;
            }
            _ => {}
        }
    }

    fn set_running(&self, running: bool) {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        status.running = running;
        status.tun_lost = false;
        if running {
            status.started_ms = Some(now_ms());
            status.last_error = None;
        } else {
            status.active = 0;
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = std::env::var("APPDATA").map(PathBuf::from).ok();
    #[cfg(not(windows))]
    let base = std::env::var("HOME")
        .map(|home| PathBuf::from(home).join(".config"))
        .ok();
    base.map(|dir| dir.join("csqtt-desktop").join("config.json"))
}

struct App {
    settings: GuiSettings,
    shared: Arc<Shared>,
    tab: usize,
    seen_generation: u64,
    log_view: Vec<String>,
    log_filter: String,
    autoscroll: bool,
    captcha_answer: String,
    status_rx: Option<std::sync::mpsc::Receiver<Result<(), String>>>,
    start_error: Option<String>,
}

impl App {
    fn new(shared: Arc<Shared>) -> Self {
        let settings = load_settings();
        let (tx, rx) = std::sync::mpsc::channel();
        *shared.result_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        Self {
            settings,
            shared,
            tab: 0,
            seen_generation: u64::MAX,
            log_view: Vec::new(),
            log_filter: String::new(),
            autoscroll: true,
            captcha_answer: String::new(),
            status_rx: Some(rx),
            start_error: None,
        }
    }

    fn build_config(&self) -> csqtt_core::ClientConfig {
        let s = &self.settings;
        csqtt_core::ClientConfig {
            turn: s.turn.clone(),
            custom_turn_ips: s.custom_turn_ips.clone(),
            port: s.port.clone(),
            listen: "127.0.0.1:9000".to_owned(),
            vk: s.vk.clone(),
            vk_hash_mode: s.vk_hash_mode.clone(),
            peer: s.peer.clone(),
            workers: s.workers,
            runtime_threads: s.runtime_threads,
            exact_workers: s.exact_workers,
            allow_hash_redistribution: s.allow_hash_redistribution,
            device_id: s.device_id.clone(),
            password: s.password.clone(),
            vk_auth_mode: s.vk_auth_mode.clone(),
            captcha_mode: s.captcha_mode.clone(),
            fingerprint: s.fingerprint.clone(),
            client_ids: s.client_ids.clone(),
            obfs: s.obfs.clone(),
            turn_transport: s.turn_transport.clone(),
            srtp_mode: s.srtp_mode.clone(),
            generation: s.generation,
            salt: s.salt.clone(),
            tun_uds: s.tun_uds.clone(),
            validate_vk_hashes: false,
            vk_js_token: s.vk_js_token.clone(),
            domain_routing: s.domain_routing,
            exclude_ru_zones: s.exclude_ru_zones,
            template_domains: false,
            domain_whitelist: false,
            direct_domains: s.direct_domains.clone(),
            domains_file: Vec::new(),
            ip_routing: false,
            ip_whitelist: false,
            direct_ips: String::new(),
        }
    }

    fn start(&mut self) {
        if self.shared.status.lock().unwrap_or_else(|e| e.into_inner()).running {
            return;
        }
        let config = self.build_config();
        let validate = validate_config(&config);
        if let Some(error) = validate {
            self.start_error = Some(error);
            return;
        }
        self.start_error = None;
        let cancel = CancellationToken::new();
        *self.shared.cancel.lock().unwrap_or_else(|e| e.into_inner()) = Some(cancel.clone());
        self.shared.set_running(true);
        let shared = self.shared.clone();
        std::thread::Builder::new()
            .name("csqtt-runtime".to_owned())
            .spawn(move || {
                let threads = csqtt_core::runtime_worker_threads(
                    config.workers,
                    config.runtime_threads,
                );
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(threads)
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        shared.push_log(format!("[ОШИБКА] Не удалось создать runtime: {error}"));
                        shared.set_running(false);
                        let _ = shared
                            .result_tx
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .as_ref()
                            .map(|tx| tx.send(Err(error.to_string())));
                        return;
                    }
                };
                let result = runtime.block_on(csqtt_core::run_client(config, Some(cancel)));
                let _ = runtime.shutdown_timeout(std::time::Duration::from_secs(2));
                let outcome = match result {
                    Ok(()) => Ok(()),
                    Err(error) => Err(format!("{error:#}")),
                };
                if let Err(message) = &outcome {
                    let mut status = shared.status.lock().unwrap_or_else(|e| e.into_inner());
                    status.last_error = Some(message.clone());
                }
                shared.set_running(false);
                let _ = shared
                    .result_tx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                    .map(|tx| tx.send(outcome));
            })
            .expect("запуск потока клиента");
    }

    fn stop(&self) {
        if !csqtt_core::submit_control_line("STOP".to_owned()) {
            if let Some(cancel) = self
                .shared
                .cancel
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                cancel.cancel();
            }
        }
    }

    fn drain_logs(&mut self) {
        let generation = self.shared.log_generation.load(Ordering::Relaxed);
        if generation == self.seen_generation {
            return;
        }
        self.seen_generation = generation;
        let logs = self.shared.logs.lock().unwrap_or_else(|e| e.into_inner());
        self.log_view = logs.iter().cloned().collect();
    }

    fn tab_bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            for (index, title) in ["Подключение", "Логи", "Настройки", "TUN"]
                .iter()
                .enumerate()
            {
                if ui
                    .selectable_label(self.tab == index, *title)
                    .clicked()
                {
                    self.tab = index;
                }
            }
        });
        ui.separator();
    }

    fn connection_tab(&mut self, ui: &mut Ui) {
        let status = self
            .shared
            .status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let running = status.running;

        let mut settings = self.settings.clone();
        egui::Grid::new("connection_grid")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label("Сервер (TURN, host или turn: URI)");
                ui.add(TextEdit::singleline(&mut settings.turn).hint_text("turn.example.org").desired_width(360.0));
                ui.end_row();
                ui.label("Порт TURN");
                ui.add(TextEdit::singleline(&mut settings.port).hint_text("3478").desired_width(120.0));
                ui.end_row();
                ui.label("Пир (host:port)");
                ui.add(TextEdit::singleline(&mut settings.peer).hint_text("peer.example.org:9000").desired_width(360.0));
                ui.end_row();
                ui.label("Хеши VK (через запятую)");
                ui.add(
                    TextEdit::multiline(&mut settings.vk)
                        .hint_text("Wabc123,Wdef456")
                        .desired_rows(3)
                        .desired_width(480.0),
                );
                ui.end_row();
                ui.label("Пароль подключения");
                ui.add(TextEdit::singleline(&mut settings.password).password(true).desired_width(280.0));
                ui.end_row();
            });
        self.settings = settings;

        ui.horizontal(|ui| {
            if !running {
                if ui.strong("▶ Подключиться").clicked() {
                    self.start();
                }
            } else {
                if ui.strong("■ Отключиться").clicked() {
                    self.stop();
                }
                if ui.button("⏸ Пауза").clicked() {
                    if csqtt_core::submit_control_line("PAUSE".to_owned()) {
                        self.shared.status.lock().unwrap_or_else(|e| e.into_inner()).paused = true;
                    }
                }
                if ui.button("▶ Продолжить").clicked() {
                    if csqtt_core::submit_control_line("RESUME".to_owned()) {
                        self.shared.status.lock().unwrap_or_else(|e| e.into_inner()).paused = false;
                    }
                }
            }
            if ui.button("💾 Сохранить").clicked() {
                save_settings(&self.settings);
            }
        });

        if let Some(error) = &self.start_error {
            ui.colored_label(egui::Color32::LIGHT_RED, format!("✗ {error}"));
        }

        ui.separator();
        let state = if running {
            if status.paused { "Пауза" } else { "Подключено" }
        } else {
            "Остановлено"
        };
        ui.horizontal(|ui| {
            let dot = if running { "🟢" } else { "⚪" };
            ui.strong(format!("{dot} {state}"));
            ui.label(format!("· активных туннелей: {}", status.active));
        });
        ui.label(format!(
            "↑ {} · ↓ {}",
            human_bytes(status.bytes_up),
            human_bytes(status.bytes_down)
        ));
        if status.tun_lost {
            ui.colored_label(egui::Color32::LIGHT_YELLOW, "⚠ TUN потерян — перезапустите подключение (от имени администратора)");
        }
        if let Some(error) = &status.last_error {
            ui.colored_label(egui::Color32::LIGHT_RED, format!("Последняя ошибка: {error}"));
        }

        ui.separator();
        ui.label("Ответ капчи (если режим ручной или солвер просит хост):");
        ui.horizontal(|ui| {
            ui.add(TextEdit::singleline(&mut self.captcha_answer).desired_width(320.0));
            if ui.button("Отправить").clicked() {
                let answer = std::mem::take(&mut self.captcha_answer);
                if !answer.is_empty() && !csqtt_core::submit_captcha_result(answer) {
                    self.shared.push_log("[КАПЧА] Клиент не запущен — ответ не принят".to_owned());
                }
            }
        });
    }

    fn logs_tab(&mut self, ui: &mut Ui) {
        self.drain_logs();
        ui.horizontal(|ui| {
            ui.add(TextEdit::singleline(&mut self.log_filter).hint_text("фильтр…").desired_width(240.0));
            ui.checkbox(&mut self.autoscroll, "автоскролл");
            if ui.button("Очистить").clicked() {
                self.shared.logs.lock().unwrap_or_else(|e| e.into_inner()).clear();
                self.seen_generation = u64::MAX;
            }
            ui.label(format!("{} строк", self.log_view.len()));
        });
        let view = self.log_view.clone();
        let filter = self.log_filter.clone();
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(self.autoscroll)
            .show(ui, |ui| {
                for line in view
                    .iter()
                    .filter(|line| filter.is_empty() || line.contains(filter.as_str()))
                {
                    ui.label(line.as_str());
                }
            });
    }

    fn settings_tab(&mut self, ui: &mut Ui) {
        let mut s = self.settings.clone();
        let mut save_requested = false;
        let mut reset_requested = false;
        egui::Grid::new("settings_grid")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label("Туннелей (workers)");
                ui.add(egui::DragValue::new(&mut s.workers).range(3..=100));
                ui.end_row();
                ui.label("Режим авторизации VK");
                egui::ComboBox::from_id_salt("vk_auth_mode")
                    .selected_text(s.vk_auth_mode.clone())
                    .show_ui(ui, |ui| {
                        for mode in ["vkcalls", "auto_js", "legacy"] {
                            ui.selectable_value(&mut s.vk_auth_mode, mode.to_owned(), mode);
                        }
                    });
                ui.end_row();
                ui.label("Источник хешей");
                egui::ComboBox::from_id_salt("vk_hash_mode")
                    .selected_text(s.vk_hash_mode.clone())
                    .show_ui(ui, |ui| {
                        for mode in ["manual", "auto_js"] {
                            ui.selectable_value(&mut s.vk_hash_mode, mode.to_owned(), mode);
                        }
                    });
                ui.end_row();
                if s.vk_hash_mode == "auto_js" || s.vk_auth_mode == "auto_js" {
                    ui.label("VK access token (auto_js)");
                    ui.add(TextEdit::singleline(&mut s.vk_js_token).password(true).desired_width(360.0));
                    ui.end_row();
                }
                ui.label("Капча");
                egui::ComboBox::from_id_salt("captcha_mode")
                    .selected_text(s.captcha_mode.clone())
                    .show_ui(ui, |ui| {
                        for mode in ["auto", "rjs", "wv"] {
                            ui.selectable_value(&mut s.captcha_mode, mode.to_owned(), mode);
                        }
                    });
                ui.end_row();
                ui.label("Fingerprint TLS");
                ui.add(TextEdit::singleline(&mut s.fingerprint).desired_width(160.0));
                ui.end_row();
                ui.label("Обфускация");
                egui::ComboBox::from_id_salt("obfs")
                    .selected_text(s.obfs.clone())
                    .show_ui(ui, |ui| {
                        for mode in ["unified", "audio", "video"] {
                            ui.selectable_value(&mut s.obfs, mode.to_owned(), mode);
                        }
                    });
                ui.end_row();
                ui.label("SRTP");
                egui::ComboBox::from_id_salt("srtp_mode")
                    .selected_text(s.srtp_mode.clone())
                    .show_ui(ui, |ui| {
                        for mode in ["auto", "wrap", "dtls"] {
                            ui.selectable_value(&mut s.srtp_mode, mode.to_owned(), mode);
                        }
                    });
                ui.end_row();
                ui.label("TUN-интерфейс");
                ui.add(TextEdit::singleline(&mut s.tun_uds).desired_width(160.0));
                ui.end_row();
                ui.label("Доменная маршрутизация");
                ui.horizontal(|ui| {
                    ui.checkbox(&mut s.domain_routing, "вкл");
                    ui.checkbox(&mut s.exclude_ru_zones, "исключить RU-зоны");
                });
                ui.end_row();
                if s.domain_routing {
                    ui.label("Прямые домены (через запятую)");
                    ui.add(TextEdit::singleline(&mut s.direct_domains).desired_width(480.0));
                    ui.end_row();
                }
                ui.label("Свой TURN IP (кастомные)");
                ui.add(TextEdit::singleline(&mut s.custom_turn_ips).desired_width(360.0));
                ui.end_row();
                ui.label("Client IDs (опция)");
                ui.add(TextEdit::singleline(&mut s.client_ids).desired_width(360.0));
                ui.end_row();
                ui.label("Device ID");
                ui.add(TextEdit::singleline(&mut s.device_id).desired_width(240.0));
                ui.end_row();
                ui.label("Нити runtime (0 = авто)");
                ui.add(egui::DragValue::new(&mut s.runtime_threads).range(0..=64));
                ui.end_row();
                ui.checkbox(&mut s.exact_workers, "Точно туннелей (без округления)");
                ui.end_row();
                ui.checkbox(&mut s.allow_hash_redistribution, "Перераспределение групп при отказе звонков");
                ui.end_row();
                ui.checkbox(&mut s.save_password, "Сохранять пароль в конфиге");
                ui.end_row();
            });
        ui.horizontal(|ui| {
            if ui.button("💾 Сохранить настройки").clicked() {
                save_requested = true;
            }
            if ui.button("↺ Сбросить").clicked() {
                reset_requested = true;
            }
        });
        if reset_requested {
            self.settings = GuiSettings::default();
        } else {
            self.settings = s;
            if save_requested {
                save_settings(&self.settings);
            }
        }
    }

    fn tun_tab(&mut self, ui: &mut Ui) {
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.heading("Настройка TUN");
                ui.separator();
                if cfg!(windows) {
                    ui.strong("Windows");
                    ui.label("1. Запустите программу от имени администратора — без прав администратора создание TUN-адаптера (Wintun) завершается ошибкой.");
                    ui.label("2. Положите wintun.dll рядом с csqtt-desktop.exe (https://www.wintun.net/builds/wintun-0.14.1.zip, каталог x64).");
                    ui.label("3. На вкладке «Подключение» нажмите «Подключиться»: ядро само создаст адаптер, назначит адрес и маршрутизирует трафик в туннель.");
                    ui.label("4. Для доменной маршрутизации включите её в настройках — RU-домены пойдут напрямую.");
                } else {
                    ui.strong("Linux");
                    ui.label("1. Требуется доступ к /dev/net/tun и права CAP_NET_ADMIN (запуск от root или setcap на бинарник).");
                    ui.label("2. Ядро создаст интерфейс csqtt и настроит его автоматически.");
                    ui.label("3. Для доменной маршрутизации включите её в настройках.");
                }
                ui.separator();
                ui.label("Имя/режим TUN в настройках: ");
                ui.monospace(&self.settings.tun_uds);
            });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // забираем результаты работы клиента
        if let Some(rx) = &self.status_rx {
            while let Ok(result) = rx.try_recv() {
                match result {
                    Ok(()) => self.shared.push_log("[GUI] Сессия завершена".to_owned()),
                    Err(error) => {
                        self.shared
                            .push_log(format!("[GUI] Сессия завершена с ошибкой: {error}"))
                    }
                }
            }
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(500));
        egui::CentralPanel::default().show(ctx, |ui| {
            self.tab_bar(ui);
            match self.tab {
                0 => self.connection_tab(ui),
                1 => self.logs_tab(ui),
                2 => self.settings_tab(ui),
                _ => self.tun_tab(ui),
            }
        });
    }
}

fn validate_config(config: &csqtt_core::ClientConfig) -> Option<String> {
    if config.peer.trim().is_empty() {
        return Some("Укажите пир (host:port) на вкладке «Подключение»".to_owned());
    }
    if config.password.is_empty() {
        return Some("Укажите пароль подключения".to_owned());
    }
    if config.vk_hash_mode != "auto_js" && config.vk.trim().is_empty() {
        return Some("Укажите хеши VK".to_owned());
    }
    if config.vk_hash_mode == "auto_js" && config.vk_js_token.trim().is_empty() {
        return Some("Для режима auto_js нужен VK access token (Настройки)".to_owned());
    }
    None
}

fn human_bytes(value: i64) -> String {
    const UNITS: [&str; 5] = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
    let mut value = value as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn load_settings() -> GuiSettings {
    let Some(path) = config_path() else {
        return GuiSettings::default();
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return GuiSettings::default();
    };
    let mut settings: GuiSettings = serde_json::from_str(&text).unwrap_or_default();
    if !settings.save_password {
        settings.password.clear();
    }
    settings
}

fn save_settings(settings: &GuiSettings) {
    let Some(path) = config_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut copy = settings.clone();
    if !copy.save_password {
        copy.password.clear();
    }
    if let Ok(text) = serde_json::to_string_pretty(&copy) {
        if let Ok(mut file) = std::fs::File::create(&path) {
            let _ = file.write_all(text.as_bytes());
        }
    }
}

fn main() -> eframe::Result<()> {
    let shared = Arc::new(Shared::default());
    csqtt_core::set_events_enabled(true);
    {
        let sink = shared.clone();
        csqtt_core::set_log_callback(Box::new(move |line: String| {
            for line in line.lines() {
                sink.push_log(line.to_owned());
            }
        }));
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 640.0])
            .with_min_inner_size([700.0, 480.0])
            .with_title("CSQTT Desktop"),
        ..Default::default()
    };
    eframe::run_native(
        "CSQTT Desktop",
        options,
        Box::new(move |_cc| -> Result<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Box::new(App::new(shared)))
        }),
    )
}