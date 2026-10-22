// csqtt-desktop — палитра: сине-серая тема; светлая/тёмная выбирается по системе.
#![allow(non_snake_case)]

use eframe::egui::Color32;
use std::sync::OnceLock;

/// Поля названы как прежние константы палитры — код обращения: th().PRIMARY.
#[derive(Clone, Copy)]
pub struct Theme {
    pub BG: Color32,
    pub SURFACE: Color32,
    pub SURF_VAR: Color32,
    pub ON_BG: Color32,
    pub ON_SURF: Color32,
    pub ON_SURF_VAR: Color32,
    pub PRIMARY: Color32,
    pub ON_PRIMARY: Color32,
    pub PRIMARY_CONT: Color32,
    pub SECONDARY: Color32,
    pub TERTIARY: Color32,
    pub OUTLINE: Color32,
    pub OUTLINE_VAR: Color32,
    pub ERR: Color32,
    pub ERR_CONT: Color32,
    pub ON_ERR_CONT: Color32,
    pub CARD: Color32,
    pub CARD_BORDER: Color32,
    pub NAV_BORDER: Color32,
    pub SUCCESS: Color32,
    pub WARNING: Color32,
    pub INFO: Color32,
    pub WARN_CONT: Color32,
    pub ON_WARN_CONT: Color32,
    pub TERM_BG: Color32,
    pub TERM_TEXT: Color32,
    pub TERM_MUTED: Color32,
    pub TERM_OK: Color32,
    pub TERM_ERR: Color32,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}
const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Color32 {
    Color32::from_rgba_premultiplied(r, g, b, a)
}

// Терминал логов остаётся тёмным в обеих темах.
const TERM_BG: Color32 = rgb(0x10, 0x12, 0x16);
const TERM_TEXT: Color32 = rgb(0xDD, 0xE1, 0xE8);
const TERM_MUTED: Color32 = rgb(0x9D, 0xA3, 0xAE);
const TERM_OK: Color32 = rgb(0x9B, 0xD4, 0xAF);
const TERM_ERR: Color32 = rgb(0xFF, 0xB4, 0xAB);

/// Тёмная сине-серая.
pub const DARK: Theme = Theme {
    BG: rgb(0x12, 0x16, 0x20),
    SURFACE: rgb(0x17, 0x1C, 0x28),
    SURF_VAR: rgb(0x23, 0x2A, 0x3A),
    ON_BG: rgb(0xE4, 0xE9, 0xF3),
    ON_SURF: rgb(0xE4, 0xE9, 0xF3),
    ON_SURF_VAR: rgb(0xB9, 0xC3, 0xD6),
    PRIMARY: rgb(0x9C, 0xC0, 0xEC),
    ON_PRIMARY: rgb(0x0E, 0x24, 0x3D),
    PRIMARY_CONT: rgb(0x2E, 0x41, 0x59),
    SECONDARY: rgb(0xAE, 0xBE, 0xDA),
    TERTIARY: rgb(0x93, 0xA6, 0xC6),
    OUTLINE: rgb(0x7A, 0x8C, 0xA8),
    OUTLINE_VAR: rgb(0x39, 0x44, 0x5A),
    ERR: rgb(0xFF, 0xB4, 0xAB),
    ERR_CONT: rgb(0x8C, 0x1D, 0x18),
    ON_ERR_CONT: rgb(0xFF, 0xDA, 0xD6),
    CARD: rgb(0x1A, 0x20, 0x2E),
    CARD_BORDER: rgba(0x7A, 0x8C, 0xA8, 70),
    NAV_BORDER: rgba(0x7A, 0x8C, 0xA8, 95),
    SUCCESS: rgb(0x8F, 0xD3, 0xA8),
    WARNING: rgb(0xE8, 0xC4, 0x66),
    INFO: rgb(0xA8, 0xC7, 0xFA),
    WARN_CONT: rgb(0x4C, 0x3D, 0x16),
    ON_WARN_CONT: rgb(0xF6, 0xE2, 0xAC),
    TERM_BG,
    TERM_TEXT,
    TERM_MUTED,
    TERM_OK,
    TERM_ERR,
};

/// Светлая сине-серая.
pub const LIGHT: Theme = Theme {
    BG: rgb(0xED, 0xF0, 0xF6),
    SURFACE: rgb(0xF7, 0xF9, 0xFC),
    SURF_VAR: rgb(0xE1, 0xE7, 0xF0),
    ON_BG: rgb(0x16, 0x1C, 0x26),
    ON_SURF: rgb(0x16, 0x1C, 0x26),
    ON_SURF_VAR: rgb(0x46, 0x53, 0x6A),
    PRIMARY: rgb(0x3E, 0x6D, 0xA8),
    ON_PRIMARY: rgb(0xFF, 0xFF, 0xFF),
    PRIMARY_CONT: rgb(0xD7, 0xE4, 0xF4),
    SECONDARY: rgb(0x59, 0x69, 0x7F),
    TERTIARY: rgb(0x47, 0x61, 0x7F),
    OUTLINE: rgb(0x5C, 0x6B, 0x82),
    OUTLINE_VAR: rgb(0xC3, 0xCC, 0xDB),
    ERR: rgb(0xB3, 0x26, 0x1E),
    ERR_CONT: rgb(0xF9, 0xDE, 0xDC),
    ON_ERR_CONT: rgb(0x41, 0x0E, 0x0B),
    CARD: rgb(0xF8, 0xFA, 0xFD),
    CARD_BORDER: rgba(0x46, 0x56, 0x6E, 60),
    NAV_BORDER: rgba(0x46, 0x56, 0x6E, 85),
    SUCCESS: rgb(0x14, 0x6C, 0x2E),
    WARNING: rgb(0x7A, 0x59, 0x00),
    INFO: rgb(0x1D, 0x4F, 0x94),
    WARN_CONT: rgb(0xF7, 0xE3, 0xA1),
    ON_WARN_CONT: rgb(0x3D, 0x2E, 0x00),
    TERM_BG,
    TERM_TEXT,
    TERM_MUTED,
    TERM_OK,
    TERM_ERR,
};

static THEME: OnceLock<Theme> = OnceLock::new();
static DEFAULT: Theme = DARK;

pub fn install(dark: bool) {
    let _ = THEME.set(if dark { DARK } else { LIGHT });
}

pub fn th() -> &'static Theme {
    THEME.get().unwrap_or(&DEFAULT)
}

/// Тёмная ли тема у системы. Windows: AppsUseLightTheme в реестре; иначе — тёмная.
#[cfg(windows)]
pub fn detect_dark() -> bool {
    use windows::core::w;
    use windows::Win32::System::Registry::{
        HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW,
    };
    unsafe {
        let mut value: u32 = 1;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        let res = RegGetValueW(
            HKEY_CURRENT_USER,
            w!("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"),
            w!("AppsUseLightTheme"),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut value as *mut u32 as *mut _),
            Some(&mut size),
        );
        match res.ok() {
            Ok(()) => value == 0,
            Err(_) => true,
        }
    }
}

#[cfg(not(windows))]
pub fn detect_dark() -> bool {
    true
}