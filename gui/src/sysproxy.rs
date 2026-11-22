// [v1.5.1] Системный прокси Windows («прокси как в Happ»): в proxy-режиме
// GUI сам включает/выключает прокси WinINet (HKCU Internet Settings), чтобы
// браузер работал без ручных настроек.
//
// Старт: сохраняем ProxyEnable/ProxyServer/ProxyOverride → пишем свои
// (http/https → HTTP CONNECT 127.0.0.1:<http_port>, socks → SOCKS5
// 127.0.0.1:<socks_port>). Стоп/выход: восстанавливаем сохранённые; чего не
// было до старта — удаляем (ProxyEnable без прежнего значения → 0). Уведомление
// WinINet (SETTINGS_CHANGED + REFRESH) — чтобы браузеры подхватили без
// перезапуска. Только HKCU — прав администратора не нужно.

/// Снимок значений, которые были в реестре до старта.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SysProxyBackup {
    pub enable: Option<u32>,
    pub server: Option<String>,
    pub override_: Option<String>,
}

#[cfg(windows)]
mod imp {
    use super::SysProxyBackup;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, HKEY, WIN32_ERROR};
    use windows::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows::Win32::System::Registry::{
        HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, RegCloseKey, RegDeleteValueW, RegGetValueW,
        RegOpenKeyExW, RegSetValueExW, REG_DWORD, REG_SZ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
    };

    const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    unsafe fn read_dword(key: HKEY, name: &str) -> Result<Option<u32>, WIN32_ERROR> {
        let name_w = wide(name);
        let mut value = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let error = RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(name_w.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(std::ptr::addr_of_mut!(value).cast()),
            Some(std::ptr::addr_of_mut!(size)),
        );
        if error == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if error.is_err() {
            return Err(error);
        }
        Ok(Some(value))
    }

    unsafe fn read_sz(key: HKEY, name: &str) -> Result<Option<String>, WIN32_ERROR> {
        let name_w = wide(name);
        let mut size = 0u32;
        let probe = RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(name_w.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(std::ptr::addr_of_mut!(size)),
        );
        if probe == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if probe.is_err() {
            return Err(probe);
        }
        let mut buffer = vec![0u16; (size as usize).div_ceil(2)];
        let mut written = size;
        let error = RegGetValueW(
            key,
            PCWSTR::null(),
            PCWSTR(name_w.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(std::ptr::addr_of_mut!(written)),
        );
        if error == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if error.is_err() {
            return Err(error);
        }
        let units = ((written as usize) / 2).saturating_sub(1); // без завершающего NUL
        let units = units.min(buffer.len());
        Ok(Some(String::from_utf16_lossy(&buffer[..units])))
    }

    unsafe fn open() -> Result<HKEY, WIN32_ERROR> {
        let path = wide(INTERNET_SETTINGS);
        let mut key = HKEY::default();
        let error = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(path.as_ptr()),
            Some(0),
            KEY_READ | KEY_SET_VALUE,
            std::ptr::addr_of_mut!(key),
        );
        if error.is_err() {
            return Err(error);
        }
        Ok(key)
    }

    unsafe fn write_dword(key: HKEY, name: &str, value: u32) -> WIN32_ERROR {
        let name_w = wide(name);
        let bytes = value.to_ne_bytes();
        RegSetValueExW(key, PCWSTR(name_w.as_ptr()), None, REG_DWORD, Some(&bytes))
    }

    unsafe fn write_sz(key: HKEY, name: &str, value: &str) -> WIN32_ERROR {
        let name_w = wide(name);
        let data = wide(value);
        let bytes = unsafe {
            std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), data.len() * 2)
        };
        RegSetValueExW(key, PCWSTR(name_w.as_ptr()), None, REG_SZ, Some(bytes))
    }

    unsafe fn delete_value(key: HKEY, name: &str) {
        let name_w = wide(name);
        let _ = RegDeleteValueW(key, PCWSTR(name_w.as_ptr()));
    }

    /// Браузеры перечитывают реестр прокси без перезапуска.
    unsafe fn notify_wininet() {
        let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
    }

    /// Включить системный прокси на порты (socks, http). None — реестр
    /// недоступен (ничего не меняли, откатывать нечего).
    pub fn apply(socks_port: u16, http_port: u16) -> Option<SysProxyBackup> {
        unsafe {
            let Ok(key) = open() else {
                crate::push_log("[ОШИБКА] Прокси: не открылся HKCU Internet Settings".into());
                return None;
            };
            let backup = SysProxyBackup {
                enable: read_dword(key, "ProxyEnable").ok().flatten(),
                server: read_sz(key, "ProxyServer").ok().flatten(),
                override_: read_sz(key, "ProxyOverride").ok().flatten(),
            };
            let server = format!(
                "http=127.0.0.1:{http_port};https=127.0.0.1:{http_port};socks=127.0.0.1:{socks_port}"
            );
            let mut ok = write_dword(key, "ProxyEnable", 1).is_ok();
            ok &= write_sz(key, "ProxyServer", &server).is_ok();
            ok &= write_sz(key, "ProxyOverride", "127.0.0.1;localhost;<local>").is_ok();
            let _ = RegCloseKey(key);
            if !ok {
                crate::push_log(
                    "[ОШИБКА] Прокси: реестр не записан — включите прокси вручную".into(),
                );
                return None;
            }
            notify_wininet();
            crate::push_log(format!(
                "[ПРОКСИ] системный прокси ВКЛ · http 127.0.0.1:{http_port} · socks 127.0.0.1:{socks_port}"
            ));
            Some(backup)
        }
    }

    /// Восстановить прежние значения (чтого не было — удалить; ProxyEnable без
    /// прежнего значения → 0). Повторный вызов безопасен.
    pub fn restore(backup: &SysProxyBackup) {
        unsafe {
            let Ok(key) = open() else {
                crate::push_log("[ОШИБКА] Прокси: откат реестра не удался (HKCU)".into());
                return;
            };
            match backup.enable {
                Some(value) => {
                    let _ = write_dword(key, "ProxyEnable", value);
                }
                None => {
                    let _ = write_dword(key, "ProxyEnable", 0);
                }
            }
            match &backup.server {
                Some(value) => {
                    let _ = write_sz(key, "ProxyServer", value);
                }
                None => delete_value(key, "ProxyServer"),
            }
            match &backup.override_ {
                Some(value) => {
                    let _ = write_sz(key, "ProxyOverride", value);
                }
                None => delete_value(key, "ProxyOverride"),
            }
            let _ = RegCloseKey(key);
            notify_wininet();
            crate::push_log("[ПРОКСИ] системный прокси отключён · настройки как до запуска".into());
        }
    }

    /// Проверить, что наша строка прокси до сих пор в реестре (пользователь
    /// или другой менеджер могли перебить) — для аккуратного откатa не нужно,
    /// restore unconditional. Утилита для логов.
    #[allow(dead_code)]
    pub fn current_server() -> Option<String> {
        unsafe {
            let key = open().ok()?;
            let value = read_sz(key, "ProxyServer").ok().flatten();
            let _ = RegCloseKey(key);
            value
        }
    }

}

#[cfg(windows)]
pub use imp::{apply, restore};

/// Не-Windows: no-op (Linux-сборка и тесты реестр не трогают).
#[cfg(not(windows))]
pub fn apply(_socks_port: u16, _http_port: u16) -> Option<SysProxyBackup> {
    None
}

#[cfg(not(windows))]
pub fn restore(_backup: &SysProxyBackup) {}

// ─────────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_default_is_empty() {
        let backup = SysProxyBackup::default();
        assert_eq!(backup.enable, None);
        assert_eq!(backup.server, None);
        assert_eq!(backup.override_, None);
    }

    #[test]
    fn proxy_server_format_matches_happ_style() {
        // ровно формат, который пишет apply()
        let server = format!(
            "http=127.0.0.1:{http};https=127.0.0.1:{http};socks=127.0.0.1:{socks}",
            http = 9001,
            socks = 9000
        );
        assert_eq!(
            server,
            "http=127.0.0.1:9001;https=127.0.0.1:9001;socks=127.0.0.1:9000"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_apply_is_noop() {
        assert!(apply(9000, 9001).is_none());
        restore(&SysProxyBackup::default());
    }
}
