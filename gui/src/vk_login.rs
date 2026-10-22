// csqtt-desktop — окно входа ВКонтакте (WebView2, чистый Win32 + webview2-com).
//
// Открывает маленькое окно поверх всех, грузит VK OAuth; по навигации на URL с
// access_token перехватывает токен, шлёт его в канал и само закрывается.
// Второй winit EventLoop в процессе eframe незаконен, поэтому здесь только Win32.

use std::sync::mpsc::Sender;

#[cfg(not(windows))]
pub fn start(_url: String, tx: Sender<Result<String, String>>) {
    let _ = tx.send(Err("Окно входа доступно только в Windows".into()));
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::channel;
    use std::sync::OnceLock;
    use webview2_com::Microsoft::Web::WebView2::Win32::*;
    use webview2_com::{
        CreateCoreWebView2ControllerCompletedHandler, CreateCoreWebView2EnvironmentCompletedHandler,
        NavigationStartingEventHandler, NewWindowRequestedEventHandler,
    };
    use windows::core::{w, Error, HSTRING, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{E_POINTER, HWND, LPARAM, LRESULT, RECT, WPARAM};
    // UpdateWindow в windows-rs живёт в Gdi; сама фича Gdi нужна и для WNDCLASSW
    // (поле hbrBackground: HBRUSH гейтит его cfg-ом).
    use windows::Win32::Graphics::Gdi::UpdateWindow;
    use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx};
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::*;

    struct State {
        controller: OnceLock<ICoreWebView2Controller>,
        captured: AtomicBool,
    }

    fn user_data_dir() -> String {
        let base = std::env::var("APPDATA")
            .unwrap_or_else(|_| std::env::temp_dir().display().to_string());
        let p = format!("{base}\\csqtt-desktop\\webview2");
        let _ = std::fs::create_dir_all(&p);
        p
    }

    fn extract_token(uri: &str) -> Option<String> {
        let i = uri.find("access_token=")? + "access_token=".len();
        let rest = &uri[i..];
        let end = rest.find(['&', '#']).unwrap_or(rest.len());
        let tok = &rest[..end];
        (!tok.is_empty()).then(|| tok.to_string())
    }

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        let state = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const State;
        match msg {
            WM_SIZE => {
                if !state.is_null() {
                    if let Some(ctrl) = unsafe { &*state }.controller.get() {
                        let mut rc = RECT::default();
                        if GetClientRect(hwnd, &mut rc).is_ok() {
                            let _ = ctrl.SetBounds(rc);
                        }
                    }
                }
                LRESULT(0)
            }
            WM_CLOSE => {
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    fn run(url: &str, tx: Sender<Result<String, String>>) -> Result<(), String> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

            let hinst = GetModuleHandleW(None).unwrap_or_default();
            let class = WNDCLASSW {
                lpfnWndProc: Some(wndproc),
                lpszClassName: w!("csqttVkLogin"),
                style: CS_HREDRAW | CS_VREDRAW,
                hInstance: hinst.into(),
                ..Default::default()
            };
            RegisterClassW(&class);

            let (sw, sh) = (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
            let (w, h) = (460, 660);
            let title = HSTRING::from("ВКонтакте — вход");
            let hwnd = CreateWindowExW(
                Default::default(),
                w!("csqttVkLogin"),
                &title,
                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                (sw - w) / 2,
                (sh - h) / 2,
                w,
                h,
                None,
                None,
                Some(hinst.into()),
                None,
            )
            .map_err(|_| "не удалось создать окно входа".to_string())?;

            let state: &'static State =
                Box::leak(Box::new(State { controller: OnceLock::new(), captured: AtomicBool::new(false) }));
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, state as *const State as isize);

            // Среда с отдельным профилем WebView2 (куки — сессия VK переживает перезапуск окна).
            let udf = HSTRING::from(user_data_dir());
            let (etx, erx) = channel();
            CreateCoreWebView2EnvironmentCompletedHandler::wait_for_async_operation(
                Box::new(move |handler| {
                    CreateCoreWebView2EnvironmentWithOptions(PCWSTR::null(), &udf, None, &handler)
                        .map_err(webview2_com::Error::WindowsError)
                }),
                Box::new(move |error_code, environment| {
                    error_code?;
                    let _ = etx.send(environment.ok_or_else(|| Error::from(E_POINTER)));
                    Ok(())
                }),
            )
            .map_err(|e| format!("WebView2 недоступен ({e}); установи WebView2 Runtime"))?;
            let env = erx
                .recv()
                .map_err(|_| "WebView2: сбой инициализации".to_string())?
                .map_err(|e| format!("WebView2: {e}"))?;

            let (ctx, crx) = channel();
            CreateCoreWebView2ControllerCompletedHandler::wait_for_async_operation(
                Box::new(move |handler| {
                    env.CreateCoreWebView2Controller(hwnd, &handler)
                        .map_err(webview2_com::Error::WindowsError)
                }),
                Box::new(move |error_code, controller| {
                    error_code?;
                    let _ = ctx.send(controller.ok_or_else(|| Error::from(E_POINTER)));
                    Ok(())
                }),
            )
            .map_err(|e| format!("WebView2 controller: {e}"))?;
            let controller = crx
                .recv()
                .map_err(|_| "WebView2: сбой контроллера".to_string())?
                .map_err(|e| format!("WebView2 controller: {e}"))?;

            let mut rc = RECT::default();
            let _ = GetClientRect(hwnd, &mut rc);
            let _ = controller.SetBounds(rc);
            let _ = controller.SetIsVisible(true);

            let webview = controller.CoreWebView2().map_err(|e| format!("WebView2: {e}"))?;
            if let Ok(settings) = webview.Settings() {
                let _ = settings.SetIsStatusBarEnabled(false);
                let _ = settings.SetAreDefaultContextMenusEnabled(false);
            }

            // Перехват редиректа: access_token приходит в URL (Uri — out-параметр PWSTR).
            let tx_nav = tx.clone();
            let nav = NavigationStartingEventHandler::create(Box::new(move |_sender, args| {
                if let Some(args) = args {
                    let mut uri = PWSTR::null();
                    if args.Uri(&mut uri).is_ok() {
                        if let Ok(uri) = uri.to_string() {
                            if let Some(tok) = extract_token(&uri) {
                                state.captured.store(true, Ordering::SeqCst);
                                let _ = tx_nav.send(Ok(tok));
                                let _ = DestroyWindow(hwnd);
                            } else if uri.contains("error=") {
                                state.captured.store(true, Ordering::SeqCst);
                                let _ = tx_nav.send(Err("VK вернул ошибку авторизации".to_string()));
                                let _ = DestroyWindow(hwnd);
                            }
                        }
                    }
                }
                Ok(())
            }));
            let mut token = 0i64;
            webview
                .add_NavigationStarting(&nav, &mut token)
                .map_err(|e| format!("WebView2: {e}"))?;

            // VK иногда открывает вход во всплывающем окне — держим всё в одном окне.
            let wv2 = webview.clone();
            let nw = NewWindowRequestedEventHandler::create(Box::new(move |_sender, args| {
                if let Some(args) = args {
                    let mut uri = PWSTR::null();
                    if args.Uri(&mut uri).is_ok() {
                        if let Ok(uri) = uri.to_string() {
                            let _ = wv2.Navigate(&HSTRING::from(uri));
                            let _ = args.SetHandled(true);
                        }
                    }
                }
                Ok(())
            }));
            let mut token2 = 0i64;
            let _ = webview.add_NewWindowRequested(&nw, &mut token2);

            let nav_url = HSTRING::from(url);
            let _ = webview.Navigate(&nav_url);

            let _ = state.controller.set(controller);
            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = UpdateWindow(hwnd);

            let mut msg = MSG::default();
            loop {
                match GetMessageW(&mut msg, None, 0, 0).0 {
                    0 | -1 => break,
                    _ => {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            }

            if !state.captured.load(Ordering::SeqCst) {
                let _ = tx.send(Err("Окно входа закрыто без авторизации".to_string()));
            }
            Ok(())
        }
    }

    pub fn start(url: String, tx: Sender<Result<String, String>>) {
        std::thread::spawn(move || {
            let _ = run(&url, tx);
        });
    }
}

#[cfg(windows)]
pub use imp::start;