use serde::Deserialize;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tauri::{webview::PageLoadEvent, Manager, Url, WebviewWindow, WebviewWindowBuilder};

const WALLET_PATH: &str = "/native/wallet";
#[derive(Clone, Default)]
pub struct NavigationState(Arc<AtomicU64>);

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    Signin,
    Vault,
}
impl Destination {
    fn url(self) -> Url {
        #[cfg(debug_assertions)]
        if let Some(origin) = developer_origin() {
            return origin
                .join(match self {
                    Self::Signin => "/signin",
                    Self::Vault => "/vault",
                })
                .expect("fixed developer path");
        }
        Url::parse(match self {
            Self::Signin => "https://auth.mikaki.org/signin",
            Self::Vault => "https://auth.mikaki.org/vault",
        })
        .expect("fixed Web URL")
    }
}

#[derive(Debug, PartialEq)]
enum Navigation {
    Web,
    Local,
    Wallet,
    Blocked,
}
fn classify(url: &Url) -> Navigation {
    if !url.username().is_empty() || url.password().is_some() {
        return Navigation::Blocked;
    }
    #[cfg(debug_assertions)]
    if developer_origin().is_some_and(|origin| origin.origin() == url.origin()) {
        return Navigation::Web;
    }

    if !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
        return Navigation::Blocked;
    }
    if local_origin(url) && matches!(url.path(), "/" | "/index.html") {
        return Navigation::Local;
    }
    if url.scheme() != "https"
        || !matches!(
            url.host_str(),
            Some("auth.mikaki.org" | "app.mikaki.org" | "mikaki.org" | "docs.mikaki.org")
        )
    {
        return Navigation::Blocked;
    }
    if url.host_str() == Some("auth.mikaki.org") && url.path() == WALLET_PATH {
        return if url.query().is_none() && url.fragment().is_none() {
            Navigation::Wallet
        } else {
            Navigation::Blocked
        };
    }
    Navigation::Web
}
fn local_origin(url: &Url) -> bool {
    #[cfg(any(target_os = "android", target_os = "windows"))]
    {
        url.scheme() == "http" && url.host_str() == Some("tauri.localhost")
    }
    #[cfg(not(any(target_os = "android", target_os = "windows")))]
    {
        url.scheme() == "tauri" && url.host_str() == Some("localhost")
    }
}
fn local_url(screen: &str) -> Url {
    #[cfg(any(target_os = "android", target_os = "windows"))]
    let base = "http://tauri.localhost/index.html";
    #[cfg(not(any(target_os = "android", target_os = "windows")))]
    let base = "tauri://localhost/index.html";
    let mut url = Url::parse(base).expect("fixed local URL");
    url.set_fragment(Some(screen));
    url
}

#[cfg(debug_assertions)]
fn developer_origin() -> Option<Url> {
    let url = Url::parse(option_env!("MIKAKI_WEBVIEW_DEV_ORIGIN")?).ok()?;
    (url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

pub fn create(app: &tauri::App) -> tauri::Result<()> {
    #[allow(unused_mut)]
    let mut config = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == "main")
        .expect("main window config")
        .clone();
    #[cfg(debug_assertions)]
    if let Some(origin) = developer_origin() {
        config.url =
            tauri::WebviewUrl::External(origin.join("/vault").expect("fixed developer path"));
    }
    let handle = app.handle().clone();
    let window = WebviewWindowBuilder::from_config(app, &config)?
        // Cosmetic feature detection only. Remote origins receive no IPC capability.
        .initialization_script("Object.defineProperty(window,'__MIKAKI_NATIVE__',{value:true});")
        .on_navigation(move |url| match classify(url) {
            Navigation::Web => {
                if let Some(window) = handle.get_webview_window("main") {
                    expect_navigation(&window);
                }
                true
            }
            Navigation::Local => {
                if let Some(window) = handle.get_webview_window("main") {
                    window
                        .state::<NavigationState>()
                        .0
                        .fetch_add(1, Ordering::AcqRel);
                }
                true
            }
            Navigation::Wallet => {
                let app = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = show_wallet(&app);
                });
                false
            }
            Navigation::Blocked => false,
        })
        .on_page_load(|window, payload| {
            let state = window.state::<NavigationState>().0.clone();
            if matches!(payload.event(), PageLoadEvent::Finished)
                && window.url().ok().as_ref() == Some(payload.url())
            {
                state.fetch_add(1, Ordering::AcqRel);
            }
        })
        .build()?;
    // A TLS failure can happen before WebKit emits any page-load callback.
    let state = window.state::<NavigationState>().0.clone();
    if state
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        arm_timeout(window, state, 1);
    }
    Ok(())
}

fn expect_navigation(window: &WebviewWindow) {
    let state = window.state::<NavigationState>().0.clone();
    let epoch = state.fetch_add(1, Ordering::AcqRel) + 1;
    arm_timeout(window.clone(), state, epoch);
}
fn arm_timeout(window: WebviewWindow, state: Arc<AtomicU64>, epoch: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(20));
        if state
            .compare_exchange(epoch, epoch + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let _ = window.navigate(local_url("connection"));
        }
    });
}

pub fn show_wallet(app: &tauri::AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window("main") {
        window
            .state::<NavigationState>()
            .0
            .fetch_add(1, Ordering::AcqRel);
        window.navigate(local_url("wallet"))?;
    }
    Ok(())
}

/// Only the trusted local Wallet UI can call this command; remote Web pages
/// have no capability and cannot invoke any Wallet signing/credential command.
#[tauri::command]
pub fn open_mikaki_web(window: WebviewWindow, destination: Destination) -> Result<(), String> {
    expect_navigation(&window);
    window
        .navigate(destination.url())
        .map_err(|_| "webview unavailable".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn navigation_pins_origins_and_wallet_switch_has_no_authority_payload() {
        for value in ["https://auth.mikaki.org/vault", "https://docs.mikaki.org/"] {
            assert_eq!(classify(&Url::parse(value).unwrap()), Navigation::Web);
        }
        assert_eq!(
            classify(&Url::parse("https://auth.mikaki.org/native/wallet").unwrap()),
            Navigation::Wallet
        );
        for value in [
            "http://auth.mikaki.org/",
            "https://auth.mikaki.org.evil.example/",
            "https://user@auth.mikaki.org/",
            "https://auth.mikaki.org:444/",
            "https://auth.mikaki.org/native/wallet?sign=data",
            "https://auth.mikaki.org/native/wallet#sign",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ] {
            assert_eq!(
                classify(&Url::parse(value).unwrap()),
                Navigation::Blocked,
                "{value}"
            );
        }
        assert_eq!(classify(&local_url("wallet")), Navigation::Local);
        assert_eq!(classify(&local_url("connection")), Navigation::Local);
    }
}
