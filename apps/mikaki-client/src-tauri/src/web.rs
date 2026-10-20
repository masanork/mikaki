use serde::Deserialize;
use std::sync::{Arc, Mutex};
use tauri::{webview::PageLoadEvent, Manager, Url, WebviewWindow, WebviewWindowBuilder};

const WALLET_PATH: &str = "/native/wallet";
#[derive(Clone, Default)]
pub struct NavigationState(Arc<Mutex<NavigationProgress>>);

#[derive(Default)]
struct NavigationProgress {
    epoch: u64,
    pending: Option<Url>,
}

impl NavigationState {
    fn begin(&self, url: &Url) -> u64 {
        let mut progress = self.0.lock().unwrap();
        progress.epoch += 1;
        progress.pending = Some(url.clone());
        progress.epoch
    }

    fn cancel(&self) {
        self.0.lock().unwrap().pending = None;
    }

    fn finish(&self, url: &Url) {
        let mut progress = self.0.lock().unwrap();
        if progress.pending.as_ref() == Some(url) {
            progress.pending = None;
        }
    }

    fn pending_epoch(&self) -> Option<u64> {
        let progress = self.0.lock().unwrap();
        progress.pending.as_ref().map(|_| progress.epoch)
    }

    fn expire(&self, epoch: u64) -> bool {
        let mut progress = self.0.lock().unwrap();
        if progress.epoch == epoch && progress.pending.is_some() {
            progress.pending = None;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    Signin,
    Vault,
    Chat,
}
impl Destination {
    fn url(self) -> Url {
        #[cfg(debug_assertions)]
        if let Some(origin) = developer_origin() {
            return origin
                .join(match self {
                    Self::Signin => "/signin",
                    Self::Vault => "/vault",
                    Self::Chat => "/vault#chat",
                })
                .expect("fixed developer path");
        }
        Url::parse(match self {
            Self::Signin => "https://auth.mikaki.org/signin",
            Self::Vault => "https://auth.mikaki.org/vault",
            Self::Chat => "https://auth.mikaki.org/vault#chat",
        })
        .expect("fixed Web URL")
    }
}

#[derive(Debug, PartialEq)]
enum Navigation {
    Web,
    Local,
    Wallet,
    Presentation,
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
    if matches!(url.scheme(), "openid4vp" | "mdoc-openid4vp")
        && url.as_str().len() <= 4096
        && url.host_str().is_none()
        && url.path().is_empty()
        && url.fragment().is_none()
    {
        return Navigation::Presentation;
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
    let state = app.state::<NavigationState>().inner().clone();
    if let tauri::WebviewUrl::External(url) = &config.url {
        state.begin(url);
    }
    let navigation_state = state.clone();
    let completion_state = state.clone();
    let handle = app.handle().clone();
    let window = WebviewWindowBuilder::from_config(app, &config)?
        // Cosmetic feature detection only. Remote origins receive no IPC capability.
        .initialization_script("Object.defineProperty(window,'__MIKAKI_NATIVE__',{value:true});")
        .on_navigation(move |url| match classify(url) {
            Navigation::Web => {
                let epoch = navigation_state.begin(url);
                if let Some(window) = handle.get_webview_window("main") {
                    arm_timeout(window, navigation_state.clone(), epoch);
                }
                true
            }
            Navigation::Local => {
                navigation_state.cancel();
                true
            }
            Navigation::Wallet => {
                let app = handle.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = show_wallet(&app);
                });
                false
            }
            Navigation::Presentation => {
                // Navigation conveys a request only. The native parser pins the
                // verifier/retrieval URI and presentation still requires consent.
                let app = handle.clone();
                let uri = url.clone();
                tauri::async_runtime::spawn(async move {
                    crate::identity_issuance::invocation::receive(&app, &uri);
                });
                false
            }
            Navigation::Blocked => false,
        })
        .on_page_load(move |_window, payload| {
            // Android delivers this callback on its UI thread. Querying window.url()
            // here waits for that same thread and Wry's late response can panic.
            if matches!(payload.event(), PageLoadEvent::Finished) {
                completion_state.finish(payload.url());
            }
        })
        .build()?;
    // A TLS failure can happen before WebKit emits any page-load callback.
    if let Some(epoch) = state.pending_epoch() {
        arm_timeout(window, state, epoch);
    }
    Ok(())
}

fn expect_navigation(window: &WebviewWindow, url: &Url) {
    let state = window.state::<NavigationState>().inner().clone();
    let epoch = state.begin(url);
    arm_timeout(window.clone(), state, epoch);
}
fn arm_timeout(window: WebviewWindow, state: NavigationState, epoch: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(20));
        if state.expire(epoch) {
            let _ = window.navigate(local_url("connection"));
        }
    });
}

pub fn show_wallet(app: &tauri::AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window("main") {
        window.state::<NavigationState>().cancel();
        window.navigate(local_url("wallet"))?;
    }
    Ok(())
}

/// Only the trusted local Wallet UI can call this command; remote Web pages
/// have no capability and cannot invoke any Wallet signing/credential command.
#[tauri::command]
pub fn open_mikaki_web(window: WebviewWindow, destination: Destination) -> Result<(), String> {
    let url = destination.url();
    expect_navigation(&window, &url);
    window
        .navigate(url)
        .map_err(|_| "webview unavailable".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_page_completion_does_not_cancel_redirect_timeout() {
        let state = NavigationState::default();
        let vault = Url::parse("https://auth.mikaki.org/vault").unwrap();
        let signin = Url::parse("https://auth.mikaki.org/signin").unwrap();
        let initial = state.begin(&vault);
        let redirect = state.begin(&signin);
        state.finish(&vault);
        assert!(!state.expire(initial));
        assert_eq!(state.pending_epoch(), Some(redirect));
        assert!(state.expire(redirect));
        assert!(!state.expire(redirect));
    }

    #[test]
    fn completed_pages_and_local_wallet_cancel_connection_fallback() {
        let state = NavigationState::default();
        let url = Url::parse("https://auth.mikaki.org/vault").unwrap();
        let finished = state.begin(&url);
        state.finish(&url);
        assert!(!state.expire(finished));
        let cancelled = state.begin(&url);
        state.cancel();
        assert!(!state.expire(cancelled));
        assert_eq!(state.pending_epoch(), None);
        let retry = state.begin(&url);
        assert!(!state.expire(cancelled));
        assert!(state.expire(retry));
    }

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
        for scheme in ["openid4vp", "mdoc-openid4vp"] {
            let value = format!(
                "{scheme}:?client_id=verifier&request_uri=https%3A%2F%2Fverifier.example%2Frequest"
            );
            assert_eq!(
                classify(&Url::parse(&value).unwrap()),
                Navigation::Presentation
            );
        }
        for value in [
            "openid4vp://evil.example/",
            "openid4vp:?client_id=v#payload",
        ] {
            assert_eq!(classify(&Url::parse(value).unwrap()), Navigation::Blocked);
        }
        assert_eq!(classify(&local_url("wallet")), Navigation::Local);
        assert_eq!(classify(&local_url("connection")), Navigation::Local);
    }
}
