#![cfg(any(target_os = "android", target_os = "ios"))]

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, TokenResponse,
};
use serde::Serialize;
use tauri::{Manager, State};
use tauri_plugin_opener::OpenerExt;
use url::Url;
use zeroize::Zeroizing;

const ISSUER: &str = "https://auth.mikaki.org";
const CALLBACK: &str = "https://app.mikaki.org/oidc/native/callback";
const LOGIN_LIFETIME: Duration = Duration::from_secs(180);
#[cfg(target_os = "android")]
#[path = "mobile_app_session.rs"]
mod app_session;

pub struct MobileAuthState {
    starting: AtomicBool,
    #[cfg(target_os = "android")]
    syncing: AtomicBool,
    inner: Mutex<Inner>,
}

struct Inner {
    pending: Option<PendingLogin>,
    session: Option<StoredSession>,
    phase: &'static str,
    generation: u64,
    #[cfg(target_os = "android")]
    checked_at: Option<Instant>,
    #[cfg(target_os = "android")]
    login_deadline: Option<Instant>,
    #[cfg(target_os = "android")]
    app_session_allowed: bool,
}

struct PendingLogin {
    state: Zeroizing<String>,
    nonce: Nonce,
    verifier: Zeroizing<String>,
    expires_at: Instant,
    generation: u64,
}

struct StoredSession {
    subject: String,
    // UserInfo token only. It is never returned to the local WebView.
    _access_token: Option<Zeroizing<String>>,
    valid_until: Instant,
}

#[derive(Serialize)]
pub struct LoginResult {
    pub(crate) subject: String,
}

#[derive(Serialize)]
pub struct MobileStatus {
    phase: &'static str,
    subject: Option<String>,
    shared_session: bool,
}

struct StartingGuard<'a> {
    state: &'a MobileAuthState,
    generation: u64,
}

impl Drop for StartingGuard<'_> {
    fn drop(&mut self) {
        if let Ok(inner) = self.state.inner.lock() {
            if inner.generation == self.generation {
                self.state.starting.store(false, Ordering::Release);
            }
        }
    }
}

impl Default for MobileAuthState {
    fn default() -> Self {
        Self {
            starting: AtomicBool::new(false),
            #[cfg(target_os = "android")]
            syncing: AtomicBool::new(false),
            inner: Mutex::new(Inner {
                pending: None,
                session: None,
                phase: "idle",
                generation: 0,
                #[cfg(target_os = "android")]
                checked_at: None,
                #[cfg(target_os = "android")]
                login_deadline: None,
                #[cfg(target_os = "android")]
                app_session_allowed: false,
            }),
        }
    }
}

#[tauri::command]
pub fn native_platform() -> &'static str {
    "mobile"
}

#[tauri::command]
pub fn native_session(state: State<'_, MobileAuthState>) -> Result<Option<LoginResult>, String> {
    let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
    expire_session(&mut inner);
    Ok(inner.session.as_ref().map(|session| LoginResult {
        subject: session.subject.clone(),
    }))
}

#[tauri::command]
pub async fn mobile_auth_status(
    app: tauri::AppHandle,
    state: State<'_, MobileAuthState>,
) -> Result<MobileStatus, String> {
    #[cfg(target_os = "android")]
    app_session::refresh(&app, &state).await?;
    #[cfg(not(target_os = "android"))]
    let _ = app;
    let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
    expire_session(&mut inner);
    if inner
        .pending
        .as_ref()
        .is_some_and(|pending| Instant::now() >= pending.expires_at)
    {
        inner.pending = None;
        inner.phase = "expired";
    }
    Ok(MobileStatus {
        shared_session: cfg!(target_os = "android"),
        phase: inner.phase,
        subject: inner
            .session
            .as_ref()
            .map(|session| session.subject.clone()),
    })
}

fn expire_session(inner: &mut Inner) {
    #[cfg(target_os = "android")]
    if inner
        .login_deadline
        .is_some_and(|deadline| Instant::now() >= deadline)
    {
        inner.login_deadline = None;
        inner.app_session_allowed = false;
        inner.generation = inner.generation.wrapping_add(1);
        if inner.phase == "pending" {
            inner.phase = "expired";
        }
    }
    if inner
        .session
        .as_ref()
        .is_some_and(|s| Instant::now() >= s.valid_until)
    {
        inner.session = None;
        inner.phase = "expired";
    }
}

#[tauri::command]
pub async fn cancel_native_login(
    app: tauri::AppHandle,
    state: State<'_, MobileAuthState>,
) -> Result<(), String> {
    let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
    inner.pending = None;
    inner.generation = inner.generation.wrapping_add(1);
    state.starting.store(false, Ordering::Release);
    inner.phase = if inner.session.is_some() {
        "complete"
    } else {
        "idle"
    };
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_app_session::AppSessionExt;
        inner.login_deadline = None;
        inner.app_session_allowed = false;
        drop(inner);
        app.app_session().reset()?;
    }
    #[cfg(not(target_os = "android"))]
    let _ = app;
    Ok(())
}

#[tauri::command]
pub async fn clear_native_session(
    app: tauri::AppHandle,
    state: State<'_, MobileAuthState>,
) -> Result<(), String> {
    crate::identity_reader::cancel_active_read(&app)?;
    crate::identity_issuance::clear_passport_session(&app);
    let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
    inner.session = None;
    inner.pending = None;
    inner.phase = "idle";
    inner.generation = inner.generation.wrapping_add(1);
    state.starting.store(false, Ordering::Release);
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_app_session::AppSessionExt;
        inner.checked_at = None;
        inner.login_deadline = None;
        inner.app_session_allowed = false;
        drop(inner);
        app.app_session().clear()?;
    }
    Ok(())
}

#[tauri::command]
pub async fn start_mobile_login(
    app: tauri::AppHandle,
    state: State<'_, MobileAuthState>,
) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_app_session::AppSessionExt;
        {
            let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
            inner.generation = inner.generation.wrapping_add(1);
            inner.session = None;
            inner.checked_at = None;
            inner.phase = "pending";
            inner.login_deadline = Some(Instant::now() + LOGIN_LIFETIME);
            inner.app_session_allowed = true;
        }
        app.app_session().reset()?;
        return Ok(());
    }
    #[cfg(not(target_os = "android"))]
    start_mobile_authorization(app, state).await
}

/// Compatibility path; normal Android sign-in uses the first-party app session.
#[tauri::command]
pub async fn start_mobile_browser_login(
    app: tauri::AppHandle,
    state: State<'_, MobileAuthState>,
) -> Result<(), String> {
    start_mobile_authorization(app, state).await
}

#[tauri::command]
pub async fn set_app_workspace(
    app: tauri::AppHandle,
    visible: bool,
    page: String,
    top: f64,
    bottom: f64,
    viewport_width: f64,
) -> Result<(), String> {
    if !matches!(page.as_str(), "chat" | "account") {
        return Err("invalid_workspace".into());
    }
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_app_session::{AppSessionExt, WorkspaceRequest};
        app.app_session().workspace(WorkspaceRequest {
            visible,
            page,
            top,
            bottom,
            viewport_width,
        })
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (app, visible, page, top, bottom, viewport_width);
        Err("workspace_unavailable".into())
    }
}

async fn start_mobile_authorization(
    app: tauri::AppHandle,
    state: State<'_, MobileAuthState>,
) -> Result<(), String> {
    let generation = {
        let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
        if inner
            .pending
            .as_ref()
            .is_some_and(|pending| Instant::now() < pending.expires_at)
            || inner.phase == "exchanging"
        {
            return Err("login already in progress".into());
        }
        if state
            .starting
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("login already starting".into());
        }
        inner.generation = inner.generation.wrapping_add(1);
        inner.generation
    };
    let _starting = StartingGuard {
        state: &state,
        generation,
    };
    let client_id = option_env!("MIKAKI_MOBILE_CLIENT_ID")
        .filter(|id| !id.is_empty())
        .ok_or("mobile client ID is not configured")?;
    let http = http_client()?;
    let provider = CoreProviderMetadata::discover_async(
        IssuerUrl::new(ISSUER.to_owned()).map_err(|_| "invalid configured issuer")?,
        &http,
    )
    .await
    .map_err(|_| "OIDC discovery failed")?;
    let client =
        CoreClient::from_provider_metadata(provider, ClientId::new(client_id.into()), None)
            .set_redirect_uri(RedirectUrl::new(CALLBACK.into()).map_err(|_| "invalid callback")?);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut authorization = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge);
    // Installed-device qualification can request fresh OP authentication using
    // the standard OIDC parameter. Normal builds retain browser SSO behavior.
    if option_env!("MIKAKI_MOBILE_LOGIN_PROMPT") == Some("login") {
        authorization = authorization.add_extra_param("prompt", "login");
    }
    let (authorization_url, state_value, nonce) = authorization.url();
    {
        let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
        if inner.generation != generation {
            return Err("login cancelled".into());
        }
        inner.session = None;
        inner.pending = Some(PendingLogin {
            state: Zeroizing::new(state_value.secret().clone()),
            nonce,
            verifier: Zeroizing::new(verifier.secret().clone()),
            expires_at: Instant::now() + LOGIN_LIFETIME,
            generation,
        });
        inner.phase = "pending";
    }
    if app
        .opener()
        .open_url(authorization_url.as_str(), None::<&str>)
        .is_err()
    {
        let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
        if inner.generation == generation {
            inner.pending = None;
            inner.phase = "failed";
        }
        return Err("could not open the system browser".into());
    }
    Ok(())
}

pub async fn handle_open_url(app: tauri::AppHandle, url: Url) {
    let state = app.state::<MobileAuthState>();
    let (pending, code) = {
        let mut inner = match state.inner.lock() {
            Ok(value) => value,
            Err(_) => return,
        };
        let Some(pending) = inner.pending.as_ref() else {
            return;
        };
        if Instant::now() >= pending.expires_at {
            inner.pending = None;
            inner.phase = "expired";
            return;
        }
        let Ok(code) = parse_callback(&url, &pending.state) else {
            return;
        };
        let pending = inner.pending.take().expect("pending checked");
        inner.phase = if code.is_some() {
            "exchanging"
        } else {
            "denied"
        };
        (pending, code)
    };
    let Some(code) = code else { return };
    let generation = pending.generation;
    let outcome = exchange_code(code, pending).await;
    let mut inner = match state.inner.lock() {
        Ok(value) => value,
        Err(_) => return,
    };
    if inner.generation != generation {
        return;
    }
    match outcome {
        Ok(session) => {
            inner.session = Some(session);
            inner.phase = "complete";
        }
        Err(_) => inner.phase = "failed",
    }
}

fn parse_callback(url: &Url, state: &str) -> Result<Option<String>, String> {
    if url.as_str().split('?').next() != Some(CALLBACK) || url.fragment().is_some() {
        return Err("unexpected callback".into());
    }
    let mut code = None;
    let mut returned_state = None;
    let mut issuer = None;
    let mut error = None;
    for (key, value) in url.query_pairs() {
        let slot = match key.as_ref() {
            "code" => &mut code,
            "state" => &mut returned_state,
            "iss" => &mut issuer,
            "error" => &mut error,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err("duplicate callback parameter".into());
        }
    }
    if returned_state.as_deref() != Some(state) || issuer.as_deref() != Some(ISSUER) {
        return Err("callback state or issuer mismatch".into());
    }
    if error.is_some() && code.is_some() {
        return Err("ambiguous callback".into());
    }
    if error.is_some() {
        return Ok(None);
    }
    code.filter(|value| value.len() == 43)
        .map(Some)
        .ok_or_else(|| "authorization code missing".into())
}

async fn exchange_code(code: String, pending: PendingLogin) -> Result<StoredSession, String> {
    let client_id = option_env!("MIKAKI_MOBILE_CLIENT_ID")
        .filter(|id| !id.is_empty())
        .ok_or("mobile client ID is not configured")?;
    let http = http_client()?;
    let provider = CoreProviderMetadata::discover_async(
        IssuerUrl::new(ISSUER.to_owned()).map_err(|_| "invalid configured issuer")?,
        &http,
    )
    .await
    .map_err(|_| "OIDC discovery failed")?;
    let client =
        CoreClient::from_provider_metadata(provider, ClientId::new(client_id.into()), None)
            .set_redirect_uri(RedirectUrl::new(CALLBACK.into()).map_err(|_| "invalid callback")?);
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| "token endpoint unavailable")?
        .set_pkce_verifier(PkceCodeVerifier::new((*pending.verifier).clone()))
        .request_async(&http)
        .await
        .map_err(|_| "token exchange failed")?;
    let id_token = token.id_token().ok_or("ID Token missing")?;
    let verifier = client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &pending.nonce)
        .map_err(|_| "ID Token validation failed")?;
    if let Some(expected) = claims.access_token_hash() {
        let actual = AccessTokenHash::from_token(
            token.access_token(),
            id_token
                .signing_alg()
                .map_err(|_| "invalid ID Token algorithm")?,
            id_token
                .signing_key(&verifier)
                .map_err(|_| "invalid ID Token key")?,
        )
        .map_err(|_| "access token hash could not be checked")?;
        if actual != *expected {
            return Err("access token hash mismatch".into());
        }
    }
    Ok(StoredSession {
        subject: claims.subject().as_str().to_owned(),
        _access_token: Some(Zeroizing::new(token.access_token().secret().clone())),
        valid_until: Instant::now()
            + token
                .expires_in()
                .unwrap_or(Duration::from_secs(300))
                .min(Duration::from_secs(3600)),
    })
}

fn http_client() -> Result<openidconnect::reqwest::Client, String> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "OIDC HTTP client unavailable".into())
}

#[cfg(test)]
mod tests {
    use super::parse_callback;
    use url::Url;

    const CODE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn app_link_is_exact_and_transaction_bound() {
        let valid = Url::parse(&format!(
            "https://app.mikaki.org/oidc/native/callback?code={CODE}&state=expected&iss=https%3A%2F%2Fauth.mikaki.org"
        ))
        .unwrap();
        assert_eq!(parse_callback(&valid, "expected"), Ok(Some(CODE.into())));
        for uri in [
            valid.as_str().replace("state=expected", "state=other"),
            valid
                .as_str()
                .replace("app.mikaki.org/oidc", "evil.example/oidc"),
            valid
                .as_str()
                .replace("/oidc/native/callback", "/oidc/native/other"),
            format!("{}&iss=https%3A%2F%2Fauth.mikaki.org", valid),
        ] {
            assert!(parse_callback(&Url::parse(&uri).unwrap(), "expected").is_err());
        }
    }
}
