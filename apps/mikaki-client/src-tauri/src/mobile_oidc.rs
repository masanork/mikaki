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

pub struct MobileAuthState {
    starting: AtomicBool,
    inner: Mutex<Inner>,
}

struct Inner {
    pending: Option<PendingLogin>,
    session: Option<StoredSession>,
    phase: &'static str,
    generation: u64,
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
    _access_token: Zeroizing<String>,
}

#[derive(Serialize)]
pub struct LoginResult {
    subject: String,
}

#[derive(Serialize)]
pub struct MobileStatus {
    phase: &'static str,
    subject: Option<String>,
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
            inner: Mutex::new(Inner {
                pending: None,
                session: None,
                phase: "idle",
                generation: 0,
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
    let inner = state.inner.lock().map_err(|_| "session unavailable")?;
    Ok(inner.session.as_ref().map(|session| LoginResult {
        subject: session.subject.clone(),
    }))
}

#[tauri::command]
pub fn mobile_auth_status(state: State<'_, MobileAuthState>) -> Result<MobileStatus, String> {
    let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
    if inner
        .pending
        .as_ref()
        .is_some_and(|pending| Instant::now() >= pending.expires_at)
    {
        inner.pending = None;
        inner.phase = "expired";
    }
    Ok(MobileStatus {
        phase: inner.phase,
        subject: inner
            .session
            .as_ref()
            .map(|session| session.subject.clone()),
    })
}

#[tauri::command]
pub fn cancel_native_login(state: State<'_, MobileAuthState>) -> Result<(), String> {
    let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
    inner.pending = None;
    inner.generation = inner.generation.wrapping_add(1);
    state.starting.store(false, Ordering::Release);
    inner.phase = if inner.session.is_some() {
        "complete"
    } else {
        "idle"
    };
    Ok(())
}

#[tauri::command]
pub fn clear_native_session(state: State<'_, MobileAuthState>) -> Result<(), String> {
    let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
    inner.session = None;
    inner.pending = None;
    inner.phase = "idle";
    inner.generation = inner.generation.wrapping_add(1);
    state.starting.store(false, Ordering::Release);
    Ok(())
}

#[tauri::command]
pub async fn start_mobile_login(
    app: tauri::AppHandle,
    state: State<'_, MobileAuthState>,
) -> Result<(), String> {
    start_mobile_authorization(app, state).await
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
        _access_token: Zeroizing::new(token.access_token().secret().clone()),
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
