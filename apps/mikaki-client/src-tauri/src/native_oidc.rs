#![cfg(not(any(target_os = "android", target_os = "ios")))]

use std::future::{poll_fn, Future};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Mutex,
};
use std::task::Poll;
use std::time::Duration;

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, RedirectUrl, TokenResponse,
};
use serde::Serialize;
use tauri::State;
use tauri_plugin_opener::OpenerExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;
use zeroize::Zeroizing;

const ISSUER: &str = "https://auth.mikaki.org";
const CALLBACK_PATH: &str = "/oidc/callback";
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(180);

pub struct NativeAuthState {
    busy: AtomicBool,
    session: Mutex<Option<StoredSession>>,
    generation: AtomicU64,
    cancelled: tokio::sync::Notify,
}

struct StoredSession {
    subject: String,
    // Kept in the Rust process for a later resource-specific grant. This
    // UserInfo token does not authorize owner Vault access.
    _access_token: Zeroizing<String>,
}

#[derive(Serialize)]
pub struct LoginResult {
    subject: String,
}

struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Default for NativeAuthState {
    fn default() -> Self {
        Self {
            busy: AtomicBool::new(false),
            session: Mutex::new(None),
            generation: AtomicU64::new(0),
            cancelled: tokio::sync::Notify::new(),
        }
    }
}

#[tauri::command]
pub fn native_platform() -> &'static str {
    "desktop"
}

#[tauri::command]
pub fn native_session(state: State<'_, NativeAuthState>) -> Result<Option<LoginResult>, String> {
    let session = state.session.lock().map_err(|_| "session unavailable")?;
    Ok(session.as_ref().map(|value| LoginResult {
        subject: value.subject.clone(),
    }))
}

#[tauri::command]
pub fn clear_native_session(state: State<'_, NativeAuthState>) -> Result<(), String> {
    invalidate(&state, true)
}

#[tauri::command]
pub fn cancel_native_login(state: State<'_, NativeAuthState>) -> Result<(), String> {
    invalidate(&state, false)
}

fn invalidate(state: &NativeAuthState, clear: bool) -> Result<(), String> {
    let mut session = state.session.lock().map_err(|_| "session unavailable")?;
    state.generation.fetch_add(1, Ordering::AcqRel);
    state.cancelled.notify_waiters();
    if clear {
        *session = None;
    }
    Ok(())
}

#[tauri::command]
pub async fn start_desktop_login(
    app: tauri::AppHandle,
    state: State<'_, NativeAuthState>,
) -> Result<LoginResult, String> {
    if state
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err("login already in progress".into());
    }
    let _busy = BusyGuard(&state.busy);
    let generation = state.generation.load(Ordering::Acquire);
    let mut cancelled = std::pin::pin!(state.cancelled.notified());
    cancelled.as_mut().enable();
    if state.generation.load(Ordering::Acquire) != generation {
        return Err("login cancelled".into());
    }
    let mut login = std::pin::pin!(perform_desktop_login(&app, &state, generation));
    poll_fn(|cx| {
        if cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err("login cancelled".into()));
        }
        login.as_mut().poll(cx)
    })
    .await
}

async fn perform_desktop_login(
    app: &tauri::AppHandle,
    state: &NativeAuthState,
    generation: u64,
) -> Result<LoginResult, String> {
    let client_id = option_env!("MIKAKI_DESKTOP_CLIENT_ID")
        .filter(|id| !id.is_empty())
        .ok_or("desktop client ID is not configured")?;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "loopback listener unavailable")?;
    let port = listener
        .local_addr()
        .map_err(|_| "loopback listener unavailable")?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}{CALLBACK_PATH}");

    let http = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "OIDC HTTP client unavailable")?;
    let provider = CoreProviderMetadata::discover_async(
        IssuerUrl::new(ISSUER.to_owned()).map_err(|_| "invalid configured issuer")?,
        &http,
    )
    .await
    .map_err(|_| "OIDC discovery failed")?;
    let client =
        CoreClient::from_provider_metadata(provider, ClientId::new(client_id.into()), None)
            .set_redirect_uri(
                RedirectUrl::new(redirect_uri.clone()).map_err(|_| "invalid callback")?,
            );
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorization_url, state_value, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge)
        .url();
    app.opener()
        .open_url(authorization_url.as_str(), None::<&str>)
        .map_err(|_| "could not open the system browser")?;

    let code = tokio::time::timeout(
        CALLBACK_TIMEOUT,
        await_callback(&listener, port, state_value.secret()),
    )
    .await
    .map_err(|_| "login timed out")??;
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| "token endpoint unavailable")?
        .set_pkce_verifier(verifier)
        .request_async(&http)
        .await
        .map_err(|_| "token exchange failed")?;
    let id_token = token.id_token().ok_or("ID Token missing")?;
    let verifier = client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &nonce)
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
    commit_session(
        state,
        generation,
        StoredSession {
            subject: claims.subject().as_str().to_owned(),
            _access_token: Zeroizing::new(token.access_token().secret().clone()),
        },
    )
}

fn commit_session(
    state: &NativeAuthState,
    generation: u64,
    stored: StoredSession,
) -> Result<LoginResult, String> {
    let mut session = state.session.lock().map_err(|_| "session unavailable")?;
    if state.generation.load(Ordering::Acquire) != generation {
        return Err("login cancelled".into());
    }
    let result = LoginResult {
        subject: stored.subject.clone(),
    };
    *session = Some(stored);
    Ok(result)
}

async fn await_callback(listener: &TcpListener, port: u16, state: &str) -> Result<String, String> {
    loop {
        let (mut stream, peer) = listener.accept().await.map_err(|_| "callback failed")?;
        if !peer.ip().is_loopback() {
            continue;
        }
        match read_callback(&mut stream, port, state).await {
            Ok(Some(code)) => {
                respond(&mut stream, 200, "Login received. Return to Mikaki.").await;
                return Ok(code);
            }
            Ok(None) => {
                respond(&mut stream, 200, "Login cancelled. Return to Mikaki.").await;
                return Err("authorization was cancelled or denied".into());
            }
            Err(_) => respond(&mut stream, 400, "Invalid login response.").await,
        }
    }
}

async fn read_callback(
    stream: &mut TcpStream,
    port: u16,
    state: &str,
) -> Result<Option<String>, String> {
    let mut request = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0u8; 1024];
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .map_err(|_| "callback read timed out")?
            .map_err(|_| "callback read failed")?;
        if read == 0 || request.len() + read > 8192 {
            return Err("invalid callback length".into());
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let request = std::str::from_utf8(&request).map_err(|_| "invalid callback encoding")?;
    parse_callback(request, port, state)
}

fn parse_callback(request: &str, port: u16, state: &str) -> Result<Option<String>, String> {
    let mut lines = request.split("\r\n");
    let mut request_line = lines.next().ok_or("missing request line")?.split(' ');
    if request_line.next() != Some("GET") {
        return Err("invalid callback method".into());
    }
    let target = request_line.next().ok_or("missing callback target")?;
    if request_line.next() != Some("HTTP/1.1") || request_line.next().is_some() {
        return Err("invalid callback protocol".into());
    }
    if !target.starts_with(CALLBACK_PATH) || !target.starts_with('/') || target.starts_with("//") {
        return Err("invalid callback path".into());
    }
    let expected_host = format!("127.0.0.1:{port}");
    let hosts: Vec<_> = lines
        .filter_map(|line| {
            line.strip_prefix("Host: ")
                .or_else(|| line.strip_prefix("host: "))
        })
        .collect();
    if hosts.as_slice() != [expected_host.as_str()] {
        return Err("invalid callback host".into());
    }
    let url = Url::parse(&format!("http://{expected_host}{target}"))
        .map_err(|_| "invalid callback URL")?;
    if url.path() != CALLBACK_PATH || url.fragment().is_some() {
        return Err("invalid callback path".into());
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
        return Err("ambiguous authorization response".into());
    }
    if error.is_some() {
        return Ok(None);
    }
    code.filter(|value| value.len() == 43)
        .map(Some)
        .ok_or_else(|| "authorization code missing".into())
}

async fn respond(stream: &mut TcpStream, status: u16, message: &str) {
    let reason = if status == 200 { "OK" } else { "Bad Request" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{message}",
        message.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn cancellation_and_logout_reject_late_session_commits() {
        let state = NativeAuthState::default();
        let stored = || StoredSession {
            subject: "synthetic-user".into(),
            _access_token: Zeroizing::new("synthetic-token".into()),
        };
        commit_session(&state, 0, stored()).unwrap();
        invalidate(&state, false).unwrap();
        assert!(state.session.lock().unwrap().is_some());
        assert!(commit_session(&state, 0, stored()).is_err());
        commit_session(&state, 1, stored()).unwrap();
        invalidate(&state, true).unwrap();
        assert!(state.session.lock().unwrap().is_none());
        assert!(commit_session(&state, 1, stored()).is_err());
    }

    #[test]
    fn cancellation_wakes_the_pending_desktop_operation() {
        let state = NativeAuthState::default();
        let mut cancelled = std::pin::pin!(state.cancelled.notified());
        cancelled.as_mut().enable();
        invalidate(&state, false).unwrap();
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        assert!(cancelled.as_mut().poll(&mut context).is_ready());
    }

    fn request(query: &str, host: &str) -> String {
        format!("GET /oidc/callback?{query} HTTP/1.1\r\nHost: {host}\r\n\r\n")
    }

    #[test]
    fn callback_binds_state_issuer_host_path_and_single_code() {
        let query = format!("code={CODE}&state=expected&iss=https%3A%2F%2Fauth.mikaki.org");
        assert_eq!(
            parse_callback(&request(&query, "127.0.0.1:43210"), 43210, "expected"),
            Ok(Some(CODE.to_owned()))
        );
        assert_eq!(
            parse_callback(
                &request(
                    "error=access_denied&state=expected&iss=https%3A%2F%2Fauth.mikaki.org",
                    "127.0.0.1:43210"
                ),
                43210,
                "expected"
            ),
            Ok(None)
        );
        for invalid in [
            request(&query, "127.0.0.1:43211"),
            request(&query.replace("expected", "wrong"), "127.0.0.1:43210"),
            request(
                &query.replace("auth.mikaki.org", "attacker.example"),
                "127.0.0.1:43210",
            ),
            request(&format!("{query}&state=expected"), "127.0.0.1:43210"),
            request(&format!("{query}&code={CODE}"), "127.0.0.1:43210"),
            format!("GET /other?{query} HTTP/1.1\r\nHost: 127.0.0.1:43210\r\n\r\n"),
        ] {
            assert!(parse_callback(&invalid, 43210, "expected").is_err());
        }
    }
}
