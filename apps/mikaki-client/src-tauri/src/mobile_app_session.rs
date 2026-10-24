//! The remote page supplies lifecycle hints only. Native independently verifies
//! its HttpOnly SSO cookie with the fixed first-party server before opening any
//! local account inventory. No PRF output or bearer token crosses into the UI.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri_plugin_app_session::AppSessionExt;

struct SyncGuard<'a>(&'a AtomicBool);
impl Drop for SyncGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(super) async fn refresh(app: &tauri::AppHandle, state: &MobileAuthState) -> Result<(), String> {
    let generation = {
        let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
        expire_session(&mut inner);
        if !inner.app_session_allowed {
            return Ok(());
        }
        // External-browser compatibility sessions retain their own OIDC expiry.
        if inner.pending.is_some()
            || inner
                .session
                .as_ref()
                .is_some_and(|s| s._access_token.is_some())
        {
            return Ok(());
        }
        if inner
            .checked_at
            .is_some_and(|t| t.elapsed() < Duration::from_secs(10))
        {
            return Ok(());
        }
        inner.generation
    };
    if state
        .syncing
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(());
    }
    let _syncing = SyncGuard(&state.syncing);
    let mut status = app.app_session().status()?;
    let cookie = status.take_cookie();
    if !status.ready && status.error.is_none() {
        return Ok(());
    }
    let outcome = match (status.error.as_deref(), cookie) {
        (Some(error), _) => Err(error.to_owned()),
        (None, Some(cookie)) => projection(&cookie).await,
        _ => Err("authentication_required".into()),
    };
    let mut inner = state.inner.lock().map_err(|_| "session unavailable")?;
    if inner.generation != generation {
        return Ok(());
    }
    inner.checked_at = Some(Instant::now());
    match outcome {
        Ok(session) => {
            inner.session = Some(session);
            inner.phase = "complete";
            inner.login_deadline = None;
        }
        Err(error) => {
            inner.session = None;
            inner.phase = match error.as_str() {
                "authentication_required" => "idle",
                "secure_connection_failed" => "secure_connection_failed",
                "workspace_unavailable" => "workspace_unavailable",
                "configuration_required" => "configuration_required",
                _ => "connection_failed",
            };
        }
    }
    Ok(())
}

async fn projection(cookie: &str) -> Result<StoredSession, String> {
    if cookie.len() != 43
        || !cookie
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("authentication_required".into());
    }
    let mut response = http_client()?
        .post(format!("{ISSUER}/native/session"))
        .header("Origin", ISSUER)
        .header("X-Mikaki-App", "1")
        .header("Cookie", format!("__Host-op-sso={cookie}"))
        .send()
        .await
        .map_err(|_| "connection_failed")?;
    if response.status().as_u16() == 401 {
        return Err("authentication_required".into());
    }
    if response.status().as_u16() == 404 {
        return Err("configuration_required".into());
    }
    if !response.status().is_success() {
        return Err("connection_failed".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| "connection_failed")? {
        if bytes.len() + chunk.len() > 4096 {
            return Err("invalid_session".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "invalid_clock")?
        .as_secs();
    let (subject, ttl) =
        crate::app_projection::Projection::read(&bytes, now, env!("MIKAKI_MOBILE_CLIENT_ID"))?;
    Ok(StoredSession {
        subject,
        _access_token: None,
        valid_until: Instant::now() + Duration::from_secs(ttl),
    })
}
