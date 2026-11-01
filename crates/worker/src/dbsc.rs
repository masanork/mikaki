//! W3C Device Bound Session Credentials (DBSC) protocol endpoints and state management.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_oidc::{verify_dbsc_refresh_async, verify_dbsc_registration_async};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::d1::D1Database;

use crate::{browser_cookie, now_seconds};

const DBSC_SHORT_LIVED_COOKIE_TTL_SECONDS: u64 = 300; // 5 minutes

#[derive(Deserialize)]
struct DbscSessionRow {
    #[allow(dead_code)]
    session_id: String,
    sso_id: String,
    public_key_sec1: Vec<u8>,
}

#[derive(Serialize)]
struct ChallengeResponse {
    challenge: String,
}

#[derive(Serialize)]
struct RegistrationScope {
    include_site: bool,
}

#[derive(Serialize)]
struct RegistrationCredential {
    #[serde(rename = "type")]
    type_: &'static str,
    name: &'static str,
    attributes: &'static str,
}

#[derive(Serialize)]
struct SessionInstructions {
    session_identifier: String,
    refresh_url: &'static str,
    scope: RegistrationScope,
    credentials: Vec<RegistrationCredential>,
}

fn hash_secret(value: &str) -> String {
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    B64.encode(h.finalize())
}

fn current_time() -> worker::Result<u64> {
    now_seconds().ok_or_else(|| worker::Error::RustError("clock_error".into()))
}

fn random_string() -> worker::Result<String> {
    use crate::WorkersCryptoRandom;
    use mikaki_oidc::CryptographicRandom;
    let mut bytes = [0u8; 32];
    WorkersCryptoRandom
        .fill(&mut bytes)
        .map_err(|_| worker::Error::RustError("crypto_error".into()))?;
    Ok(B64.encode(bytes))
}

pub(crate) async fn create_challenge(db: &D1Database, session_id: Option<&str>) -> worker::Result<String> {
    let challenge = random_string()?;
    let now = current_time()?;
    let expires_at = now + 120; // 2 minutes validity

    // Clean up expired challenges and insert new one
    db.batch(vec![
        db.prepare("DELETE FROM dbsc_challenge WHERE expires_at <= ?1")
            .bind(&[JsValue::from_f64(now as f64)])?,
        db.prepare("INSERT INTO dbsc_challenge(challenge, session_id, expires_at) VALUES(?1, ?2, ?3)")
            .bind(&[
                JsValue::from_str(&challenge),
                session_id.map(JsValue::from_str).unwrap_or(JsValue::NULL),
                JsValue::from_f64(expires_at as f64),
            ])?,
    ]).await?;

    Ok(challenge)
}

async fn consume_challenge(db: &D1Database, challenge: &str) -> worker::Result<bool> {
    let now = current_time()?;
    let result = db.prepare(
        "DELETE FROM dbsc_challenge WHERE challenge = ?1 AND expires_at > ?2",
    )
    .bind(&[JsValue::from_str(challenge), JsValue::from_f64(now as f64)])?
    .run()
    .await?;

    Ok(result.meta()?.is_some_and(|m| m.changes == Some(1)))
}

/// Endpoint to request a new DBSC challenge: GET /dbsc/challenge
pub(crate) async fn challenge_endpoint(
    _request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let db = context.env.d1("DB")?;
    let challenge = create_challenge(&db, None).await?;

    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Content-Type", "application/json")?
        .from_json(&ChallengeResponse { challenge })
}

/// Endpoint for DBSC session registration: POST /dbsc/register
pub(crate) async fn register(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let db = context.env.d1("DB")?;
    let now = current_time()?;

    // Verify existing SSO session from cookie
    let Some(sso_secret) = browser_cookie(&request, "__Host-op-sso")? else {
        return crate::vault_http::error(401, "unauthorized");
    };
    let sso_hash = hash_secret(&sso_secret);

    let sso_row = db.prepare(
        "SELECT s.sso_id FROM sso_context c JOIN sso_session s ON s.sso_id = c.sso_id \
         WHERE c.secret_hash = ?1 AND s.expires_at > ?2",
    )
    .bind(&[JsValue::from_str(&sso_hash), JsValue::from_f64(now as f64)])?
    .first::<String>(Some("sso_id"))
    .await?;

    let Some(sso_id) = sso_row else {
        return crate::vault_http::error(401, "invalid_session");
    };

    // Get Sec-Session-Response header (or fallback to body)
    let jwt = if let Some(h) = request.headers().get("Sec-Session-Response")? {
        h
    } else {
        request.text().await?
    };

    if jwt.is_empty() {
        return crate::vault_http::error(400, "missing_session_response");
    }

    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return crate::vault_http::error(400, "malformed_jwt");
    }

    #[derive(Deserialize)]
    struct TempClaims {
        jti: String,
    }

    let payload_bytes = B64.decode(parts[1]).map_err(|_| worker::Error::RustError("bad_b64".into()))?;
    let claims: TempClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| worker::Error::RustError("bad_json".into()))?;

    if !consume_challenge(&db, &claims.jti).await? {
        return crate::vault_http::error(400, "invalid_or_expired_challenge");
    }

    let verified = verify_dbsc_registration_async(&jwt, &claims.jti, now)
        .await
        .map_err(|_| worker::Error::RustError("verification_failed".into()))?;

    let session_id = random_string()?;
    let cookie_expires_at = now + DBSC_SHORT_LIVED_COOKIE_TTL_SECONDS;

    db.prepare(
        "INSERT INTO dbsc_session(session_id, sso_id, public_key_sec1, public_key_jwk, created_at, last_refreshed_at, cookie_expires_at) \
         VALUES(?1, ?2, ?3, ?4, ?5, ?5, ?6)",
    )
    .bind(&[
        JsValue::from_str(&session_id),
        JsValue::from_str(&sso_id),
        JsValue::from(js_sys::Uint8Array::from(verified.sec1_public_key.as_slice())),
        JsValue::from_str(&verified.public_key_jwk),
        JsValue::from_f64(now as f64),
        JsValue::from_f64(cookie_expires_at as f64),
    ])?
    .run()
    .await?;

    let instructions = SessionInstructions {
        session_identifier: session_id,
        refresh_url: "/dbsc/refresh",
        scope: RegistrationScope {
            include_site: true,
        },
        credentials: vec![RegistrationCredential {
            type_: "cookie",
            name: "__Host-op-sso",
            attributes: "Path=/; Secure; HttpOnly; SameSite=Lax",
        }],
    };

    // Return 200 OK with session instructions and refreshed short-lived SSO cookie
    worker::Response::builder()
        .with_header(
            "Set-Cookie",
            &format!(
                "__Host-op-sso={sso_secret}; Max-Age={DBSC_SHORT_LIVED_COOKIE_TTL_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Lax"
            ),
        )?
        .with_header("Cache-Control", "no-store")?
        .from_json(&instructions)
}

/// Endpoint for DBSC session refresh: POST /dbsc/refresh
pub(crate) async fn refresh(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let db = context.env.d1("DB")?;
    let now = current_time()?;

    let jwt = if let Some(h) = request.headers().get("Sec-Session-Response")? {
        h
    } else {
        request.text().await?
    };

    if jwt.is_empty() {
        return crate::vault_http::error(400, "missing_session_response");
    }

    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return crate::vault_http::error(400, "malformed_jwt");
    }

    #[derive(Deserialize)]
    struct RefreshClaims {
        jti: String,
        #[serde(default)]
        sub: Option<String>,
    }

    let payload_bytes = B64.decode(parts[1]).map_err(|_| worker::Error::RustError("bad_b64".into()))?;
    let claims: RefreshClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|_| worker::Error::RustError("bad_json".into()))?;

    let session_id = claims.sub
        .or(request.headers().get("Sec-Session-Id")?.filter(|s| !s.is_empty()))
        .unwrap_or_default();

    if session_id.is_empty() {
        return crate::vault_http::error(400, "missing_session_id");
    }

    if !consume_challenge(&db, &claims.jti).await? {
        let fresh_challenge = create_challenge(&db, Some(&session_id)).await?;
        return Ok(worker::Response::builder()
            .with_status(401)
            .with_header("Cache-Control", "no-store")?
            .with_header("Sec-Session-Challenge", &format!("challenge=\"{fresh_challenge}\"; id=\"{session_id}\""))?
            .empty());
    }

    let session_row = db.prepare(
        "SELECT session_id, sso_id, public_key_sec1 FROM dbsc_session WHERE session_id = ?1",
    )
    .bind(&[JsValue::from_str(&session_id)])?
    .first::<DbscSessionRow>(None)
    .await?;

    let Some(session) = session_row else {
        return crate::vault_http::error(401, "unknown_dbsc_session");
    };

    // Verify parent SSO session is still active
    let sso_active = db.prepare(
        "SELECT 1 AS valid FROM sso_context c JOIN sso_session s ON s.sso_id = c.sso_id \
         WHERE s.sso_id = ?1 AND s.expires_at > ?2",
    )
    .bind(&[JsValue::from_str(&session.sso_id), JsValue::from_f64(now as f64)])?
    .first::<i32>(Some("valid"))
    .await?
    .is_some();

    if !sso_active {
        return crate::vault_http::error(401, "parent_session_expired");
    }

    // Verify DBSC proof against stored public key
    let _ = verify_dbsc_refresh_async(&jwt, &claims.jti, &session.public_key_sec1, now)
        .await
        .map_err(|_| worker::Error::RustError("verification_failed".into()))?;

    // Update last_refreshed_at and extend server-side short-lived expiry
    let cookie_expires_at = now + DBSC_SHORT_LIVED_COOKIE_TTL_SECONDS;
    db.prepare("UPDATE dbsc_session SET last_refreshed_at = ?1, cookie_expires_at = ?2 WHERE session_id = ?3")
        .bind(&[
            JsValue::from_f64(now as f64),
            JsValue::from_f64(cookie_expires_at as f64),
            JsValue::from_str(&session_id),
        ])?
        .run()
        .await?;

    // Reissue / rotate SSO secret bound to verified parent session, ensuring valid Cookie is always returned
    let new_sso_secret = random_string()?;
    let new_sso_hash = hash_secret(&new_sso_secret);

    db.prepare("UPDATE sso_context SET secret_hash = ?1 WHERE sso_id = ?2")
        .bind(&[JsValue::from_str(&new_sso_hash), JsValue::from_str(&session.sso_id)])?
        .run()
        .await?;

    let fresh_challenge = create_challenge(&db, Some(&session_id)).await?;

    Ok(worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Sec-Session-Challenge", &format!("challenge=\"{fresh_challenge}\"; id=\"{session_id}\""))?
        .with_header(
            "Set-Cookie",
            &format!(
                "__Host-op-sso={new_sso_secret}; Max-Age={DBSC_SHORT_LIVED_COOKIE_TTL_SECONDS}; Path=/; Secure; HttpOnly; SameSite=Lax"
            ),
        )?
        .empty())
}
