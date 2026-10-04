//! Shared owner authentication, request guards and mutation identity.
//!
//! This module never reads or writes legacy attribute storage.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::{D1Database, Request, Response};

use crate::vault_authzen;
use crate::{browser_cookie, now_seconds};

#[derive(Deserialize)]
pub(crate) struct Owner {
    pub(crate) account_id: String,
    pub(crate) secret_hash: String,
    pub(crate) credential_id: String,
}

pub(crate) fn error(status: u16, code: &str) -> worker::Result<Response> {
    Response::builder()
        .with_status(status)
        .with_header("Cache-Control", "no-store")?
        .from_json(&serde_json::json!({ "error": code }))
}

pub(crate) async fn owner(request: &Request, db: &D1Database) -> worker::Result<Option<Owner>> {
    let Some(cookie) = browser_cookie(request, "__Host-op-sso")? else {
        return Ok(None);
    };
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(cookie.as_bytes()));
    db.prepare(
        "SELECT ss.account_id,sx.secret_hash,ss.credential_id FROM sso_context sx \
         JOIN sso_session ss ON ss.sso_id=sx.sso_id \
         JOIN account_security a ON a.account_id=ss.account_id \
         JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id \
         WHERE sx.secret_hash=?1 AND ss.revoked=0 AND ss.expires_at>?2 \
         AND a.active=1 AND a.epoch=ss.epoch AND c.active=1",
    )
    .bind(&[JsValue::from_str(&hash), JsValue::from_f64(now as f64)])?
    .first::<Owner>(None)
    .await
}

pub(crate) fn same_origin(request: &Request) -> worker::Result<bool> {
    let Some(origin) = request.headers().get("Origin")? else {
        return Ok(false);
    };
    Ok(origin == request.url()?.origin().ascii_serialization())
}

pub(crate) fn expected_revision(request: &Request) -> worker::Result<Option<i64>> {
    let none_match = request.headers().get("If-None-Match")?;
    let match_header = request.headers().get("If-Match")?;
    if none_match.is_some() && match_header.is_some() {
        return Ok(None);
    }
    if none_match.as_deref() == Some("*") {
        return Ok(Some(-1));
    }
    let Some(value) = match_header else {
        return Ok(None);
    };
    let Some(digits) = value.strip_prefix('"').and_then(|x| x.strip_suffix('"')) else {
        return Ok(None);
    };
    let Ok(revision) = digits.parse::<i64>() else {
        return Ok(None);
    };
    Ok((revision > 0 && revision < 9_007_199_254_740_991).then_some(revision))
}

pub(crate) fn operation_id(request: &Request) -> worker::Result<Option<String>> {
    let Some(id) = request.headers().get("X-Operation-ID")? else {
        return Ok(None);
    };
    if id.len() != 43
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Ok(None);
    }
    Ok(Some(id))
}

pub(crate) fn request_hash(method: &str, attribute: &str, expected: i64, body: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(method.as_bytes());
    hash.update([0]);
    hash.update(attribute.as_bytes());
    hash.update([0]);
    hash.update(expected.to_be_bytes());
    hash.update(body);
    URL_SAFE_NO_PAD.encode(hash.finalize())
}

pub(crate) fn owner_allowed(account: &str, attribute: &str, action: &str) -> bool {
    let evaluation = vault_authzen::owner_evaluation(account, action, account, attribute);
    vault_authzen::evaluate_owner(&evaluation, account, attribute).decision
}
