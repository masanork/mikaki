//! The context accepted in a Passkey login, reused only by matching SSO requests.
use super::*;
use wasm_bindgen::JsValue;

pub(super) fn scope(value: &str) -> &str {
    match value {
        "profile openid" => "openid profile",
        _ => value,
    }
}

// Append after the transaction is consumed and app_connection is activated,
// inside the SAME guarded batch as Passkey verification and SSO creation.
#[allow(clippy::too_many_arguments)]
pub(super) fn record(
    db: &worker::d1::D1Database,
    login: &LoginTransactionRow,
    issuer: &str,
    tx: &str,
    browser_hash: &str,
    account: &str,
    guard: &str,
) -> worker::Result<Vec<worker::D1PreparedStatement>> {
    if login.owner_login != 0 || login.client_id == "mikaki-internal-enrollment" {
        return Ok(vec![]);
    }
    let url = url::Url::parse(&login.authorization_url)
        .map_err(|_| worker::Error::RustError("invalid_continuation".into()))?;
    let parameters = url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    let redirect = parameters
        .get("redirect_uri")
        .ok_or_else(|| worker::Error::RustError("invalid_continuation".into()))?;
    let requested_scope = login
        .requested_scope
        .as_deref()
        .ok_or_else(|| worker::Error::RustError("invalid_continuation".into()))?;
    if url.origin().ascii_serialization() != issuer
        || url.path() != "/authorize"
        || parameters.get("client_id").map(|value| value.as_ref()) != Some(login.client_id.as_str())
        || !matches!(
            requested_scope,
            "openid" | "openid profile" | "profile openid"
        )
    {
        return Err(worker::Error::RustError("invalid_continuation".into()));
    }
    // The native loopback port is ephemeral; bind its exact registered template.
    let template = loopback_redirect_template(redirect);
    let redirect = template.as_deref().unwrap_or(redirect);
    Ok(vec![
        db.prepare(include_str!("../sql/record-login-review.sql")).bind(&[
            JsValue::from_str(redirect),
            JsValue::from_str(scope(requested_scope)),
            JsValue::from_str(account),
            JsValue::from_str(&login.client_id),
            JsValue::from_str(tx),
            JsValue::from_str(browser_hash),
        ])?,
        db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)")
            .bind(&[JsValue::from_str(guard)])?,
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
            .bind(&[JsValue::from_str(guard)])?,
    ])
}
