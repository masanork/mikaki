//! First-party app account projection, not an OAuth grant or a Vault key bridge.
//! Only the registered mobile sector is addressable; no token is minted here.
use super::*;
use crate::vault_http::{error, owner, same_origin};
use wasm_bindgen::JsValue;

const CLIENT: &str = "dfd936fd-f33d-4f82-ae39-f25e08ec7948";
const SECTOR: &str = "app.mikaki.org";
const CALLBACK: &str = "https://app.mikaki.org/oidc/native/callback";

#[derive(Deserialize, Serialize)]
struct Projection {
    subject: String,
    expires_at: u64,
}

pub async fn session(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let url = request.url()?;
    if url.origin().ascii_serialization() != enrollment::issuer(&context)? {
        return error(404, "not_found");
    }
    if url.query().is_some() {
        return error(400, "invalid_request");
    }
    if !same_origin(&request)? || request.headers().get("X-Mikaki-App")?.as_deref() != Some("1") {
        return error(403, "origin_required");
    }
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let candidate = passkey_login::random_secret(&mut WorkersCryptoRandom)?;
    // Preserve the exact pairwise subject used by the external-browser OIDC
    // client. Recheck live authority inside both statements to cover revocation
    // between the initial cookie check and the projection.
    let authority = "FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
        JOIN account_security a ON a.account_id=ss.account_id \
        JOIN credential cr ON cr.account_id=ss.account_id AND cr.credential_id=ss.credential_id \
        JOIN client c ON c.client_id=?3 \
        JOIN client_redirect_uri r ON r.client_id=c.client_id AND r.redirect_uri=?4 AND r.active=1 \
        WHERE sx.secret_hash=?1 AND ss.account_id=?2 AND ss.revoked=0 AND ss.expires_at>?5 \
        AND a.active=1 AND a.epoch=ss.epoch AND cr.active=1 AND c.active=1 \
        AND c.client_type='native' AND c.auth_method='none' AND c.sector_identifier=?6";
    let values = [
        JsValue::from_str(&owner.secret_hash),
        JsValue::from_str(&owner.account_id),
        JsValue::from_str(CLIENT),
        JsValue::from_str(CALLBACK),
        JsValue::from_f64(now as f64),
        JsValue::from_str(SECTOR),
        JsValue::from_str(&candidate),
    ];
    db.prepare(&format!("INSERT INTO pairwise_subject(account_id,sector_identifier,sub) SELECT ss.account_id,c.sector_identifier,?7 {authority} ON CONFLICT(account_id,sector_identifier) DO NOTHING"))
        .bind(&values)?.run().await?;
    let projection = db.prepare(&format!("SELECT (SELECT sub FROM pairwise_subject WHERE account_id=ss.account_id AND sector_identifier=c.sector_identifier) AS subject,ss.expires_at {authority}"))
        .bind(&values[..6])?.first::<Projection>(None).await?;
    let Some(projection) = projection else {
        return error(401, "authentication_required");
    };
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .from_json(&serde_json::json!({
            "subject":projection.subject,"expires_at":projection.expires_at,"client_id":CLIENT
        }))
}
