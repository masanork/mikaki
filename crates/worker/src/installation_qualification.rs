//! Local-only installation enrollment qualification. No production route,
//! token, durable app session, user-consent UI or recovery is provided here.
use crate::vault_http::{error, owner, same_origin};
use mikaki_oidc::{
    DpopTarget,
    installation_enrollment::{BoundInstallationProof, PendingInstallation},
    verify_dpop_proof_async,
};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{D1SessionConstraint, Env, Method, Request, Response, Result};

const CLIENT: &str = "dfd936fd-f33d-4f82-ae39-f25e08ec7948";
const CALLBACK: &str = "https://app.mikaki.org/oidc/native/callback";
const START: &str = "/native/installations/start";
const COMPLETE: &str = "/native/installations/complete";
const LIVE: &str = "EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
    JOIN account_security a ON a.account_id=ss.account_id \
    JOIN credential cr ON cr.account_id=ss.account_id AND cr.credential_id=ss.credential_id \
    JOIN client c ON c.client_id=?4 JOIN client_redirect_uri r ON r.client_id=c.client_id AND r.redirect_uri=?5 \
    WHERE sx.secret_hash=?1 AND ss.account_id=?2 AND ss.credential_id=?3 \
    AND ss.revoked=0 AND ss.expires_at>unixepoch() AND a.active=1 AND a.epoch=ss.epoch AND cr.active=1 \
    AND c.active=1 AND c.client_type='native' AND c.auth_method='none' AND c.sector_identifier='app.mikaki.org' AND r.active=1 \
    AND NOT EXISTS(SELECT 1 FROM dbsc_session ds WHERE ds.sso_id=ss.sso_id AND ds.cookie_expires_at<=unixepoch()))";

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}
fn number(value: u64) -> JsValue {
    JsValue::from_f64(value as f64)
}
fn json(value: &impl serde::Serialize) -> Result<Response> {
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(value)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    id: String,
}
#[derive(Deserialize)]
struct Pending {
    nonce: String,
    thumbprint: String,
    created_at: u64,
    expires_at: u64,
}
#[derive(Deserialize)]
struct Receipt {
    id: String,
    expires_at: u64,
}
#[derive(Deserialize)]
struct Id {
    id: String,
}

pub async fn fetch(mut request: Request, env: &Env) -> Result<Response> {
    let url = request.url()?;
    let issuer = env.var("MIKAKI_ISSUER")?.to_string();
    let Some(issuer) = crate::configured_issuer(&issuer) else {
        return error(503, "configuration_required");
    };
    if url.origin().ascii_serialization() != issuer
        || url.query().is_some()
        || request.method() != Method::Post
    {
        return error(404, "not_found");
    }
    let path = url.path();
    if !matches!(path, START | COMPLETE) {
        return error(404, "not_found");
    }
    if !same_origin(&request)?
        || request.headers().get("X-Mikaki-App")?.as_deref() != Some("1")
        || request.headers().get("Content-Type")?.as_deref() != Some("application/json")
    {
        return error(403, "origin_required");
    }
    let db = env.d1("DB")?;
    let Some(actor) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let Some(compact) = request.headers().get("DPoP")? else {
        return error(400, "invalid_proof");
    };
    let Some(now) = crate::now_seconds() else {
        return error(503, "clock_unavailable");
    };
    let endpoint = format!("{issuer}{path}");
    let Ok(proof) =
        verify_dpop_proof_async(&compact, "POST", &endpoint, DpopTarget::Token, now).await
    else {
        return error(400, "invalid_proof");
    };
    let bytes = request.bytes().await?;
    if bytes.len() > 1024 {
        return error(400, "invalid_request");
    }
    let principal = [
        text(&actor.secret_hash),
        text(&actor.account_id),
        text(&actor.credential_id),
        text(CLIENT),
        text(CALLBACK),
    ];
    let primary = db.with_session_constraint(D1SessionConstraint::FirstPrimary)?;
    if path == START {
        if serde_json::from_slice::<Empty>(&bytes).is_err() {
            return error(400, "invalid_request");
        }
        let id = crate::passkey_login::random_secret(&mut crate::WorkersCryptoRandom)?;
        let nonce = crate::passkey_login::random_secret(&mut crate::WorkersCryptoRandom)?;
        let mut values = principal.to_vec();
        values.extend([
            text(proof.thumbprint()),
            text(proof.jti_hash()),
            number(proof.retain_until()),
            number(proof.issued_at()),
            text(&id),
            text(&nonce),
        ]);
        let replay = format!(
            "INSERT INTO installation_proof_use(thumbprint,jti_hash,retain_until) \
          SELECT ?6,?7,?8 WHERE {LIVE} AND ?9<=unixepoch()+10 AND ?8>=unixepoch() \
          AND (SELECT count(*) FROM installation_proof_use)<10000 \
          AND (SELECT count(*) FROM installation_pending WHERE owner=?2 AND consumed=0 AND expires_at>unixepoch())<4 \
          ON CONFLICT(thumbprint,jti_hash) DO NOTHING"
        );
        let pending = "INSERT INTO installation_pending(id,owner,session_hash,credential_id,thumbprint,nonce,created_at,expires_at) \
          SELECT ?10,?2,?1,?3,?6,?11,unixepoch(),unixepoch()+120 WHERE changes()=1 RETURNING id,expires_at";
        let results = primary
            .batch(vec![
                primary.prepare(replay).bind(&values[..9])?,
                primary.prepare(pending).bind(&values)?,
            ])
            .await?;
        let Some(receipt) = results[1].results::<Receipt>()?.into_iter().next() else {
            return error(409, "enrollment_unavailable");
        };
        return json(
            &serde_json::json!({"id":receipt.id,"nonce":nonce,"expires_at":receipt.expires_at}),
        );
    }
    let Ok(input) = serde_json::from_slice::<Completion>(&bytes) else {
        return error(400, "invalid_request");
    };
    if input.id.len() != 43
        || !input
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return error(400, "invalid_request");
    }
    let pending = primary.prepare("SELECT nonce,thumbprint,created_at,expires_at FROM installation_pending WHERE id=?1 AND owner=?2 AND session_hash=?3 AND credential_id=?4 AND consumed=0 AND expires_at>unixepoch()")
        .bind(&[text(&input.id),text(&actor.account_id),text(&actor.secret_hash),text(&actor.credential_id)])?.first::<Pending>(None).await?;
    let Some(pending) = pending else {
        return error(409, "enrollment_unavailable");
    };
    let expected = PendingInstallation {
        endpoint: &endpoint,
        nonce: &pending.nonce,
        key_thumbprint: &pending.thumbprint,
        created_at: pending.created_at,
        expires_at: pending.expires_at,
    };
    let Some(bound) = BoundInstallationProof::bind(&expected, &proof, now) else {
        return error(400, "invalid_proof");
    };
    let mut values = principal.to_vec();
    values.extend([
        text(&input.id),
        text(bound.thumbprint()),
        text(&pending.nonce),
        text(bound.replay_id_hash()),
        number(bound.replay_retain_until()),
        number(proof.issued_at()),
    ]);
    let consume = format!(
        "UPDATE installation_pending SET consumed=1 WHERE id=?6 AND owner=?2 AND session_hash=?1 AND credential_id=?3 \
      AND thumbprint=?7 AND nonce=?8 AND created_at=?12 AND expires_at=?13 AND consumed=0 AND expires_at>unixepoch() \
      AND ?10>=unixepoch() AND ?11<=unixepoch()+10 AND {LIVE} \
      AND (SELECT count(*) FROM installation_device WHERE owner=?2 AND state='active')<8 AND (SELECT count(*) FROM installation_proof_use)<10000"
    );
    values.extend([number(pending.created_at), number(pending.expires_at)]);
    let replay = "INSERT INTO installation_proof_use(thumbprint,jti_hash,retain_until) SELECT ?7,?9,?10 WHERE changes()=1";
    let device = "INSERT INTO installation_device(id,owner,thumbprint,state,created_at) SELECT ?6,?2,?7,'active',unixepoch() WHERE changes()=1 RETURNING id";
    let results = primary
        .batch(vec![
            primary.prepare(consume).bind(&values)?,
            primary.prepare(replay).bind(&values[..10])?,
            primary.prepare(device).bind(&values[..7])?,
        ])
        .await?;
    let Some(receipt) = results[2].results::<Id>()?.into_iter().next() else {
        return error(409, "enrollment_unavailable");
    };
    json(&serde_json::json!({"id":receipt.id,"status":"active"}))
}
