//! Add a discoverable credential to the authenticated account, without a new account.
use super::*;
use crate::vault_http::{error, owner, same_origin};
use wasm_bindgen::JsValue;

#[derive(Deserialize, Serialize)]
struct CredentialId {
    credential_id: String,
}

#[derive(Deserialize)]
struct RegistrationRow {
    challenge: String,
    user_handle: String,
    expires_at: u64,
    failures: u32,
    consumed: i64,
    credential_id: Option<String>,
    request_hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Finish {
    transaction_id: String,
    response: mikaki_webauthn::Registration,
}

pub async fn list(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let ids = db.prepare("SELECT c.credential_id FROM credential c JOIN passkey_credential p ON p.credential_id=c.credential_id WHERE c.account_id=?1 AND c.active=1 ORDER BY c.credential_id LIMIT 10")
        .bind(&[JsValue::from_str(&owner.account_id)])?.all().await?.results::<CredentialId>()?;
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&ids)
}

pub async fn start(
    request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let mut random = WorkersCryptoRandom;
    let tx = passkey_login::random_secret(&mut random)?;
    let challenge = passkey_login::random_secret(&mut random)?;
    // Five-minute fresh authentication and a bounded number of outstanding attempts.
    db.prepare("DELETE FROM owner_passkey_registration WHERE expires_at<?1")
        .bind(&[JsValue::from_f64(now.saturating_sub(86400) as f64)])?
        .run()
        .await?;
    db.prepare("INSERT INTO owner_passkey_registration(transaction_id,account_id,session_hash,challenge,user_handle,expires_at) \
      SELECT ?1,ss.account_id,sx.secret_hash,?2,p.user_handle,?3 FROM sso_context sx \
      JOIN sso_session ss ON ss.sso_id=sx.sso_id JOIN account_security a ON a.account_id=ss.account_id \
      JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id \
      JOIN passkey_credential p ON p.credential_id=c.credential_id \
      WHERE sx.secret_hash=?4 AND ss.account_id=?5 AND sx.auth_time>?6-300 AND ss.expires_at>?6 AND ss.revoked=0 \
      AND a.active=1 AND a.epoch=ss.epoch AND c.active=1 \
      AND (SELECT count(*) FROM credential WHERE account_id=ss.account_id AND active=1)<10 \
      AND (SELECT count(*) FROM owner_passkey_registration WHERE account_id=ss.account_id AND consumed=0 AND expires_at>?6)<5")
      .bind(&[JsValue::from_str(&tx),JsValue::from_str(&challenge),JsValue::from_f64((now+300) as f64),JsValue::from_str(&owner.secret_hash),JsValue::from_str(&owner.account_id),JsValue::from_f64(now as f64)])?.run().await?;
    let row = db.prepare("SELECT challenge,user_handle,expires_at,failures,consumed,credential_id,request_hash FROM owner_passkey_registration WHERE transaction_id=?1")
      .bind(&[JsValue::from_str(&tx)])?.first::<RegistrationRow>(None).await?;
    let Some(row) = row else {
        return error(403, "fresh_login_or_capacity_required");
    };
    let issuer = enrollment::issuer(&context)?;
    let excluded = db.prepare("SELECT credential_id FROM credential WHERE account_id=?1 ORDER BY credential_id LIMIT 10")
      .bind(&[JsValue::from_str(&owner.account_id)])?.all().await?.results::<CredentialId>()?;
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&serde_json::json!({
            "transaction_id":tx,"challenge":row.challenge,"user_handle":row.user_handle,
            "rp_id":enrollment::rp_id(&issuer)?,"exclude_credentials":excluded
        }))
}

pub async fn finish(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    if !same_origin(&request)? {
        return error(403, "origin_required");
    }
    if request.headers().get("Content-Type")?.as_deref() != Some("application/json") {
        return error(415, "json_required");
    }
    let db = context.env.d1("DB")?;
    let Some(owner) = owner(&request, &db).await? else {
        return error(401, "authentication_required");
    };
    let body = match read_bounded_body(&mut request, 64 * 1024).await {
        Ok(value) => value,
        Err(_) => return error(413, "invalid_body"),
    };
    if mikaki_webauthn::strict_json(&body, 64 * 1024, 16).is_err() {
        return error(400, "invalid_body");
    }
    let Ok(input) = serde_json::from_str::<Finish>(&body) else {
        return error(400, "invalid_body");
    };
    if !passkey_login::valid_tx(&input.transaction_id) {
        return error(400, "invalid_transaction");
    }
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let hash = passkey_login::hash(&body);
    let row = db.prepare("SELECT challenge,user_handle,expires_at,failures,consumed,credential_id,request_hash FROM owner_passkey_registration WHERE transaction_id=?1 AND account_id=?2 AND session_hash=?3 AND expires_at>?4 AND failures<5")
      .bind(&[JsValue::from_str(&input.transaction_id),JsValue::from_str(&owner.account_id),JsValue::from_str(&owner.secret_hash),JsValue::from_f64(now as f64)])?.first::<RegistrationRow>(None).await?;
    let Some(row) = row else {
        return error(400, "invalid_transaction");
    };
    // A retry must still verify the same registration response before acknowledgement.
    let issuer = enrollment::issuer(&context)?;
    let context = mikaki_webauthn::Context {
        challenge: row.challenge,
        origin: issuer.clone(),
        rp_id: enrollment::rp_id(&issuer)?,
        max_bytes: 64 * 1024,
        max_depth: 16,
        user_verification: Default::default(),
        authentication: Default::default(),
        algorithms: vec![-7],
        attestation: None,
        attestation_policy: Default::default(),
    };
    let proof = mikaki_auth::Ceremony {
        purpose: "register".into(),
        browser_hash: owner.secret_hash.clone(),
        expires_at: row.expires_at,
        failures: row.failures,
        consumed: false,
        context,
    }
    .register(&owner.secret_hash, now, 5, input.response);
    let proof = match proof {
        Ok(proof) if proof.user_verified() => proof,
        _ => {
            db.prepare("UPDATE owner_passkey_registration SET failures=failures+1 WHERE transaction_id=?1 AND consumed=0 AND failures<5")
              .bind(&[JsValue::from_str(&input.transaction_id)])?.run().await?;
            return error(401, "invalid_registration");
        }
    };
    if row.consumed != 0 {
        return if row.credential_id.as_deref() == Some(proof.id())
            && row.request_hash.as_deref() == Some(&hash)
        {
            result(proof.id())
        } else {
            error(409, "transaction_reused")
        };
    }
    let guard = format!("owner-passkey-{}", input.transaction_id);
    let statements = vec![
      db.prepare("UPDATE owner_passkey_registration SET consumed=1,credential_id=?1,request_hash=?6 WHERE transaction_id=?2 AND consumed=0 AND failures<5 AND expires_at>?3 \
        AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id JOIN account_security a ON a.account_id=ss.account_id JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id \
        WHERE sx.secret_hash=?4 AND ss.account_id=?5 AND sx.auth_time>?3-300 AND ss.revoked=0 AND ss.expires_at>?3 AND a.active=1 AND a.epoch=ss.epoch AND c.active=1) \
        AND (SELECT count(*) FROM credential WHERE account_id=?5 AND active=1)<10")
        .bind(&[JsValue::from_str(proof.id()),JsValue::from_str(&input.transaction_id),JsValue::from_f64(now as f64),JsValue::from_str(&owner.secret_hash),JsValue::from_str(&owner.account_id),JsValue::from_str(&hash)])?,
      db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[JsValue::from_str(&guard)])?,
      db.prepare("INSERT INTO credential VALUES(?1,?2,1)").bind(&[JsValue::from_str(proof.id()),JsValue::from_str(&owner.account_id)])?,
      db.prepare("INSERT INTO passkey_credential(credential_id,public_key,user_handle,counter,backup_eligible,backup_state,revision) VALUES(?1,?2,?3,?4,?5,?6,1)")
        .bind(&[JsValue::from_str(proof.id()),JsValue::from_str(proof.public_key()),JsValue::from_str(&row.user_handle),JsValue::from_f64(proof.counter() as f64),JsValue::from_f64(f64::from(proof.backup_eligible())),JsValue::from_f64(f64::from(proof.backup_state()))])?,
      db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1").bind(&[JsValue::from_str(&guard)])?,
    ];
    if db.batch(statements).await.is_err() {
        return error(409, "registration_conflict");
    }
    result(proof.id())
}

fn result(id: &str) -> worker::Result<worker::Response> {
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&serde_json::json!({"credential_id":id}))
}
