//! Dedicated document intake and OID4VCI issuer. Ordinary OP/Vault tokens have no authority here.
mod attester;
mod claims;
mod wallet;
pub(crate) use attester::{challenge as attester_challenge, redeem as attester_redeem};
pub(crate) use claims::{CLAIM, enabled as claims_enabled, release_post, userinfo};
pub(crate) use wallet::{authorize_get, authorize_post, par};

use crate::{
    WorkersCryptoRandom, configured_issuer, now_seconds, read_bounded_body,
    vault_attributes::{error, owner},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mikaki_identity::{
    evidence::{Evidence, TrustedKey, VerifiedDocument, verify},
    issuance::{self, PublicJwk},
    mdoc,
};
use mikaki_oidc::CryptographicRandom;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::{Request, Response, RouteContext};
use zeroize::Zeroizing;

fn server_error() -> worker::Error {
    worker::Error::RustError("identity_unavailable".into())
}
fn now() -> worker::Result<u64> {
    now_seconds().ok_or_else(server_error)
}
fn random() -> worker::Result<String> {
    let mut bytes = [0; 32];
    WorkersCryptoRandom
        .fill(&mut bytes)
        .map_err(|_| server_error())?;
    Ok(B64.encode(bytes))
}
fn hash(s: &str) -> String {
    B64.encode(Sha256::digest(s.as_bytes()))
}
fn js(s: &str) -> JsValue {
    JsValue::from_str(s)
}
fn valid_id(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
fn response(value: Value) -> worker::Result<Response> {
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .from_json(&value)
}
fn issuer(ctx: &RouteContext<()>) -> worker::Result<String> {
    let root =
        configured_issuer(&ctx.env.var("MIKAKI_ISSUER")?.to_string()).ok_or_else(server_error)?;
    Ok(format!("{root}/identity/issuer"))
}
fn enabled(ctx: &RouteContext<()>) -> bool {
    ctx.env
        .var("IDENTITY_ENABLED")
        .is_ok_and(|v| v.to_string() == "true")
}
fn policy(ctx: &RouteContext<()>) -> worker::Result<(Vec<TrustedKey>, String)> {
    if !enabled(ctx) {
        return Err(server_error());
    }
    trust_policy(&ctx.env)
}
fn trust_policy(env: &worker::Env) -> worker::Result<(Vec<TrustedKey>, String)> {
    let raw = Zeroizing::new(env.secret("IDENTITY_TRUSTED_KEYS")?.to_string());
    let keys: Vec<TrustedKey> = serde_json::from_str(&raw).map_err(|_| server_error())?;
    let mut ids = std::collections::HashSet::new();
    if keys.is_empty()
        || keys.len() > 16
        || !keys
            .iter()
            .all(|k| !k.id.is_empty() && k.id.len() <= 128 && ids.insert(&k.id))
    {
        return Err(server_error());
    }
    Ok((keys, hash(&raw)))
}
fn signing(ctx: &RouteContext<()>) -> worker::Result<(p256_key::Key, String)> {
    let raw = Zeroizing::new(ctx.env.secret("IDENTITY_ISSUER_JWK")?.to_string());
    issuance::issuer_key(&raw).map_err(|_| server_error())
}
fn encryption_key(
    ctx: &RouteContext<()>,
) -> worker::Result<Option<mikaki_identity::issuance_encryption::RequestKey>> {
    let Ok(raw) = ctx.env.secret("IDENTITY_CREDENTIAL_ENCRYPTION_JWK") else {
        return Ok(None);
    };
    let raw = Zeroizing::new(raw.to_string());
    let key = mikaki_identity::issuance_encryption::RequestKey::parse(&raw)
        .map_err(|_| server_error())?;
    if key.public().public().map_err(|_| server_error())?
        == PublicJwk::from_key(signing(ctx)?.0.verifying_key())
    {
        return Err(server_error());
    }
    Ok(Some(key))
}
// The shared library owns the key type; this alias keeps a second crypto implementation out.
mod p256_key {
    pub type Key = mikaki_identity::issuance::IssuerSigningKey;
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialCertificates {
    sd_jwt: Option<mikaki_identity::credential_certificate::SigningTrust>,
    mdoc: Option<mikaki_identity::credential_certificate::SigningTrust>,
}
fn credential_trust(
    ctx: &RouteContext<()>,
    purpose: mikaki_identity::credential_certificate::Purpose,
) -> worker::Result<Option<mikaki_identity::credential_certificate::SigningTrust>> {
    use mikaki_identity::credential_certificate::Purpose;
    let raw = ctx
        .env
        .var("IDENTITY_CREDENTIAL_CERTIFICATES")
        .ok()
        .map(|v| v.to_string());
    let configured = if let Some(raw) = raw {
        if raw.len() > 65536 {
            return Err(server_error());
        }
        let config: CredentialCertificates =
            serde_json::from_str(&raw).map_err(|_| server_error())?;
        match purpose {
            Purpose::SdJwt => config.sd_jwt,
            Purpose::Mdoc => config.mdoc,
        }
    } else {
        None
    };
    if configured.is_none() && purpose == Purpose::SdJwt && wallet::haip(ctx) {
        return Err(server_error());
    }
    if let Some(trust) = &configured {
        let (key, _) = signing(ctx)?;
        mikaki_identity::credential_certificate::verify(
            trust,
            &PublicJwk::from_key(key.verifying_key()),
            purpose,
            now()?,
        )
        .map_err(|_| server_error())?;
    }
    Ok(configured)
}
fn mdoc_certificate(ctx: &RouteContext<()>) -> worker::Result<Option<Vec<u8>>> {
    use mikaki_identity::credential_certificate::{Purpose, verify};
    if let Some(trust) = credential_trust(ctx, Purpose::Mdoc)? {
        let (key, _) = signing(ctx)?;
        let (chain, _) = verify(
            &trust,
            &PublicJwk::from_key(key.verifying_key()),
            Purpose::Mdoc,
            now()?,
        )
        .map_err(|_| server_error())?;
        if ctx.env.var("IDENTITY_MDOC_CERT_DER").is_ok() {
            return Err(server_error());
        }
        return Ok(Some(chain[0].clone()));
    }
    if wallet::haip(ctx) {
        return Ok(None);
    }

    let Ok(raw) = ctx.env.var("IDENTITY_MDOC_CERT_DER") else {
        return Ok(None);
    };
    let raw = raw.to_string();
    if raw.len() > 5500 {
        return Err(server_error());
    }
    let cert = B64.decode(raw).map_err(|_| server_error())?;
    let (key, _) = signing(ctx)?;
    mdoc::validate_certificate(&cert, &PublicJwk::from_key(key.verifying_key()), now()?)
        .map_err(|_| server_error())?;
    Ok(Some(cert))
}
async fn limited(req: &Request, ctx: &RouteContext<()>, operation: &str) -> worker::Result<bool> {
    let ip = req
        .headers()
        .get("cf-connecting-ip")?
        .unwrap_or_else(|| "unknown".into());
    // Mandatory binding: missing deployment configuration never enables anonymous intake.
    Ok(ctx
        .env
        .rate_limiter("IDENTITY_RATE_LIMIT")?
        .limit(format!("{operation}:{}", hash(&ip)))
        .await?
        .success)
}
async fn json_body<T: serde::de::DeserializeOwned>(
    req: &mut Request,
    max: usize,
) -> worker::Result<Option<T>> {
    if !req.headers().get("content-type")?.is_some_and(|v| {
        v.split(';')
            .next()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
    }) {
        return Ok(None);
    }
    let body = Zeroizing::new(read_bounded_body(req, max).await?);
    Ok(serde_json::from_slice(body.as_bytes()).ok())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intake {
    evidence: Evidence,
    holder_jwk: PublicJwk,
}
pub async fn intake(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    let Ok((trust, policy_hash)) = policy(&ctx) else {
        return error(503, "issuer_unavailable");
    };
    if signing(&ctx).is_err() {
        return error(503, "issuer_unavailable");
    }
    if !limited(&req, &ctx, "intake").await? {
        return error(429, "slow_down");
    }
    let Some(body) = json_body::<Intake>(&mut req, 48 * 1024).await? else {
        return error(400, "invalid_request");
    };
    if body.holder_jwk.verifying_key().is_err() {
        return error(400, "invalid_key");
    }
    let Ok(document) = verify(&body.evidence, &trust, now()?) else {
        return error(422, "document_verification_failed");
    };
    let tx = random()?;
    let secret = random()?;
    let db = ctx.env.d1("DB")?;
    // Remove abandoned transactions/expired nonces. Linked documents have their own retention API.
    db.prepare("DELETE FROM identity_transaction WHERE expires_at<=unixepoch() AND NOT EXISTS(SELECT 1 FROM identity_document d WHERE d.document_id=identity_transaction.tx_id)").run().await?;
    db.prepare("DELETE FROM identity_nonce WHERE expires_at<=unixepoch()")
        .run()
        .await?;
    let result=db.prepare("INSERT INTO identity_transaction(tx_id,poll_hash,holder_json,document_json,policy_hash,created_at,expires_at,state) SELECT ?1,?2,?3,?4,?5,unixepoch(),unixepoch()+600,'pending' WHERE (SELECT count(*) FROM identity_transaction WHERE state='pending' AND expires_at>unixepoch())<10000")
        .bind(&[js(&tx),js(&hash(&secret)),js(&serde_json::to_string(&body.holder_jwk)?),js(&serde_json::to_string(&document)?),js(&policy_hash)])?.run().await?;
    if result.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(429, "slow_down");
    }
    let root = issuer(&ctx)?
        .trim_end_matches("/identity/issuer")
        .to_string();
    response(
        json!({"transaction_id":tx,"poll_secret":secret,"approval_url":format!("{root}/identity/approve?tx={tx}"),"holder_thumbprint":body.holder_jwk.thumbprint().map_err(|_|server_error())?,"expires_in":600}),
    )
}
#[derive(Deserialize)]
struct Row {
    tx_id: String,
    holder_json: String,
    document_json: String,
    policy_hash: String,
    state: String,
    #[serde(default)]
    document_id: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    dpop_jkt: Option<String>,
}
const COLUMNS: &str = "tx_id,holder_json,document_json,policy_hash,state,account_id,epoch";
fn query_tx(req: &Request) -> worker::Result<Option<String>> {
    let url = req.url()?;
    let pairs = url.query_pairs().collect::<Vec<_>>();
    Ok(match pairs.as_slice() {
        [(key, value)] if key == "tx" && valid_id(value) => Some(value.to_string()),
        _ => None,
    })
}
pub async fn approve_get(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    let Some(tx) = query_tx(&req)? else {
        return error(404, "not_found");
    };
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    let csrf = random()?;
    let r=db.prepare("UPDATE identity_transaction SET account_id=?1,epoch=(SELECT epoch FROM account_security WHERE account_id=?1),session_hash=?2,csrf_hash=?3 WHERE tx_id=?4 AND state='pending' AND expires_at>unixepoch() AND (session_hash IS NULL OR session_hash=?2)")
        .bind(&[js(&owner.account_id),js(&owner.secret_hash),js(&hash(&csrf)),js(&tx)])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(404, "not_found");
    }
    let row = db
        .prepare(&format!(
            "SELECT {COLUMNS} FROM identity_transaction WHERE tx_id=?1 AND session_hash=?2"
        ))
        .bind(&[js(&tx), js(&owner.secret_hash)])?
        .first::<Row>(None)
        .await?
        .ok_or_else(server_error)?;
    let document: VerifiedDocument =
        serde_json::from_str(&row.document_json).map_err(|_| server_error())?;
    let holder: PublicJwk = serde_json::from_str(&row.holder_json).map_err(|_| server_error())?;
    let a = &document.attributes;
    let escape = crate::i18n::html_escape;
    let html = format!(
        "<!doctype html><html lang=ja><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>身分証の紐付け</title><main><h1>このアカウントに身分証の属性を紐付けます</h1><p>発行者の署名を検証しました。カードの現在の所持、顔の一致、現在の免許状態は確認していません。免許証は交付時の記載情報を対象とし、署名の対象外である変更記録を含めません。政府発行の証明書ではなく、Mikakiの属性証明書をこの端末の鍵に発行します。</p><p>端末に表示された鍵の識別子と一致することを確認してください。</p><dl><dt>アカウント</dt><dd>{}</dd><dt>氏名</dt><dd>{}</dd><dt>住所</dt><dd>{}</dd><dt>生年月日</dt><dd>{}</dd><dt>カード種別</dt><dd>{:?}</dd><dt>端末鍵</dt><dd>{}</dd></dl><p>本籍・写真・暗証番号・個人番号は保存しません。属性は削除するまで保存され、再発行には24時間以内の読取が必要です。今回の証明書は最長5分で失効します。</p><form method=post action=/identity/approve><input type=hidden name=tx value='{}'><input type=hidden name=csrf value='{}'><button name=decision value=approve>紐付けとこの端末への発行を許可</button><button name=decision value=link>属性のみ紐付ける</button><button name=decision value=deny>拒否</button></form></main></html>",
        escape(&owner.account_id),
        escape(&a.name),
        escape(&a.address),
        escape(&a.birth_date),
        a.document_type,
        escape(&holder.thumbprint().map_err(|_| server_error())?),
        tx,
        csrf
    );
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )?
        .from_html(html)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    tx: String,
    csrf: String,
    decision: String,
}
async fn form<T: serde::de::DeserializeOwned>(req: &mut Request) -> worker::Result<Option<T>> {
    if !req.headers().get("content-type")?.is_some_and(|s| {
        s.split(';').next().is_some_and(|v| {
            v.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
    }) {
        return Ok(None);
    }
    let body = Zeroizing::new(read_bounded_body(req, 4096).await?);
    let Ok(pairs) = serde_urlencoded::from_bytes::<Vec<(String, String)>>(body.as_bytes()) else {
        return Ok(None);
    };
    let mut names = std::collections::HashSet::new();
    if !pairs.iter().all(|(name, _)| names.insert(name)) {
        return Ok(None);
    }
    Ok(serde_urlencoded::from_bytes(body.as_bytes()).ok())
}
pub async fn approve_post(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    let root = issuer(&ctx)?
        .trim_end_matches("/identity/issuer")
        .to_string();
    if req.headers().get("origin")?.as_deref() != Some(&root) {
        return error(403, "invalid_origin");
    }
    let Some(body) = form::<Approval>(&mut req).await? else {
        return error(400, "invalid_request");
    };
    if !valid_id(&body.tx)
        || !valid_id(&body.csrf)
        || !matches!(body.decision.as_str(), "approve" | "link" | "deny")
    {
        return error(400, "invalid_request");
    }
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    let state = if body.decision != "deny" {
        "approved"
    } else {
        "denied"
    };
    let Ok((_, policy_hash)) = policy(&ctx) else {
        return error(503, "issuer_unavailable");
    };
    let r=db.prepare("UPDATE identity_transaction SET state=?1,csrf_hash=NULL,poll_hash=CASE WHEN ?7='link' THEN tx_id ELSE poll_hash END WHERE tx_id=?2 AND csrf_hash=?3 AND session_hash=?4 AND account_id=?5 AND state='pending' AND expires_at>unixepoch() AND policy_hash=?6")
        .bind(&[js(state),js(&body.tx),js(&hash(&body.csrf)),js(&owner.secret_hash),js(&owner.account_id),js(&policy_hash),js(&body.decision)])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(409, "transaction_unavailable");
    }
    if body.decision == "link" {
        return Response::builder().with_header("Cache-Control", "no-store")?
            .from_html("<!doctype html><html lang=ja><meta charset=utf-8><title>紐付け完了</title><p>属性をアカウントに紐付けました。証明書の受領は、利用するwalletから開始して別途承認してください。</p><a href=/identity>紐付けた属性を確認</a></html>");
    }
    Response::builder().with_header("Cache-Control","no-store")?.from_html("<!doctype html><html lang=ja><meta charset=utf-8><title>操作完了</title><p>操作が完了しました。Mikakiアプリに戻って受取操作を続けてください。</p></html>")
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Poll {
    transaction_id: String,
    poll_secret: String,
}
pub async fn poll(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    if !limited(&req, &ctx, "poll").await? {
        return error(429, "slow_down");
    }
    let Some(body) = json_body::<Poll>(&mut req, 4096).await? else {
        return error(400, "invalid_request");
    };
    if !valid_id(&body.transaction_id) || !valid_id(&body.poll_secret) {
        return error(400, "invalid_request");
    }
    let db = ctx.env.d1("DB")?;
    let row=db.prepare(&format!("SELECT {COLUMNS} FROM identity_transaction WHERE tx_id=?1 AND poll_hash=?2 AND expires_at>unixepoch()"))
        .bind(&[js(&body.transaction_id),js(&hash(&body.poll_secret))])?.first::<Row>(None).await?;
    let Some(row) = row else {
        return error(404, "transaction_unavailable");
    };
    if row.state == "pending" {
        return response(json!({"state":"pending","interval":3}));
    }
    if row.state == "denied" {
        return error(403, "access_denied");
    }
    if row.state != "approved" {
        return error(409, "transaction_consumed");
    }
    let code = random()?;
    let r=db.prepare("UPDATE identity_transaction SET state='offered',offer_hash=?1,expires_at=unixepoch()+90 WHERE tx_id=?2 AND poll_hash=?3 AND state='approved' AND expires_at>unixepoch()")
        .bind(&[js(&hash(&code)),js(&body.transaction_id),js(&hash(&body.poll_secret))])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(409, "transaction_consumed");
    }
    let mut configurations = vec![issuance::CONFIGURATION];
    if mdoc_certificate(&ctx)?.is_some() {
        configurations.push(mdoc::CONFIGURATION);
    }
    response(
        json!({"state":"approved","credential_offer":{"credential_issuer":issuer(&ctx)?,"credential_configuration_ids":configurations,"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":code}}}}),
    )
}

pub async fn metadata(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    if policy(&ctx).is_err() || signing(&ctx).is_err() {
        return error(503, "issuer_unavailable");
    }
    if credential_trust(
        &ctx,
        mikaki_identity::credential_certificate::Purpose::SdJwt,
    )
    .is_err()
    {
        return error(503, "issuer_unavailable");
    }
    let iss = issuer(&ctx)?;
    let mut metadata = json!({"credential_issuer":iss,"credential_endpoint":format!("{iss}/credential"),"nonce_endpoint":format!("{iss}/nonce"),"credential_configurations_supported":{"linked_document":{"format":"dc+sd-jwt","scope":"linked_document","vct":format!("{iss}/types/linked-document"),"cryptographic_binding_methods_supported":["jwk"],"credential_signing_alg_values_supported":["ES256"],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}}}}});
    if mdoc_certificate(&ctx)?.is_some() {
        metadata["credential_configurations_supported"][mdoc::CONFIGURATION] = json!({"format":"mso_mdoc","doctype":mdoc::DOCTYPE,"scope":mdoc::CONFIGURATION,"cryptographic_binding_methods_supported":["cose_key"],"credential_signing_alg_values_supported":[-7],"proof_types_supported":{"jwt":{"proof_signing_alg_values_supported":["ES256"]}}});
    }
    if wallet::haip(&ctx) {
        let Ok((policy, _)) = wallet::key_attestation_policy(&ctx) else {
            return error(503, "issuer_unavailable");
        };
        let mut required = json!({});
        if let Some(values) = policy.key_storage {
            required["key_storage"] = json!(values);
        }
        if let Some(values) = policy.user_authentication {
            required["user_authentication"] = json!(values);
        }
        for configuration in metadata["credential_configurations_supported"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            configuration["proof_types_supported"]["jwt"]["key_attestations_required"] =
                required.clone();
            configuration["proof_types_supported"]["attestation"] = json!({"proof_signing_alg_values_supported":["ES256"],"key_attestations_required":required});
        }
    }
    match encryption_key(&ctx) {
        Ok(Some(key)) => {
            metadata["credential_request_encryption"] = json!({"jwks":{"keys":[key.public().metadata()]},"enc_values_supported":["A256GCM","A128GCM"],"encryption_required":false});
            metadata["credential_response_encryption"] = json!({"alg_values_supported":["ECDH-ES"],"zip_values_supported":["DEF"],"enc_values_supported":["A256GCM","A128GCM"],"encryption_required":false});
        }
        Ok(None) => {}
        Err(_) => return error(503, "issuer_unavailable"),
    }
    response(metadata)
}
pub async fn oauth_metadata(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    let iss = issuer(&ctx)?;
    let mut metadata = json!({"issuer":iss,"token_endpoint":format!("{iss}/token"),"jwks_uri":format!("{iss}/jwks"),"grant_types_supported":["urn:ietf:params:oauth:grant-type:pre-authorized_code"],"token_endpoint_auth_methods_supported":["none"],"pre-authorized_grant_anonymous_access_supported":true,"scopes_supported":["linked_document"]});
    if wallet::enabled(&ctx) {
        wallet::validate_haip(&ctx)?;
        if wallet::haip(&ctx) {
            metadata["token_endpoint_auth_methods_supported"] = json!(["attest_jwt_client_auth"]);
            metadata["client_attestation_signing_alg_values_supported"] = json!(["ES256"]);
            metadata["client_attestation_pop_signing_alg_values_supported"] = json!(["ES256"]);
            metadata["require_pushed_authorization_requests"] = json!(true);
            metadata["grant_types_supported"] = json!([]);
            metadata["pre-authorized_grant_anonymous_access_supported"] = json!(false);
        }
        metadata["authorization_endpoint"] = json!(format!("{iss}/authorize"));
        metadata["pushed_authorization_request_endpoint"] = json!(format!("{iss}/par"));
        metadata["dpop_signing_alg_values_supported"] = json!(["ES256"]);
        metadata["grant_types_supported"]
            .as_array_mut()
            .unwrap()
            .push(json!("authorization_code"));
        metadata["response_types_supported"] = json!(["code"]);
        metadata["code_challenge_methods_supported"] = json!(["S256"]);
        metadata["authorization_response_iss_parameter_supported"] = json!(true);
        if mdoc_certificate(&ctx)?.is_some() {
            metadata["scopes_supported"]
                .as_array_mut()
                .unwrap()
                .push(json!(mdoc::CONFIGURATION));
        }
    }
    response(metadata)
}
pub async fn jwks(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    let Ok((key, kid)) = signing(&ctx) else {
        return error(503, "issuer_unavailable");
    };
    let mut jwk = serde_json::to_value(PublicJwk::from_key(key.verifying_key()))?;
    jwk["kid"] = json!(kid);
    jwk["alg"] = json!("ES256");
    jwk["use"] = json!("sig");
    response(json!({"keys":[jwk]}))
}
pub async fn type_metadata(_req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    response(
        json!({"vct":format!("{}/types/linked-document",issuer(&ctx)?),"name":"Mikaki linked document attributes","description":"Static issuer-signed document attributes linked by account-owner consent. Not a government credential; no liveness or current licence status assertion."}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    grant_type: String,
    #[serde(rename = "pre-authorized_code")]
    code: String,
}
pub async fn token(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    if !limited(&req, &ctx, "token").await? {
        return error(429, "slow_down");
    }
    let Some(body) = form::<Value>(&mut req).await? else {
        return error(400, "invalid_request");
    };
    if body["grant_type"] == "authorization_code" {
        let Ok(body) = serde_json::from_value::<wallet::Token>(body) else {
            return error(400, "invalid_request");
        };
        return wallet::token(&req, &ctx, body).await;
    }
    let Ok(body) = serde_json::from_value::<TokenRequest>(body) else {
        return error(400, "invalid_request");
    };
    if body.grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        || !valid_id(&body.code)
    {
        return error(400, "invalid_grant");
    }
    let Ok((_, policy_hash)) = policy(&ctx) else {
        return error(503, "issuer_unavailable");
    };
    let access = random()?;
    if wallet::haip(&ctx) {
        return error(400, "unsupported_grant_type");
    }
    let r=ctx.env.d1("DB")?.prepare("UPDATE identity_transaction SET state='token',access_hash=?1,offer_hash=NULL,token_expires_at=unixepoch()+120 WHERE offer_hash=?2 AND state='offered' AND expires_at>unixepoch() AND policy_hash=?3 AND EXISTS(SELECT 1 FROM identity_document d JOIN account_security a ON a.account_id=d.account_id WHERE d.document_id=identity_transaction.tx_id AND d.revoked=0 AND d.valid_until>unixepoch() AND a.active=1 AND a.epoch=d.epoch)")
        .bind(&[js(&hash(&access)),js(&hash(&body.code)),js(&policy_hash)])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(400, "invalid_grant");
    }
    response(
        json!({"access_token":access,"token_type":"Bearer","expires_in":120,"scope":"linked_document"}),
    )
}
pub async fn nonce(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    if !limited(&req, &ctx, "nonce").await? {
        return error(429, "slow_down");
    }
    let nonce = random()?;
    let db = ctx.env.d1("DB")?;
    db.prepare("DELETE FROM identity_nonce WHERE expires_at<=unixepoch()")
        .run()
        .await?;
    let r=db.prepare("INSERT INTO identity_nonce(nonce_hash,expires_at) SELECT ?1,unixepoch()+60 WHERE (SELECT count(*) FROM identity_nonce)<10000").bind(&[js(&hash(&nonce))])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(429, "slow_down");
    }
    response(json!({"c_nonce":nonce}))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proofs {
    jwt: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationProofs {
    attestation: Vec<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum CredentialProofs {
    Jwt(Proofs),
    Attestation(AttestationProofs),
    // Preserve the distinction between malformed proof data and the request envelope.
    // Invalid/ambiguous proof objects are never interpreted or used for issuance.
    Invalid(serde::de::IgnoredAny),
}
#[derive(Deserialize)]
struct CredentialRequest {
    credential_configuration_id: Option<String>,
    credential_identifier: Option<String>,
    proofs: Option<CredentialProofs>,
    format: Option<String>,
    vct: Option<String>,
    doctype: Option<String>,
    credential_response_encryption: Option<Value>,
}
pub async fn credential(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    if !limited(&req, &ctx, "credential").await? {
        return error(429, "slow_down");
    }
    let authorization = req.headers().get("authorization")?.unwrap_or_default();
    let (scheme, token) = authorization.split_once(' ').unwrap_or(("", ""));
    let dpop = scheme.eq_ignore_ascii_case("DPoP");
    if wallet::haip(&ctx) && !dpop {
        return error(401, "invalid_token");
    }
    let Some(access) = (dpop || scheme.eq_ignore_ascii_case("Bearer"))
        .then(|| token.to_owned())
        .filter(|s| valid_id(s))
    else {
        return error(401, "invalid_token");
    };
    let encrypted_request = req.headers().get("content-type")?.is_some_and(|v| {
        v.split(';')
            .next()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/jwt"))
    });
    let body = if encrypted_request {
        let Some(key) = encryption_key(&ctx)? else {
            return error(400, "invalid_encryption_parameters");
        };
        let compact = Zeroizing::new(read_bounded_body(&mut req, 32768).await?);
        let Ok(plain) = mikaki_identity::issuance_encryption::decrypt_request(&compact, &key)
        else {
            return error(400, "invalid_encryption_parameters");
        };
        serde_json::from_slice::<CredentialRequest>(&plain).ok()
    } else {
        json_body::<CredentialRequest>(&mut req, 20 * 1024).await?
    };
    let Some(body) = body else {
        return error(400, "invalid_credential_request");
    };
    let response_encryption = if let Some(parameters) = body.credential_response_encryption.as_ref()
    {
        if !encrypted_request {
            return error(400, "invalid_encryption_parameters");
        }
        let Ok(parameters) = serde_json::from_value::<
            mikaki_identity::issuance_encryption::ResponseEncryption,
        >(parameters.clone()) else {
            return error(400, "invalid_encryption_parameters");
        };
        if parameters.validate().is_err() {
            return error(400, "invalid_encryption_parameters");
        }
        Some(parameters)
    } else {
        None
    };
    let configuration = match (
        body.credential_configuration_id.as_deref(),
        body.credential_identifier.as_deref(),
    ) {
        (Some(configuration), None) if !configuration.is_empty() => configuration,
        // This issuer never returns credential_identifiers in its token response.
        (None, Some(identifier)) if !identifier.is_empty() => {
            return error(400, "unknown_credential_identifier");
        }
        _ => return error(400, "invalid_credential_request"),
    };
    if !matches!(configuration, issuance::CONFIGURATION | mdoc::CONFIGURATION) {
        return error(400, "unknown_credential_configuration");
    }
    let (proof, attestation_proof) = match body.proofs.as_ref() {
        Some(CredentialProofs::Jwt(proofs)) if proofs.jwt.len() == 1 => (&proofs.jwt[0], false),
        Some(CredentialProofs::Attestation(proofs))
            if proofs.attestation.len() == 1 && wallet::haip(&ctx) =>
        {
            (&proofs.attestation[0], true)
        }
        _ => return error(400, "invalid_proof"),
    };
    let certificate = if configuration == mdoc::CONFIGURATION {
        match mdoc_certificate(&ctx)? {
            Some(cert) => Some(cert),
            None => return error(400, "unknown_credential_configuration"),
        }
    } else {
        None
    };
    let db = ctx.env.d1("DB")?;
    let row=db.prepare(&format!("SELECT {COLUMNS} FROM identity_transaction WHERE access_hash=?1 AND state='token' AND token_expires_at>unixepoch()"))
        .bind(&[js(&hash(&access))])?.first::<Row>(None).await?;
    let row = match row {
        Some(row) => Some(row),
        None => wallet::load(&ctx, &access, configuration).await?,
    };
    let Some(row) = row else {
        return error(401, "invalid_token");
    };
    if row.document_id.is_some() {
        if let Some(response) =
            wallet::authorize_credential(&req, &ctx, &row, &access, dpop).await?
        {
            return Ok(response);
        }
    } else if dpop {
        return error(401, "invalid_token");
    }
    let iss = issuer(&ctx)?;
    let expected_format = if configuration == mdoc::CONFIGURATION {
        "mso_mdoc"
    } else {
        "dc+sd-jwt"
    };
    if body
        .format
        .as_deref()
        .is_some_and(|format| format != expected_format)
        || body.vct.as_ref().is_some_and(|vct| {
            expected_format != "dc+sd-jwt" || vct != &format!("{}/types/linked-document", iss)
        })
        || body
            .doctype
            .as_deref()
            .is_some_and(|doctype| expected_format != "mso_mdoc" || doctype != mdoc::DOCTYPE)
    {
        return error(400, "invalid_credential_request");
    }
    let Ok(nonce) = issuance::proof_nonce(proof) else {
        return error(400, "invalid_proof");
    };
    let (holder, attestation_deadline): (PublicJwk, Option<u64>) = if let Some(client) =
        row.client_id.as_deref()
    {
        if wallet::haip(&ctx) {
            let (policy, _) = wallet::key_attestation_policy(&ctx)?;
            let verified = if attestation_proof {
                mikaki_identity::key_attestation::verify(proof, &nonce, &policy, false, now()?)
                    .map(|v| (v.holder, v.expires_at))
            } else {
                issuance::verify_attested_wallet_proof(proof, &iss, &nonce, client, &policy, now()?)
            };
            let (holder, expiry) = match verified {
                Ok(value) => value,
                Err("invalid_nonce") => return error(400, "invalid_nonce"),
                Err(_) => return error(400, "invalid_proof"),
            };
            (holder, Some(expiry))
        } else {
            let Ok(holder) = issuance::verify_wallet_proof(proof, &iss, &nonce, client, now()?)
            else {
                return error(400, "invalid_proof");
            };
            (holder, None)
        }
    } else {
        if attestation_proof {
            return error(400, "invalid_proof");
        }
        (
            serde_json::from_str(&row.holder_json).map_err(|_| server_error())?,
            None,
        )
    };
    let document: VerifiedDocument =
        serde_json::from_str(&row.document_json).map_err(|_| server_error())?;
    let (trust, policy_hash) = policy(&ctx)?;
    let time = now()?;
    let trusted_key = trust.iter().find(|k| {
        k.id == document.trusted_key_id
            && k.document_type == document.attributes.document_type
            && k.not_before <= time
            && time < k.not_after
    });
    let Some(trusted_key) = trusted_key.filter(|_| row.policy_hash == policy_hash) else {
        return error(403, "document_revalidation_required");
    };
    #[derive(Deserialize)]
    struct LinkageDeadline {
        valid_until: u64,
    }
    let linkage=db.prepare("SELECT d.valid_until FROM identity_document d JOIN account_security a ON a.account_id=d.account_id WHERE d.document_id=?1 AND d.revoked=0 AND d.valid_until>unixepoch() AND d.policy_hash=?2 AND a.active=1 AND a.epoch=d.epoch")
        .bind(&[js(row.document_id.as_deref().unwrap_or(&row.tx_id)),js(&policy_hash)])?.first::<LinkageDeadline>(None).await?;
    let Some(linkage) = linkage else {
        return error(403, "document_revalidation_required");
    };
    let mut deadline = linkage
        .valid_until
        .min(trusted_key.not_after)
        .min(attestation_deadline.unwrap_or(u64::MAX));
    let (key, kid) = signing(&ctx)?;
    use mikaki_identity::credential_certificate::{Purpose, verify as verify_chain};
    let purpose = if certificate.is_some() {
        Purpose::Mdoc
    } else {
        Purpose::SdJwt
    };
    let signing_trust = credential_trust(&ctx, purpose)?;
    let mut signing_not_before = 0;
    if let Some(trust) = &signing_trust {
        let (chain, end) = verify_chain(
            trust,
            &PublicJwk::from_key(key.verifying_key()),
            purpose,
            time,
        )
        .map_err(|_| server_error())?;
        deadline = deadline.min(end);
        for cert in chain {
            signing_not_before = signing_not_before.max(
                mikaki_identity::credential_certificate::not_before(&cert)
                    .map_err(|_| server_error())?,
            );
        }
    }
    if let Some(cert) = certificate.as_deref() {
        deadline = deadline.min(
            mdoc::certificate_valid_until(cert, &PublicJwk::from_key(key.verifying_key()), time)
                .map_err(|_| server_error())?,
        );
    }
    let Ok(validity) = issuance::Validity::new(&document, time, deadline) else {
        return error(403, "document_revalidation_required");
    };
    let validity = if wallet::haip(&ctx) {
        let Ok(rounded) = validity.rounded_minutes(signing_not_before) else {
            return error(403, "document_revalidation_required");
        };
        rounded
    } else {
        validity
    };
    if attestation_deadline.is_none()
        && issuance::verify_proof(proof, &holder, &iss, &nonce, time).is_err()
    {
        return error(400, "invalid_proof");
    }
    let present=db.prepare("SELECT nonce_hash FROM identity_nonce WHERE nonce_hash=?1 AND used=0 AND expires_at>unixepoch()")
        .bind(&[js(&hash(&nonce))])?.first::<Value>(None).await?;
    if present.is_none() {
        return error(400, "invalid_nonce");
    }
    let count = 3
        + usize::from(!document.attributes.gender.is_empty())
        + usize::from(document.attributes.expiry_date.is_some());
    let mut salts = vec![[0; 16]; count];
    for salt in &mut salts {
        WorkersCryptoRandom.fill(salt).map_err(|_| server_error())?;
    }
    let credential = Zeroizing::new(
        match certificate {
            Some(cert) => {
                mdoc::issue_with_validity(&key, &cert, &holder, &document, validity, &salts)
            }
            None if signing_trust.is_some() => issuance::issue_with_certificate_trust(
                &key,
                &kid,
                &iss,
                &holder,
                &document,
                validity,
                &salts,
                signing_trust.as_ref().unwrap(),
            ),
            None => issuance::issue_with_validity(
                &key, &kid, &iss, &holder, &document, validity, &salts,
            ),
        }
        .map_err(|_| server_error())?,
    );
    let payload = json!({"credentials":[{"credential":&*credential}]});
    // Prepare authenticated ciphertext before committing nonce/budget consumption.
    let encrypted_response = if let Some(parameters) = response_encryption {
        let plain = Zeroizing::new(serde_json::to_vec(&payload)?);
        let mut entropy = Zeroizing::new([0u8; 32]);
        let mut iv = [0u8; 12];
        WorkersCryptoRandom
            .fill(&mut *entropy)
            .map_err(|_| server_error())?;
        WorkersCryptoRandom
            .fill(&mut iv)
            .map_err(|_| server_error())?;
        Some(
            mikaki_identity::issuance_encryption::encrypt_response(
                &plain,
                &parameters,
                *entropy,
                iv,
            )
            .map_err(|_| server_error())?,
        )
    } else {
        None
    };
    // D1 triggers check the live account/document and consume nonce in the SAME atomic statement.
    let committed = if row.document_id.is_some() {
        wallet::commit(&ctx, &row, &access, &nonce, &holder, validity.expires_at()).await?
    } else {
        let result=db.prepare("UPDATE identity_transaction SET state='issued',proof_nonce_hash=?1,access_hash=NULL WHERE tx_id=?2 AND access_hash=?3 AND state='token' AND token_expires_at>unixepoch() AND policy_hash=?4 AND EXISTS(SELECT 1 FROM identity_nonce n WHERE n.nonce_hash=?1 AND n.used=0 AND n.expires_at>unixepoch()) AND EXISTS(SELECT 1 FROM identity_document d JOIN account_security a ON a.account_id=d.account_id WHERE d.document_id=?2 AND d.revoked=0 AND d.valid_until>=?5 AND unixepoch()<?5 AND a.active=1 AND a.epoch=d.epoch)")
        .bind(&[js(&hash(&nonce)),js(&row.tx_id),js(&hash(&access)),js(&policy_hash),JsValue::from_f64(validity.expires_at() as f64)])?.run().await;
        matches!(result,Ok(r) if r.meta().ok().flatten().and_then(|m|m.changes).unwrap_or(0)>0)
    };
    if !committed {
        return error(409, "issuance_consumed");
    }
    if let Some(ciphertext) = encrypted_response {
        return Ok(Response::builder()
            .with_header("Content-Type", "application/jwt")?
            .with_header("Cache-Control", "no-store")?
            .with_header("Referrer-Policy", "no-referrer")?
            .fixed(ciphertext.into_bytes()));
    }
    response(payload)
}
pub async fn documents(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    let records=db.prepare("SELECT document_id,document_json,linked_at,valid_until,revoked FROM identity_document WHERE account_id=?1 ORDER BY linked_at DESC LIMIT 100").bind(&[js(&owner.account_id)])?.all().await?.results::<Value>()?;
    response(json!({"documents":records}))
}
pub async fn revoke(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    let root = issuer(&ctx)?
        .trim_end_matches("/identity/issuer")
        .to_string();
    if req.headers().get("origin")?.as_deref() != Some(&root) {
        return error(403, "invalid_origin");
    }
    let Some(id) = ctx.param("document").filter(|id| valid_id(id)) else {
        return error(404, "not_found");
    };
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    let r=db.prepare("UPDATE identity_document SET revoked=1,document_json='{}' WHERE document_id=?1 AND account_id=?2 AND revoked=0").bind(&[js(id),js(&owner.account_id)])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(404, "not_found");
    }
    response(json!({"revoked":true,"credential_max_remaining_lifetime":300}))
}

/// Owner can inspect/erase linked attributes even when new issuance is disabled.
pub async fn manage_get(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    let rows=db.prepare("SELECT document_id,document_json,revoked FROM identity_document WHERE account_id=?1 ORDER BY linked_at DESC LIMIT 100")
        .bind(&[js(&owner.account_id)])?.all().await?.results::<Value>()?;
    let release_management = claims::management(&ctx.env, &db, &owner).await?;
    let escape = crate::i18n::html_escape;
    let mut items = String::new();
    for row in rows {
        let id = row["document_id"]
            .as_str()
            .filter(|id| valid_id(id))
            .ok_or_else(server_error)?;
        if row["revoked"] == 1 {
            continue;
        }
        let document: VerifiedDocument =
            serde_json::from_str(row["document_json"].as_str().ok_or_else(server_error)?)
                .map_err(|_| server_error())?;
        let a = &document.attributes;
        let csrf = hash(&format!("{}:identity-erase:{id}", owner.secret_hash));
        items.push_str(&format!("<section><h2>{:?}</h2><dl><dt>氏名</dt><dd>{}</dd><dt>住所</dt><dd>{}</dd><dt>生年月日</dt><dd>{}</dd></dl><form method=post action=/identity/erase><input type=hidden name=document value='{id}'><input type=hidden name=csrf value='{csrf}'><button>紐付けを解除し属性を削除</button></form></section>",a.document_type,escape(&a.name),escape(&a.address),escape(&a.birth_date)));
        items.push_str(&release_management.controls(id)?);
    }
    if items.is_empty() {
        items = "<p>紐付けられた身分証はありません。</p>".into();
    }
    Response::builder().with_header("Cache-Control","no-store")?.with_header("Referrer-Policy","no-referrer")?.with_header("Content-Security-Policy","default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")?.from_html(format!("<!doctype html><html lang=ja><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>身分証の属性</title><main><h1>紐付けた身分証の属性</h1><p>アカウント: {}</p><p>解除後は再発行できません。すでに受け取った証明書は最長5分で失効します。</p>{items}</main></html>",escape(&owner.account_id)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EraseForm {
    document: String,
    csrf: String,
}
pub async fn manage_post(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    let root = issuer(&ctx)?
        .trim_end_matches("/identity/issuer")
        .to_string();
    if req.headers().get("origin")?.as_deref() != Some(&root) {
        return error(403, "invalid_origin");
    }
    let Some(body) = form::<EraseForm>(&mut req).await? else {
        return error(400, "invalid_request");
    };
    if !valid_id(&body.document) || !valid_id(&body.csrf) {
        return error(400, "invalid_request");
    }
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    use subtle::ConstantTimeEq;
    let expected = hash(&format!(
        "{}:identity-erase:{}",
        owner.secret_hash, body.document
    ));
    if !bool::from(expected.as_bytes().ct_eq(body.csrf.as_bytes())) {
        return error(403, "invalid_request");
    }
    let r=db.prepare("UPDATE identity_document SET revoked=1,document_json='{}' WHERE document_id=?1 AND account_id=?2 AND revoked=0")
        .bind(&[js(&body.document),js(&owner.account_id)])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(404, "not_found");
    }
    Ok(Response::builder()
        .with_status(303)
        .with_header("Cache-Control", "no-store")?
        .with_header("Location", "/identity")?
        .empty())
}

pub async fn purge(env: &worker::Env) -> worker::Result<()> {
    let db = env.d1("DB")?;
    // Rollout and rollback can temporarily leave issuance disabled or the migration absent.
    if db.prepare("SELECT 1 AS present FROM sqlite_master WHERE type='table' AND name='identity_transaction'").first::<Value>(None).await?.is_none() { return Ok(()); }
    db.prepare("DELETE FROM identity_transaction WHERE tx_id IN (SELECT tx_id FROM identity_transaction WHERE expires_at<=unixepoch() AND NOT EXISTS(SELECT 1 FROM identity_document d WHERE d.document_id=identity_transaction.tx_id) LIMIT 1000)").run().await?;
    if db.prepare("SELECT 1 AS present FROM sqlite_master WHERE type='table' AND name='identity_wallet_grant'").first::<Value>(None).await?.is_some() {
        db.prepare("DELETE FROM identity_wallet_grant WHERE grant_id IN (SELECT grant_id FROM identity_wallet_grant WHERE max(expires_at,coalesce(token_expires_at,0))<=unixepoch() LIMIT 1000)").run().await?;
    }
    if db.prepare("SELECT 1 AS present FROM sqlite_master WHERE type='table' AND name='identity_wallet_par'").first::<Value>(None).await?.is_some() {
        db.prepare("DELETE FROM identity_wallet_par WHERE request_hash IN (SELECT request_hash FROM identity_wallet_par WHERE expires_at<=unixepoch()-300 LIMIT 1000)").run().await?;
    }
    db.prepare("DELETE FROM identity_nonce WHERE nonce_hash IN (SELECT nonce_hash FROM identity_nonce WHERE expires_at<=unixepoch() LIMIT 1000)").run().await?;
    Ok(())
}
