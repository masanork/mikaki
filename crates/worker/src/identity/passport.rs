//! Owner-approved, ephemeral DG1 attestation issuance. Raw evidence is never stored.
pub(super) mod haip;
use super::*;
use mikaki_identity::passport::{self as model, credential as profile};

pub(super) fn enabled(ctx: &RouteContext<()>) -> bool {
    super::enabled(ctx)
        && ctx
            .env
            .var("IDENTITY_PASSPORT_ENABLED")
            .is_ok_and(|v| v.to_string() == "true")
}
fn policy(ctx: &RouteContext<()>) -> worker::Result<model::Policy> {
    policy_from_env(&ctx.env)
}
fn policy_from_env(env: &worker::Env) -> worker::Result<model::Policy> {
    match env.var("IDENTITY_PASSPORT_CRLS") {
        Ok(json) => model::Policy::from_json(&json.to_string()).map_err(|_| server_error()),
        Err(_) => Ok(model::Policy::default()),
    }
}
#[derive(serde::Serialize)]
pub(crate) struct Readiness {
    fingerprint: String,
    valid_until: u64,
}
pub(crate) async fn ready(env: &worker::Env) -> worker::Result<Option<Readiness>> {
    if !env
        .var("IDENTITY_PASSPORT_ENABLED")
        .is_ok_and(|v| v.to_string() == "true")
    {
        return Ok(None);
    }
    if !env
        .var("IDENTITY_ENABLED")
        .is_ok_and(|v| v.to_string() == "true")
    {
        return Err(server_error());
    }
    if env
        .var("IDENTITY_HAIP_ENABLED")
        .is_ok_and(|v| v.to_string() == "true")
        && !env
            .var("IDENTITY_WALLET_ENABLED")
            .is_ok_and(|v| v.to_string() == "true")
    {
        return Err(server_error());
    }
    let policy = policy_from_env(env)?;
    let valid_until = policy.valid_until(now()?).map_err(|_| server_error())?;
    let raw = Zeroizing::new(env.secret("IDENTITY_ISSUER_JWK")?.to_string());
    issuance::issuer_key(&raw).map_err(|_| server_error())?;
    env.d1("DB")?
        .prepare("SELECT tx_id FROM identity_passport_transaction LIMIT 0")
        .run()
        .await?;
    Ok(Some(Readiness {
        fingerprint: policy.fingerprint(),
        valid_until,
    }))
}
fn evidence_hash(evidence: &model::Evidence) -> worker::Result<String> {
    let bytes = Zeroizing::new(serde_json::to_vec(evidence)?);
    Ok(B64.encode(Sha256::digest(&*bytes)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Intake {
    evidence: model::Evidence,
    holder_jwk: PublicJwk,
}
#[derive(Deserialize)]
struct PassportRow {
    tx_id: String,
    holder_json: String,
    projection_json: String,
    evidence_hash: String,
    policy_hash: String,
    expires_at: u64,
    evidence_until: u64,
    state: String,
    #[serde(default)]
    haip: u8,
    client_id: Option<String>,
    dpop_jkt: Option<String>,
}
pub(crate) async fn intake(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    if !limited(&req, &ctx, "passport_intake").await? {
        return error(429, "slow_down");
    }
    let Some(body) = json_body::<Intake>(&mut req, 16 * 1024).await? else {
        return error(400, "invalid_request");
    };
    if body.holder_jwk.verifying_key().is_err() {
        return error(400, "invalid_key");
    }
    let policy = policy(&ctx)?;
    let time = now()?;
    let Ok(verified) = body.evidence.verify(&policy, time) else {
        return error(422, "passport_verification_failed");
    };
    signing(&ctx)?;
    let tx = random()?;
    let secret = random()?;
    let until = time
        .saturating_add(600)
        .min(verified.evidence_valid_until());
    let db = ctx.env.d1("DB")?;
    db.prepare("DELETE FROM identity_passport_transaction WHERE tx_id IN (SELECT tx_id FROM identity_passport_transaction WHERE expires_at<=unixepoch() LIMIT 1000)")
        .run()
        .await?;
    let r=db.prepare("INSERT INTO identity_passport_transaction(tx_id,poll_hash,holder_json,projection_json,evidence_hash,policy_hash,created_at,expires_at,evidence_until,state,haip) SELECT ?1,?2,?3,?4,?5,?6,unixepoch(),?7,?8,'pending',?9 WHERE (SELECT count(*) FROM identity_passport_transaction WHERE state='pending')<1000")
        .bind(&[js(&tx),js(&hash(&secret)),js(&serde_json::to_string(&body.holder_jwk)?),js(&serde_json::to_string(verified.claims())?),js(&evidence_hash(&body.evidence)?),js(&policy.fingerprint()),JsValue::from_f64(until as f64),JsValue::from_f64(verified.evidence_valid_until() as f64),JsValue::from_f64(if wallet::haip(&ctx) {1.0} else {0.0})])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(429, "slow_down");
    }
    let root = issuer(&ctx)?
        .trim_end_matches("/identity/issuer")
        .to_string();
    response(
        json!({"transaction_id":tx,"poll_secret":secret,"approval_url":format!("{root}/identity/passport/approve?tx={tx}"),"holder_thumbprint":body.holder_jwk.thumbprint().map_err(|_|server_error())?,"expires_in":until-time}),
    )
}
pub(crate) async fn approve_get(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) || wallet::haip(&ctx) {
        return error(404, "not_found");
    }
    let pairs = req
        .url()?
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<Vec<_>>();
    if pairs.len() != 1 || pairs[0].0 != "tx" || !valid_id(&pairs[0].1) {
        return error(400, "invalid_request");
    }
    let tx = &pairs[0].1;
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    let csrf = random()?;
    let policy_hash = policy(&ctx)?.fingerprint();
    let r=db.prepare("UPDATE identity_passport_transaction SET account_id=?1,epoch=(SELECT epoch FROM account_security WHERE account_id=?1),session_hash=?2,csrf_hash=?3 WHERE tx_id=?4 AND state='pending' AND expires_at>unixepoch() AND policy_hash=?5 AND (session_hash IS NULL OR (session_hash=?2 AND account_id=?1))")
        .bind(&[js(&owner.account_id),js(&owner.secret_hash),js(&hash(&csrf)),js(tx),js(&policy_hash)])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(404, "transaction_unavailable");
    }
    let row=db.prepare("SELECT tx_id,holder_json,projection_json,evidence_hash,policy_hash,expires_at,evidence_until,state,haip,client_id,dpop_jkt FROM identity_passport_transaction WHERE tx_id=?1 AND session_hash=?2").bind(&[js(tx),js(&owner.secret_hash)])?.first::<PassportRow>(None).await?.ok_or_else(server_error)?;
    let claims: Value = serde_json::from_str(&row.projection_json)?;
    let holder: PublicJwk = serde_json::from_str(&row.holder_json)?;
    let escape = crate::i18n::html_escape;
    let mut values = String::new();
    for (key, label) in [
        ("name_mrz", "氏名（MRZ表記）"),
        ("issuing_state", "発行国コード"),
        ("nationality", "国籍コード"),
        ("birth_date_mrz", "生年月日（YYMMDD）"),
        ("expiry_date_mrz", "旅券期限（YYMMDD）"),
        ("sex_mrz", "性別（MRZ表記）"),
    ] {
        values.push_str(&format!(
            "<dt>{label}</dt><dd>{}</dd>",
            escape(claims[key].as_str().unwrap_or(""))
        ));
    }
    let html = format!(
        "<!doctype html><html lang=ja><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>旅券属性証明の発行</title><main><h1>このWalletへ旅券のMRZ属性証明を発行します</h1><p>アカウント: {}</p><p>DG1・SOD原本を受け取り、発行国への署名チェーンと失効情報を検証しました。原本は保存しません。上記原本には旅券番号・個人番号欄も含まれますが、証明書には次の6項目だけを含めます。</p><dl>{values}<dt>Wallet鍵の識別子</dt><dd>{}</dd></dl><p>日付は年の下2桁のままです。生年の世紀・年齢・現在有効な旅券・本人の顔や現在の所持は証明しません。政府発行のデジタル旅券ではなくMikakiの証明書です。発行直前にも原本を再検証します。証明書の有効期間は最長5分です。6項目の審査期限は最長10分で、期限後に削除します。アカウントへの永続的な属性紐付けは行いません。</p><form method=post action=/identity/passport/approve><input type=hidden name=tx value='{tx}'><input type=hidden name=csrf value='{csrf}'><button name=decision value=approve>内容とWallet鍵を確認して発行を許可</button><button name=decision value=deny>拒否</button></form></main></html>",
        escape(&owner.account_id),
        escape(&holder.thumbprint().map_err(|_| server_error())?)
    );
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )?
        .with_header("X-Content-Type-Options", "nosniff")?
        .from_html(html)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    tx: String,
    csrf: String,
    decision: String,
}
pub(crate) async fn approve_post(
    mut req: Request,
    ctx: RouteContext<()>,
) -> worker::Result<Response> {
    if !enabled(&ctx) || wallet::haip(&ctx) {
        return error(404, "not_found");
    }
    let root = issuer(&ctx)?
        .trim_end_matches("/identity/issuer")
        .to_string();
    if req.headers().get("origin")?.as_deref() != Some(&root) {
        return error(403, "invalid_origin");
    }
    let Some(body) = form::<Decision>(&mut req).await? else {
        return error(400, "invalid_request");
    };
    if !valid_id(&body.tx)
        || !valid_id(&body.csrf)
        || !matches!(body.decision.as_str(), "approve" | "deny")
    {
        return error(400, "invalid_request");
    }
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    let state = if body.decision == "approve" {
        "approved"
    } else {
        "denied"
    };
    let r=db.prepare("UPDATE identity_passport_transaction SET state=?1,csrf_hash=NULL WHERE tx_id=?2 AND csrf_hash=?3 AND session_hash=?4 AND account_id=?5 AND state='pending' AND expires_at>unixepoch() AND policy_hash=?6 AND EXISTS(SELECT 1 FROM account_security a WHERE a.account_id=identity_passport_transaction.account_id AND a.active=1 AND a.epoch=identity_passport_transaction.epoch)")
        .bind(&[js(state),js(&body.tx),js(&hash(&body.csrf)),js(&owner.secret_hash),js(&owner.account_id),js(&policy(&ctx)?.fingerprint())])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(409, "transaction_unavailable");
    }
    Response::builder().with_header("Cache-Control","no-store")?.from_html("<!doctype html><html lang=ja><meta charset=utf-8><title>操作完了</title><p>操作が完了しました。Mikakiアプリに戻って受取操作を続けてください。</p></html>")
}
pub(crate) async fn poll(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) || wallet::haip(&ctx) {
        return error(404, "not_found");
    }
    if !limited(&req, &ctx, "passport_poll").await? {
        return error(429, "slow_down");
    }
    let Some(body) = json_body::<super::Poll>(&mut req, 4096).await? else {
        return error(400, "invalid_request");
    };
    if !valid_id(&body.transaction_id) || !valid_id(&body.poll_secret) {
        return error(400, "invalid_request");
    }
    let db = ctx.env.d1("DB")?;
    let row=db.prepare("SELECT tx_id,holder_json,projection_json,evidence_hash,policy_hash,expires_at,evidence_until,state,haip,client_id,dpop_jkt FROM identity_passport_transaction WHERE tx_id=?1 AND poll_hash=?2 AND expires_at>unixepoch()").bind(&[js(&body.transaction_id),js(&hash(&body.poll_secret))])?.first::<PassportRow>(None).await?;
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
    let r=db.prepare("UPDATE identity_passport_transaction SET state='offered',offer_hash=?1,expires_at=min(expires_at,unixepoch()+90) WHERE tx_id=?2 AND poll_hash=?3 AND state='approved' AND expires_at>unixepoch() AND policy_hash=?4 AND EXISTS(SELECT 1 FROM account_security a WHERE a.account_id=identity_passport_transaction.account_id AND a.active=1 AND a.epoch=identity_passport_transaction.epoch)")
        .bind(&[js(&hash(&code)),js(&row.tx_id),js(&hash(&body.poll_secret)),js(&policy(&ctx)?.fingerprint())])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(409, "transaction_consumed");
    }
    response(
        json!({"state":"approved","credential_offer":{"credential_issuer":issuer(&ctx)?,"credential_configuration_ids":[profile::CONFIGURATION],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":code}}}}),
    )
}
pub(super) async fn token_if_present(
    ctx: &RouteContext<()>,
    code: &str,
) -> worker::Result<Option<Response>> {
    if !enabled(ctx) || wallet::haip(ctx) {
        return Ok(None);
    }
    let db = ctx.env.d1("DB")?;
    if db
        .prepare("SELECT tx_id FROM identity_passport_transaction WHERE offer_hash=?1")
        .bind(&[js(&hash(code))])?
        .first::<Value>(None)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    let access = random()?;
    let r=db.prepare("UPDATE identity_passport_transaction SET state='token',offer_hash=NULL,access_hash=?1,token_expires_at=min(expires_at,unixepoch()+120) WHERE offer_hash=?2 AND state='offered' AND expires_at>unixepoch() AND policy_hash=?3 AND EXISTS(SELECT 1 FROM account_security a WHERE a.account_id=identity_passport_transaction.account_id AND a.active=1 AND a.epoch=identity_passport_transaction.epoch)")
        .bind(&[js(&hash(&access)),js(&hash(code)),js(&policy(ctx)?.fingerprint())])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return Ok(Some(error(400, "invalid_grant")?));
    }
    let end = db
        .prepare("SELECT token_expires_at FROM identity_passport_transaction WHERE access_hash=?1")
        .bind(&[js(&hash(&access))])?
        .first::<Value>(None)
        .await?
        .ok_or_else(server_error)?;
    Ok(Some(response(
        json!({"access_token":access,"token_type":"Bearer","expires_in":end["token_expires_at"].as_u64().unwrap_or(0).saturating_sub(now()?),"scope":profile::CONFIGURATION}),
    )?))
}
pub(super) async fn credential(
    req: &Request,
    ctx: &RouteContext<()>,
    body: &CredentialRequest,
    access: &str,
    dpop: bool,
    encrypted: bool,
    response_encryption: Option<mikaki_identity::issuance_encryption::ResponseEncryption>,
) -> worker::Result<Response> {
    if !enabled(ctx) {
        return error(400, "unknown_credential_configuration");
    }
    if body.doctype.is_some()
        || body.format.as_deref().is_some_and(|s| s != "dc+sd-jwt")
        || body
            .vct
            .as_ref()
            .is_some_and(|v| v != &profile::vct(&issuer(ctx).unwrap_or_default()))
    {
        return error(400, "invalid_credential_request");
    }
    let Some(evidence) = body.passport_evidence.as_ref() else {
        return error(400, "passport_evidence_required");
    };
    let (proof, attestation_proof) = match body.proofs.as_ref() {
        Some(CredentialProofs::Jwt(proofs)) if proofs.jwt.len() == 1 => (&proofs.jwt[0], false),
        Some(CredentialProofs::Attestation(proofs))
            if proofs.attestation.len() == 1 && wallet::haip(ctx) =>
        {
            (&proofs.attestation[0], true)
        }
        _ => return error(400, "invalid_proof"),
    };
    let db = ctx.env.d1("DB")?;
    let row=db.prepare("SELECT tx_id,holder_json,projection_json,evidence_hash,policy_hash,expires_at,evidence_until,state,haip,client_id,dpop_jkt FROM identity_passport_transaction WHERE access_hash=?1 AND state='token' AND expires_at>unixepoch() AND token_expires_at>unixepoch() AND EXISTS(SELECT 1 FROM account_security a WHERE a.account_id=identity_passport_transaction.account_id AND a.active=1 AND a.epoch=identity_passport_transaction.epoch)").bind(&[js(&hash(access))])?.first::<PassportRow>(None).await?;
    let Some(row) = row else {
        return error(401, "invalid_token");
    };
    if (row.haip != 0) != wallet::haip(ctx) {
        return error(401, "invalid_token");
    }
    if let Some(response) =
        wallet::authorize_sender(req, ctx, row.dpop_jkt.as_deref(), access, dpop).await?
    {
        return Ok(response);
    }
    let policy = policy(ctx)?;
    let time = now()?;
    let iss = issuer(ctx)?;
    if row.policy_hash != policy.fingerprint() || row.evidence_hash != evidence_hash(evidence)? {
        return error(403, "passport_revalidation_required");
    }
    let Ok(nonce) = issuance::proof_nonce(proof) else {
        return error(400, "invalid_proof");
    };
    let (holder, attestation_end) = if row.haip != 0 {
        if !encrypted || response_encryption.is_none() {
            return error(400, "invalid_encryption_parameters");
        }
        let Some(client) = row.client_id.as_deref() else {
            return error(401, "invalid_token");
        };
        let (trust, _) = wallet::key_attestation_policy(ctx)?;
        let verified = if attestation_proof {
            mikaki_identity::key_attestation::verify(proof, &nonce, &trust, false, time)
                .map(|v| (v.holder, v.expires_at))
        } else {
            issuance::verify_attested_wallet_proof(proof, &iss, &nonce, client, &trust, time)
        };
        match verified {
            Ok(v) => v,
            Err(_) => return error(400, "invalid_proof"),
        }
    } else {
        let holder: PublicJwk = serde_json::from_str(&row.holder_json)?;
        if issuance::verify_proof(proof, &holder, &iss, &nonce, time).is_err() {
            return error(400, "invalid_proof");
        }
        (holder, u64::MAX)
    };
    if db.prepare("SELECT nonce_hash FROM identity_nonce WHERE nonce_hash=?1 AND used=0 AND expires_at>unixepoch()").bind(&[js(&hash(&nonce))])?.first::<Value>(None).await?.is_none() { return error(400,"invalid_nonce"); }
    let Ok(verified) = evidence.verify(&policy, time) else {
        return error(422, "passport_verification_failed");
    };
    if serde_json::to_value(verified.claims())?
        != serde_json::from_str::<Value>(&row.projection_json)?
    {
        return error(403, "passport_revalidation_required");
    }
    let (key, kid) = signing(ctx)?;
    let trust = credential_trust(ctx, mikaki_identity::credential_certificate::Purpose::SdJwt)?;
    let mut salts = [[0; 16]; 6];
    for salt in &mut salts {
        WorkersCryptoRandom.fill(salt).map_err(|_| server_error())?;
    }
    let (credential, end) = profile::issue(
        &key,
        &kid,
        &iss,
        &holder,
        &verified,
        time,
        row.expires_at.min(row.evidence_until).min(attestation_end),
        &salts,
        trust.as_ref(),
    )
    .map_err(|_| server_error())?;
    let credential = Zeroizing::new(credential);
    let payload = json!({"credentials":[{"credential":&*credential}]});
    let ciphertext = if let Some(parameters) = response_encryption {
        if !encrypted {
            return error(400, "invalid_encryption_parameters");
        }
        let plain = Zeroizing::new(serde_json::to_vec(&payload)?);
        let mut entropy = Zeroizing::new([0; 32]);
        let mut iv = [0; 12];
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
    let r=db.prepare("UPDATE identity_passport_transaction SET state='issued',proof_nonce_hash=?1 WHERE tx_id=?2 AND access_hash=?3 AND state='token' AND expires_at>unixepoch() AND token_expires_at>unixepoch() AND policy_hash=?4 AND ?5>unixepoch() AND (haip=0 OR (client_policy_hash=?6 AND client_binding IS NOT NULL AND dpop_jkt=?7)) AND EXISTS(SELECT 1 FROM account_security a WHERE a.account_id=identity_passport_transaction.account_id AND a.active=1 AND a.epoch=identity_passport_transaction.epoch) AND EXISTS(SELECT 1 FROM identity_nonce n WHERE n.nonce_hash=?1 AND n.used=0 AND n.expires_at>unixepoch())")
        .bind(&[js(&hash(&nonce)),js(&row.tx_id),js(&hash(access)),js(&policy.fingerprint()),JsValue::from_f64(end as f64),js(&haip::client_policy(ctx)?),row.dpop_jkt.as_deref().map(js).unwrap_or(JsValue::NULL)])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(409, "transaction_consumed");
    }
    match ciphertext {
        Some(wire) => Ok(Response::builder()
            .with_header("Cache-Control", "no-store")?
            .with_header("Content-Type", "application/jwt")?
            .fixed(wire.into_bytes())),
        None => response(payload),
    }
}
pub(crate) async fn type_metadata(
    _req: Request,
    ctx: RouteContext<()>,
) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    response(
        json!({"vct":profile::vct(&issuer(&ctx)?),"name":"Mikaki passport DG1 authenticity attestation","description":"MRZ dates retain two-digit years. Does not verify current document validity, age, live possession or face match. Not a government DTC."}),
    )
}
