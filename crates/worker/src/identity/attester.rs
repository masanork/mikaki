//! Opt-in native attester broker. Android trust decisions use a dedicated service
//! binding; device envelopes, browser sessions and caller URLs have no authority.
use super::*;
use futures_util::{
    StreamExt,
    future::{Either, select},
};
use mikaki_identity::{
    android_attestation_evidence::UntrustedAndroidEvidence,
    client_attestation::{self, AttesterTrust, VerifiedAttestation},
};
use std::time::Duration;
use worker::{Delay, Headers, Method, RequestInit};
use zeroize::Zeroize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Client {
    client_id: String,
    verifier_policy_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signing {
    jwk: String,
    chain: Vec<String>,
    trust_anchors: Vec<String>,
}
struct Policy {
    issuer: String,
    fingerprint: String,
    client: Client,
    signing: Signing,
    key: p256_key::Key,
    deadline: u64,
}
fn enabled(ctx: &RouteContext<()>) -> bool {
    wallet::haip(ctx)
        && ctx
            .env
            .var("IDENTITY_ATTESTER_ENABLED")
            .is_ok_and(|v| v.to_string() == "true")
}
fn policy(ctx: &RouteContext<()>, client: &str) -> worker::Result<Policy> {
    ctx.env.service("IDENTITY_ANDROID_VERIFIER")?;
    let raw = ctx.env.var("IDENTITY_ATTESTER_CLIENTS")?.to_string();
    if raw.len() > 16384 {
        return Err(server_error());
    }
    let clients: Vec<Client> = serde_json::from_str(&raw).map_err(|_| server_error())?;
    let mut ids = std::collections::HashSet::new();
    if clients.is_empty()
        || clients.len() > 32
        || clients.iter().any(|c| {
            c.client_id.is_empty()
                || c.client_id.len() > 256
                || !ids.insert(&c.client_id)
                || !valid_id(&c.verifier_policy_hash)
        })
    {
        return Err(server_error());
    }
    let client = clients
        .into_iter()
        .find(|c| c.client_id == client)
        .ok_or_else(server_error)?;
    let secret = Zeroizing::new(ctx.env.secret("IDENTITY_ATTESTER_SIGNING")?.to_string());
    if secret.len() > 32768 {
        return Err(server_error());
    }
    let mut signing: Signing = serde_json::from_str(&secret).map_err(|_| server_error())?;
    let key = issuance::issuer_key(&signing.jwk);
    signing.jwk.zeroize();
    let (key, _) = key.map_err(|_| server_error())?;
    let public = PublicJwk::from_key(key.verifying_key());
    if public == PublicJwk::from_key(super::signing(ctx)?.0.verifying_key()) {
        return Err(server_error());
    }
    if let Some(encryption) = encryption_key(ctx)? {
        if public == encryption.public().public().map_err(|_| server_error())? {
            return Err(server_error());
        }
    }
    mikaki_identity::certificate::validate_attester_roots(&signing.trust_anchors)
        .map_err(|_| server_error())?;
    let chain = signing
        .chain
        .iter()
        .map(|s| mikaki_identity::certificate::decode_certificate(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| server_error())?;
    let (cert_key, deadline) =
        mikaki_identity::certificate::verify_attester_chain(&chain, &signing.trust_anchors, now()?)
            .map_err(|_| server_error())?;
    if cert_key != *key.verifying_key() {
        return Err(server_error());
    }
    let issuer = format!(
        "{}/identity/attester",
        configured_issuer(&ctx.env.var("MIKAKI_ISSUER")?.to_string()).ok_or_else(server_error)?
    );
    let fingerprint = hash(&serde_json::to_string(
        &json!({"v":1,"issuer":issuer,"client":client.client_id,"verifier_policy_hash":client.verifier_policy_hash,"key":public,"chain":signing.chain,"roots":signing.trust_anchors}),
    )?);
    Ok(Policy {
        issuer,
        fingerprint,
        client,
        signing,
        key,
        deadline,
    })
}
async fn client_binding(req: &Request, p: &Policy) -> worker::Result<Option<VerifiedAttestation>> {
    let Some(at) = req.headers().get("oauth-client-attestation")? else {
        return Ok(None);
    };
    let Some(pop) = req.headers().get("oauth-client-attestation-pop")? else {
        return Ok(None);
    };
    let policies = [AttesterTrust {
        issuer: p.issuer.clone(),
        trust_anchors: p.signing.trust_anchors.clone(),
    }];
    let Ok(v) =
        client_attestation::verify(&at, &pop, &p.client.client_id, &p.issuer, &policies, now()?)
    else {
        return Ok(None);
    };
    // Only our authenticated, current policy version can authorize holder enrollment.
    let claims = at
        .split('.')
        .nth(1)
        .and_then(|s| B64.decode(s).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    if claims
        .as_ref()
        .is_none_or(|c| c["attester_policy_hash"] != p.fingerprint)
    {
        return Ok(None);
    }
    Ok(Some(v))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    client_id: String,
    purpose: String,
    c_nonce: Option<String>,
}
pub async fn challenge(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    if !limited(&req, &ctx, "attester-challenge").await? {
        return error(429, "slow_down");
    }
    let Some(body) = json_body::<Challenge>(&mut req, 4096).await? else {
        return error(400, "invalid_request");
    };
    let Ok(p) = policy(&ctx, &body.client_id) else {
        return error(503, "attester_unavailable");
    };
    if !matches!(body.purpose.as_str(), "client" | "holder")
        || (body.purpose == "client" && body.c_nonce.is_some())
    {
        return error(400, "invalid_request");
    }
    let db = ctx.env.d1("DB")?;
    let mut until = now()?.saturating_add(60).min(p.deadline);
    let binding = if body.purpose == "holder" {
        let Some(v) = client_binding(&req, &p).await? else {
            return error(400, "invalid_client");
        };
        until = until.min(v.expires_at);
        Some(v)
    } else {
        None
    };
    let nonce = if body.purpose == "holder" {
        let Some(nonce) = body.c_nonce.filter(|s| valid_id(s)) else {
            return error(400, "invalid_nonce");
        };
        let expiry=db.prepare("SELECT expires_at FROM identity_nonce WHERE nonce_hash=?1 AND used=0 AND expires_at>unixepoch()")
            .bind(&[js(&hash(&nonce))])?.first::<Value>(None).await?.and_then(|v|v["expires_at"].as_u64());
        let Some(expiry) = expiry else {
            return error(400, "invalid_nonce");
        };
        until = until.min(expiry);
        Some(nonce)
    } else {
        None
    };
    if until <= now()? {
        return error(503, "attester_unavailable");
    }
    if !wallet::accept_attestation(&ctx, &body.client_id, &binding).await? {
        return error(400, "invalid_client");
    }
    let challenge = random()?;
    db.prepare("DELETE FROM identity_attester_challenge WHERE challenge_hash IN (SELECT challenge_hash FROM identity_attester_challenge WHERE expires_at<=unixepoch() LIMIT 1000)").run().await?;
    let inserted=db.prepare("INSERT INTO identity_attester_challenge(challenge_hash,client_id,purpose,policy_hash,client_binding,nonce_hash,expires_at) SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE (SELECT count(*) FROM identity_attester_challenge)<2000")
        .bind(&[js(&hash(&challenge)),js(&body.client_id),js(&body.purpose),js(&p.fingerprint),binding.as_ref().map(|v|js(&v.thumbprint)).unwrap_or(JsValue::NULL),nonce.as_ref().map(|n|js(&hash(n))).unwrap_or(JsValue::NULL),JsValue::from_f64(until as f64)])?.run().await?;
    if inserted.meta()?.and_then(|m| m.changes) != Some(1) {
        return error(503, "attester_unavailable");
    }
    response(
        json!({"challenge":challenge,"expires_in":until.saturating_sub(now()?),"purpose":body.purpose}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Redeem {
    client_id: String,
    purpose: String,
    challenge: String,
    public_key: PublicJwk,
    certificate_chain: Vec<String>,
    proof: String,
    c_nonce: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verdict {
    format: String,
    verified: bool,
    client_id: String,
    purpose: String,
    challenge: String,
    public_key: PublicJwk,
    verifier_policy_hash: String,
    expires_at: u64,
}
async fn verdict(
    ctx: &RouteContext<()>,
    p: &Policy,
    b: &Redeem,
    evidence: UntrustedAndroidEvidence,
) -> worker::Result<Option<Verdict>> {
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    init.body = Some(JsValue::from_str(&serde_json::to_string(
        &json!({"format":"android-key-attestation-verification-v1","client_id":b.client_id,"purpose":b.purpose,"verifier_policy_hash":p.client.verifier_policy_hash,"evidence":evidence}),
    )?));
    let request = Request::new_with_init("https://android-verifier.internal/verify", &init)?;
    let service = ctx.env.service("IDENTITY_ANDROID_VERIFIER")?;
    let work = async {
        let mut response = service.fetch_request(request).await?;
        if response.status_code() != 200
            || !response.headers().get("content-type")?.is_some_and(|s| {
                s.split(';')
                    .next()
                    .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json"))
            })
        {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        let mut stream = response.stream()?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len() + chunk.len() > 4096 {
                return Ok(None);
            }
            bytes.extend(chunk);
        }
        let v: Verdict = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        if v.format != "android-key-attestation-verdict-v1"
            || !v.verified
            || v.client_id != b.client_id
            || v.purpose != b.purpose
            || v.challenge != b.challenge
            || v.public_key != b.public_key
            || v.verifier_policy_hash != p.client.verifier_policy_hash
            || v.expires_at <= now()?
        {
            return Ok(None);
        }
        Ok(Some(v))
    };
    match select(
        Box::pin(work),
        Box::pin(Delay::from(Duration::from_secs(10))),
    )
    .await
    {
        Either::Left((v, _)) => v,
        Either::Right(_) => Ok(None),
    }
}
pub async fn redeem(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    if !limited(&req, &ctx, "attester-redeem").await? {
        return error(429, "slow_down");
    }
    let Some(b) = json_body::<Redeem>(&mut req, 64 * 1024).await? else {
        return error(400, "invalid_request");
    };
    if !valid_id(&b.challenge) || !matches!(b.purpose.as_str(), "client" | "holder") {
        return error(400, "invalid_request");
    }
    if b.public_key.verifying_key().is_err() {
        return error(400, "invalid_request");
    }
    let Ok(p) = policy(&ctx, &b.client_id) else {
        return error(503, "attester_unavailable");
    };
    let db = ctx.env.d1("DB")?;
    let row=db.prepare("SELECT client_binding,nonce_hash FROM identity_attester_challenge WHERE challenge_hash=?1 AND client_id=?2 AND purpose=?3 AND policy_hash=?4 AND used=0 AND expires_at>unixepoch()")
        .bind(&[js(&hash(&b.challenge)),js(&b.client_id),js(&b.purpose),js(&p.fingerprint)])?.first::<Value>(None).await?;
    let Some(row) = row else {
        return error(400, "invalid_challenge");
    };
    let binding = if b.purpose == "holder" {
        let Some(v) = client_binding(&req, &p).await? else {
            return error(400, "invalid_client");
        };
        if row["client_binding"] != v.thumbprint
            || b.public_key.thumbprint().map_err(|_| server_error())? == v.thumbprint
        {
            return error(400, "invalid_client");
        }
        Some(v)
    } else {
        None
    };
    let nonce = if b.purpose == "holder" {
        let Some(nonce) = b.c_nonce.as_ref().filter(|s| valid_id(s)) else {
            return error(400, "invalid_nonce");
        };
        if row["nonce_hash"] != hash(nonce) {
            return error(400, "invalid_nonce");
        }
        Some(nonce)
    } else {
        if b.c_nonce.is_some() {
            return error(400, "invalid_request");
        }
        None
    };
    if mikaki_identity::attester_proof::verify(
        &b.proof,
        &b.client_id,
        &p.issuer,
        &b.challenge,
        &b.purpose,
        &b.public_key,
        now()?,
    )
    .is_err()
    {
        return error(400, "invalid_attestation_proof");
    }
    let challenge = B64
        .decode(&b.challenge)
        .ok()
        .and_then(|v| v.try_into().ok());
    let Some(challenge) = challenge else {
        return error(400, "invalid_challenge");
    };
    let evidence = match UntrustedAndroidEvidence::collect(
        &challenge,
        b.public_key.clone(),
        b.certificate_chain.clone(),
    ) {
        Ok(e) => e,
        Err(_) => return error(400, "invalid_android_evidence"),
    };
    let v = match verdict(&ctx, &p, &b, evidence).await {
        Ok(Some(v)) => v,
        _ => return error(503, "android_verification_unavailable"),
    };
    let at = now()?;
    let mut until = at
        .saturating_add(if b.purpose == "client" { 300 } else { 60 })
        .min(v.expires_at)
        .min(p.deadline);
    if let Some(v) = &binding {
        until = until.min(v.expires_at);
    }
    if let Some(nonce) = nonce {
        let expiry=db.prepare("SELECT expires_at FROM identity_nonce WHERE nonce_hash=?1 AND used=0 AND expires_at>unixepoch()")
            .bind(&[js(&hash(nonce))])?.first::<Value>(None).await?.and_then(|v|v["expires_at"].as_u64());
        let Some(expiry) = expiry else {
            return error(400, "invalid_nonce");
        };
        until = until.min(expiry);
    }
    if until <= at {
        return error(503, "attester_unavailable");
    }
    let claims = if let Some(nonce) = nonce {
        json!({"iat":at,"exp":until,"nonce":nonce,"attested_keys":[b.public_key]})
    } else {
        json!({"iss":p.issuer,"sub":b.client_id,"iat":at,"exp":until,"cnf":{"jwk":b.public_key},"attester_policy_hash":p.fingerprint})
    };
    let typ = if nonce.is_some() {
        "key-attestation+jwt"
    } else {
        "oauth-client-attestation+jwt"
    };
    let jwt = Zeroizing::new(
        issuance::sign_jwt(
            &p.key,
            json!({"typ":typ,"alg":"ES256","x5c":p.signing.chain}),
            claims,
        )
        .map_err(|_| server_error())?,
    );
    if jwt.len() > if nonce.is_some() { 16384 } else { 24576 } {
        return error(503, "attester_unavailable");
    }
    if !wallet::accept_attestation(&ctx, &b.client_id, &binding).await? {
        return error(400, "invalid_client");
    }
    let accepted=db.prepare("UPDATE identity_attester_challenge SET used=1 WHERE challenge_hash=?1 AND client_id=?2 AND purpose=?3 AND policy_hash=?4 AND used=0 AND expires_at>unixepoch() AND (?5 IS NULL OR EXISTS(SELECT 1 FROM identity_nonce WHERE nonce_hash=?5 AND used=0 AND expires_at>unixepoch()))")
        .bind(&[js(&hash(&b.challenge)),js(&b.client_id),js(&b.purpose),js(&p.fingerprint),nonce.map(|n|js(&hash(n))).unwrap_or(JsValue::NULL)])?.run().await?;
    if accepted.meta()?.and_then(|m| m.changes) != Some(1) {
        return error(400, "invalid_challenge");
    }
    response(json!({"attestation":&*jwt,"expires_in":until.saturating_sub(now()?)}))
}
