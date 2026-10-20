//! Authenticated device registry and independent journal head adapter.
//! Shared by local qualification and the explicitly enabled product beta host.
use crate::messaging_crypto::{self as profile, Identity, MAX_SAFE, Signer};
use crate::vault_http::{error, same_origin};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast, JsValue};
use worker::{D1Database, D1SessionConstraint, Env, Method, Request, Response, Result};

#[path = "messaging_delivery.rs"]
mod delivery;

fn text(s: &str) -> JsValue {
    JsValue::from_str(s)
}
fn num(n: u64) -> JsValue {
    JsValue::from_f64(n as f64)
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let crypto = js_sys::Reflect::get(&js_sys::global(), &"crypto".into())?
        .dyn_into::<web_sys::Crypto>()
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let mut bytes = [0; N];
    crypto.get_random_values_with_u8_array(&mut bytes)?;
    Ok(bytes)
}
fn new_id() -> Result<String> {
    let mut b = random::<16>()?;
    b[6] = (b[6] & 15) | 64;
    b[8] = (b[8] & 63) | 128;
    let h = b.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
fn json(value: &impl Serialize) -> Result<Response> {
    Response::builder()
        .with_header("Cache-Control", "no-store, no-transform")?
        .from_json(value)
}
#[derive(Deserialize)]
struct Actor {
    secret_hash: String,
}
async fn actor(db: &D1Database, secret: &str) -> Result<Option<Actor>> {
    db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare("SELECT * FROM messaging_live_owner WHERE secret_hash=?1")
        .bind(&[text(secret)])?
        .first(None)
        .await
}
async fn account(
    request: &mut Request,
    db: &D1Database,
    a: &Actor,
    issuer: &str,
) -> Result<Response> {
    if request.method() == Method::Post {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Empty {}
        if let Err(response) = body::<Empty>(request, 64).await {
            return Ok(response);
        }
        db.prepare("INSERT INTO messaging_account(owner_id,account_id) SELECT account_id,?2 FROM messaging_live_owner WHERE secret_hash=?1 ON CONFLICT(owner_id) DO NOTHING")
            .bind(&[text(&a.secret_hash),text(&new_id()?)])?.run().await?;
    }
    #[derive(Deserialize, Serialize)]
    struct Account {
        account_id: String,
    }
    let current = db.with_session_constraint(D1SessionConstraint::FirstPrimary)?.prepare("SELECT m.account_id FROM messaging_account m JOIN messaging_live_owner a ON a.account_id=m.owner_id WHERE a.secret_hash=?1")
        .bind(&[text(&a.secret_hash)])?.first::<Account>(None).await?;
    match current {
        Some(value) => json(&serde_json::json!({"issuer":issuer,"account_id":value.account_id})),
        None => error(404, "messaging_account_missing"),
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Start {
    device_id: String,
    public_key: String,
    storage_id: String,
    key_id: String,
    expected_revision: u64,
}
#[derive(Deserialize)]
struct Enrollment {
    enrollment_id: String,
    request_hash: String,
    device_id: String,
    generation: u64,
    public_key: String,
    storage_id: String,
    key_id: String,
    nonce: String,
    expires_at: u64,
    consumed_proof: Option<String>,
    account_id: String,
    now: u64,
}
async fn enrollment(db: &D1Database, id: &str, secret: &str) -> Result<Option<Enrollment>> {
    db.with_session_constraint(D1SessionConstraint::FirstPrimary)?.prepare("SELECT e.*,m.account_id,unixepoch() AS now FROM messaging_enrollment e JOIN messaging_account m ON m.owner_id=e.owner_id JOIN messaging_live_owner a ON a.account_id=e.owner_id AND a.secret_hash=e.secret_hash AND a.credential_id=e.credential_id WHERE e.enrollment_id=?1 AND e.secret_hash=?2")
        .bind(&[text(id),text(secret)])?.first(None).await
}
impl Enrollment {
    fn identity(&self, issuer: &str) -> Identity {
        Identity {
            issuer: issuer.into(),
            account_id: self.account_id.clone(),
            device_id: self.device_id.clone(),
            generation: self.generation,
        }
    }
    fn response(&self, issuer: &str) -> Result<Response> {
        let identity = self.identity(issuer);
        json(
            &serde_json::json!({"enrollment_id":self.enrollment_id,"device":identity,"nonce":self.nonce,"expires_at":self.expires_at,"scope":{"device":identity,"storage_id":self.storage_id,"key_id":self.key_id,"fingerprint":identity.fingerprint(&self.public_key)?}}),
        )
    }
}
#[derive(Deserialize)]
struct Device {
    account_id: String,
    device_id: String,
    generation: u64,
    revision: u64,
    public_key: String,
    status: String,
    enrollment_id: String,
    scope_hash: String,
    head_revision: u64,
    head_hash: Option<String>,
    now: u64,
}
async fn device(db: &D1Database, id: &str, secret: &str) -> Result<Option<Device>> {
    db.with_session_constraint(D1SessionConstraint::FirstPrimary)?.prepare("SELECT g.*,unixepoch() AS now FROM messaging_generation g JOIN messaging_device_head h ON h.account_id=g.account_id AND h.device_id=g.device_id AND h.generation=g.generation JOIN messaging_account m ON m.account_id=g.account_id JOIN messaging_live_owner a ON a.account_id=m.owner_id WHERE g.device_id=?1 AND a.secret_hash=?2")
        .bind(&[text(id),text(secret)])?.first(None).await
}
async fn binding(
    db: &D1Database,
    issuer: &str,
    signer: &Signer,
    id: &str,
    secret: &str,
    expected: Option<&str>,
) -> Result<Response> {
    let Some(d) = device(db, id, secret).await? else {
        return error(404, "device_missing");
    };
    if expected.is_some_and(|e| d.enrollment_id != e) {
        return error(409, "device_generation_changed");
    }
    let identity = Identity {
        issuer: issuer.into(),
        account_id: d.account_id.clone(),
        device_id: d.device_id.clone(),
        generation: d.generation,
    };
    let token = signer
        .binding(&identity, &d.public_key, d.revision, &d.status, d.now)
        .await?;
    // Signing awaits must not turn a revoked/replaced registry snapshot into a
    // fresh active lease. Recheck the exact head and authority before return.
    let Some(current) = device(db, id, secret).await? else {
        return error(403, "authority_changed");
    };
    if current.enrollment_id != d.enrollment_id
        || current.revision != d.revision
        || current.status != d.status
        || current.now >= d.now + 300
    {
        return error(409, "device_changed");
    }
    json(&serde_json::json!({"binding":token}))
}
async fn body<T: serde::de::DeserializeOwned>(
    request: &mut Request,
    max: usize,
) -> std::result::Result<T, Response> {
    if request
        .headers()
        .get("Content-Type")
        .ok()
        .flatten()
        .as_deref()
        != Some("application/json")
    {
        return Err(error(415, "json_required").unwrap());
    }
    let body = crate::read_bounded_body(request, max)
        .await
        .map_err(|_| error(413, "body_too_large_or_invalid").unwrap())?;
    serde_json::from_str(&body).map_err(|_| error(400, "invalid_body").unwrap())
}
async fn start(
    request: &mut Request,
    db: &D1Database,
    a: &Actor,
    issuer: &str,
) -> Result<Response> {
    let Some(operation) = request
        .headers()
        .get("X-Operation-ID")?
        .filter(|v| profile::uuid(v))
    else {
        return error(400, "operation_id_required");
    };
    let value: Start = match body(request, 1024).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if !profile::uuid(&value.device_id)
        || !profile::uuid(&value.storage_id)
        || !profile::uuid(&value.key_id)
        || profile::decode(&value.public_key, 32).is_err()
        || value.expected_revision >= MAX_SAFE
    {
        return error(400, "invalid_enrollment");
    }
    let hash = profile::digest(&serde_json::to_vec(&value)?);
    if let Some(previous) = enrollment(db, &operation, &a.secret_hash).await? {
        if previous.request_hash != hash {
            return error(409, "operation_id_conflict");
        }
        if previous.expires_at <= previous.now && previous.consumed_proof.is_none() {
            return error(410, "enrollment_expired");
        }
        return previous.response(issuer);
    }
    db.prepare("INSERT INTO messaging_account(owner_id,account_id) SELECT account_id,?2 FROM messaging_live_owner WHERE secret_hash=?1 ON CONFLICT(owner_id) DO NOTHING")
        .bind(&[text(&a.secret_hash),text(&new_id()?)])?.run().await?;
    db.prepare(include_str!("messaging-sql/challenge.sql"))
        .bind(&[
            text(&operation),
            text(&a.secret_hash),
            text(&hash),
            text(&value.device_id),
            num(value.expected_revision),
            text(&value.public_key),
            text(&value.storage_id),
            text(&value.key_id),
            text(&B64.encode(random::<32>()?)),
        ])?
        .run()
        .await?;
    let Some(row) = enrollment(db, &operation, &a.secret_hash).await? else {
        return error(409, "enrollment_precondition_or_limit");
    };
    if row.request_hash != hash {
        return error(409, "operation_id_conflict");
    }
    row.response(issuer)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Complete {
    proof: String,
}
async fn complete(
    request: &mut Request,
    db: &D1Database,
    a: &Actor,
    issuer: &str,
    signer: &Signer,
    id: &str,
) -> Result<Response> {
    let value: Complete = match body(request, 9216).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    let Some(row) = enrollment(db, id, &a.secret_hash).await? else {
        return error(404, "enrollment_missing");
    };
    let proof_hash = profile::digest(value.proof.as_bytes());
    if let Some(old) = &row.consumed_proof {
        if old != &proof_hash {
            return error(409, "proof_conflict");
        }
        return binding(db, issuer, signer, &row.device_id, &a.secret_hash, Some(id)).await;
    }
    if row.expires_at <= row.now {
        return error(410, "enrollment_expired");
    }
    let identity = row.identity(issuer);
    let (proof_iat, proof_exp) = match profile::verify_proof(
        &value.proof,
        &identity,
        &row.public_key,
        &row.nonce,
        row.now,
    )
    .await
    {
        Ok(window) => window,
        Err(_) => return error(400, "invalid_registration_proof"),
    };
    let args = [text(id), text(&a.secret_hash)];
    let completed = db
        .batch(vec![
            db.prepare(include_str!("messaging-sql/retire.sql"))
                .bind(&args)?,
            db.prepare(include_str!("messaging-sql/complete.sql"))
                .bind(&[
                    args[0].clone(),
                    args[1].clone(),
                    text(&identity.fingerprint(&row.public_key)?),
                    text(&identity.scope(&row.public_key, &row.storage_id, &row.key_id)?),
                    num(proof_iat),
                    num(proof_exp),
                ])?,
            db.prepare(include_str!("messaging-sql/publish.sql"))
                .bind(&args)?,
            db.prepare(include_str!("messaging-sql/consume.sql"))
                .bind(&[args[0].clone(), args[1].clone(), text(&proof_hash)])?,
            db.prepare(include_str!("messaging-sql/guard.sql")).bind(&[
                args[0].clone(),
                args[1].clone(),
                text(&proof_hash),
                num(proof_iat),
                num(proof_exp),
            ])?,
        ])
        .await;
    if completed.is_err() {
        // A lost D1 response is not evidence that the transaction rolled back.
        // Reconcile the durable proof receipt before reporting an outcome.
        let Some(latest) = enrollment(db, id, &a.secret_hash).await? else {
            return error(403, "authority_changed");
        };
        if let Some(accepted) = latest.consumed_proof {
            if accepted != proof_hash {
                return error(409, "proof_conflict");
            }
            return binding(db, issuer, signer, &row.device_id, &a.secret_hash, Some(id)).await;
        }
        #[derive(Deserialize)]
        struct Ready {
            enrollment_id: String,
        }
        let ready = db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
            .prepare("SELECT enrollment_id FROM messaging_enrollment_ready WHERE enrollment_id=?1 AND secret_hash=?2")
            .bind(&args)?.first::<Ready>(None).await?;
        if ready.as_ref().is_none_or(|r| r.enrollment_id != id) || latest.now >= proof_exp {
            return error(409, "enrollment_conflict");
        }
        return error(503, "enrollment_unconfirmed");
    }
    binding(db, issuer, signer, &row.device_id, &a.secret_hash, Some(id)).await
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Head {
    revision: u64,
    hash: Option<String>,
}
impl Head {
    fn valid(&self) -> bool {
        self.revision <= MAX_SAFE
            && if self.revision == 0 {
                self.hash.is_none()
            } else {
                self.hash
                    .as_ref()
                    .is_some_and(|h| profile::decode(h, 32).is_ok())
            }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cas {
    expected: Head,
    next: Head,
}
const SCOPE_SELECT: &str = "SELECT g.*,unixepoch() AS now FROM messaging_generation g JOIN messaging_device_head h ON h.account_id=g.account_id AND h.device_id=g.device_id AND h.generation=g.generation JOIN messaging_account m ON m.account_id=g.account_id JOIN messaging_live_owner a ON a.account_id=m.owner_id WHERE g.scope_hash=?1 AND g.status='active' AND a.secret_hash=?2";
async fn witness(request: &mut Request, db: &D1Database, a: &Actor, id: &str) -> Result<Response> {
    if profile::decode(id, 32).is_err() {
        return error(400, "invalid_scope");
    }
    if request.method() == Method::Put {
        let value: Cas = match body(request, 1024).await {
            Ok(v) => v,
            Err(r) => return Ok(r),
        };
        if !value.expected.valid()
            || !value.next.valid()
            || value.expected.revision >= MAX_SAFE
            || value.next.revision != value.expected.revision + 1
        {
            return error(400, "invalid_head_transition");
        }
        db.prepare("UPDATE messaging_generation SET head_revision=?3,head_hash=?4 WHERE scope_hash=?1 AND head_revision=?5 AND head_hash IS ?6 AND status='active' AND EXISTS(SELECT 1 FROM messaging_device_head h JOIN messaging_account m ON m.account_id=h.account_id JOIN messaging_live_owner a ON a.account_id=m.owner_id WHERE h.account_id=messaging_generation.account_id AND h.device_id=messaging_generation.device_id AND h.generation=messaging_generation.generation AND a.secret_hash=?2)")
            .bind(&[text(id),text(&a.secret_hash),num(value.next.revision),text(value.next.hash.as_deref().unwrap_or_default()),num(value.expected.revision),value.expected.hash.as_deref().map(text).unwrap_or(JsValue::NULL)])?.run().await?;
    }
    let Some(d) = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(SCOPE_SELECT)
        .bind(&[text(id), text(&a.secret_hash)])?
        .first::<Device>(None)
        .await?
    else {
        return error(404, "scope_missing_or_inactive");
    };
    debug_assert_eq!(d.scope_hash, id);
    json(&Head {
        revision: d.head_revision,
        hash: d.head_hash,
    })
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoke {
    expected_revision: u64,
}
async fn revoke(
    request: &mut Request,
    db: &D1Database,
    a: &Actor,
    issuer: &str,
    signer: &Signer,
    id: &str,
) -> Result<Response> {
    let value: Revoke = match body(request, 128).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if value.expected_revision == 0 || value.expected_revision >= MAX_SAFE {
        return error(400, "invalid_revision");
    }
    db.batch(vec![
        db.prepare("UPDATE messaging_generation SET status='revoked',revision=revision+1 WHERE device_id=?1 AND revision=?3 AND EXISTS(SELECT 1 FROM messaging_device_head h JOIN messaging_account m ON m.account_id=h.account_id JOIN messaging_live_owner a ON a.account_id=m.owner_id WHERE h.account_id=messaging_generation.account_id AND h.device_id=messaging_generation.device_id AND h.generation=messaging_generation.generation AND h.revision=?3 AND a.secret_hash=?2) AND status='active'")
            .bind(&[text(id),text(&a.secret_hash),num(value.expected_revision)])?,
        db.prepare("UPDATE messaging_device_head SET revision=revision+1 WHERE device_id=?1 AND revision=?3 AND EXISTS(SELECT 1 FROM messaging_generation g JOIN messaging_account m ON m.account_id=g.account_id JOIN messaging_live_owner a ON a.account_id=m.owner_id WHERE g.account_id=messaging_device_head.account_id AND g.device_id=messaging_device_head.device_id AND g.generation=messaging_device_head.generation AND g.status='revoked' AND g.revision=?3+1 AND a.secret_hash=?2)")
            .bind(&[text(id),text(&a.secret_hash),num(value.expected_revision)])?,
    ]).await?;
    let Some(d) = device(db, id, &a.secret_hash).await? else {
        return error(404, "device_missing");
    };
    if d.status != "revoked" || d.revision != value.expected_revision + 1 {
        return error(409, "device_changed");
    }
    binding(db, issuer, signer, id, &a.secret_hash, None).await
}
async fn dispatch(mut request: Request, env: &Env) -> Result<Response> {
    let url = request.url()?;
    let issuer = env.var("MIKAKI_ISSUER")?.to_string();
    if !profile::origin(&issuer) || url.origin().ascii_serialization() != issuer {
        return error(400, "invalid_origin");
    }
    if url.query().is_some() {
        return error(400, "query_not_supported");
    }
    let path = url.path();
    let parts: Vec<_> = path.split('/').collect();
    let method = request.method();
    let route = match parts.as_slice() {
        ["", "messaging", "account"] if method == Method::Get || method == Method::Post => 5,
        ["", "messaging", "enrollments"] if method == Method::Post => 0,
        ["", "messaging", "enrollments", id, "complete"]
            if method == Method::Post && profile::uuid(id) =>
        {
            1
        }
        ["", "messaging", "devices", id, "binding"]
            if method == Method::Get && profile::uuid(id) =>
        {
            2
        }
        ["", "messaging", "devices", id, "revoke"]
            if method == Method::Post && profile::uuid(id) =>
        {
            3
        }
        ["", "messaging", "heads", _] if method == Method::Get || method == Method::Put => 4,
        ["", "messaging", "channels", ..] => 6,
        _ => return error(404, "not_found"),
    };
    // Mutations require exact Origin; reads also reject cross-origin browser
    // initiators and supplied nonmatching Origin, without granting CORS access.
    if method != Method::Get && !same_origin(&request)? {
        return error(403, "origin_required");
    }
    if method == Method::Get
        && (request.headers().get("Origin")?.is_some() && !same_origin(&request)?
            || request.headers().get("Sec-Fetch-Site")?.as_deref() == Some("cross-site"))
    {
        return error(403, "origin_required");
    }
    let Some(cookie) = crate::browser_cookie(&request, "__Host-op-sso")? else {
        return error(401, "authentication_required");
    };
    let secret = profile::digest(cookie.as_bytes());
    let db = env.d1("DB")?;
    let Some(a) = actor(&db, &secret).await? else {
        return error(401, "authentication_required");
    };
    let signer = if route <= 3 {
        Some(Signer::load(env).await?)
    } else {
        None
    };
    match route {
        6 => delivery::dispatch(&mut request, &db, &a, env, &issuer).await,
        5 => account(&mut request, &db, &a, &issuer).await,
        0 => start(&mut request, &db, &a, &issuer).await,
        1 => {
            complete(
                &mut request,
                &db,
                &a,
                &issuer,
                signer.as_ref().unwrap(),
                parts[3],
            )
            .await
        }
        2 => {
            binding(
                &db,
                &issuer,
                signer.as_ref().unwrap(),
                parts[3],
                &secret,
                None,
            )
            .await
        }
        3 => {
            revoke(
                &mut request,
                &db,
                &a,
                &issuer,
                signer.as_ref().unwrap(),
                parts[3],
            )
            .await
        }
        _ => witness(&mut request, &db, &a, parts[3]).await,
    }
}
pub async fn fetch(request: Request, env: &Env) -> Result<Response> {
    match dispatch(request, env).await {
        Ok(r) => Ok(r),
        Err(_) => error(503, "messaging_unavailable"),
    }
}

/// Actual Owner Vault handlers for the local custody qualifier, never mounted
/// by the product messaging router or a synthetic authentication facade.
pub fn vault_qualification_routes(router: worker::Router<'_, ()>) -> worker::Router<'_, ()> {
    router
        .get_async("/vault/session", crate::vault_ui::session)
        .get_async("/vault/owner-key", crate::vault_owner_keys::get)
        .put_async("/vault/owner-key", crate::vault_owner_keys::create)
}
