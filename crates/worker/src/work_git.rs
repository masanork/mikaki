//! Fixed productive Git adapter. The caller never receives the custodied bearer.
use crate::work_store::{WorkStore, credential_key};
use futures_util::StreamExt;
use mikaki_auth::work::{CredentialObservation, CredentialPurpose, Digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use worker::{Env, Method, Request, RequestInit, Response};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const MAX_BYTES: usize = 8 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format_version: u64,
    role: String,
    r#ref: String,
    commit: String,
    tree: String,
    objects: u64,
    object_bytes: u64,
    inventory_sha256: String,
    pack_bytes: u64,
    pack_sha256: String,
    request_sha256: String,
}
fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn packet(s: &str) -> String {
    format!("{:04x}{s}", s.len() + 4)
}
fn prefix(m: &Manifest, purpose: CredentialPurpose) -> Vec<u8> {
    if purpose == CredentialPurpose::Upload {
        format!(
            "{}0000",
            packet(&format!(
                "{} {} {}\0report-status\n",
                "0".repeat(40),
                m.commit,
                m.r#ref
            ))
        )
        .into_bytes()
    } else {
        format!(
            "{}0000{}",
            packet(&format!("want {}\n", m.commit)),
            packet("done\n")
        )
        .into_bytes()
    }
}
async fn metadata(env: &Env, attempt: &str) -> Result<serde_json::Value> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(
        serde_json::json!({"attempt_id":attempt}).to_string().into(),
    ));
    let mut r = env
        .service("WORK_GIT_METADATA")?
        .fetch("https://private.invalid/git-metadata", Some(init))
        .await?;
    if r.status_code() != 200 {
        return Err("git_denied".into());
    }
    let mut bytes = Vec::new();
    let mut stream = r.stream()?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > 8192 {
            return Err("git_metadata_capacity".into());
        }
        bytes.extend(chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}
async fn plan(
    store: &WorkStore,
    env: &Env,
    attempt: &str,
    m: &Manifest,
    body: &[u8],
) -> Result<serde_json::Value> {
    let checkpoint = store.current_authority_checkpoint().await?;
    let records = metadata(env, attempt).await?;
    let r = &records["mint"];
    let mint = &r["plan"];
    let o = &r["observation"];
    if r["state"] != "custodied"
        || r["cleanup_requested"] != false
        || r["revoke_acknowledged"] != false
        || mint["attempt_id"] != attempt
    {
        return Err("git_custody_unavailable".into());
    }
    let a = store.credential_plan(attempt).await?;
    if a.purpose() == CredentialPurpose::Initial
        || mint["digest"] != a.digest().to_hex()
        || mint["role"] != a.role().name()
        || mint["purpose"] != a.purpose().name()
    {
        return Err("git_binding_mismatch".into());
    }
    let p = store.preparation(a.preparation_id()).await?;
    let (namespace, name) = p.credential_destination(a.role());
    let d = store.disclosure(p.disclosure_digest()).await?;
    let (commit, tree) = d.copy_binding(a.role());
    if m.format_version != 1
        || m.role != a.role().name()
        || m.commit.len() != 40
        || m.commit != commit
        || m.tree != tree
        || m.r#ref
            != if m.role == "task" {
                "refs/heads/work"
            } else {
                "refs/heads/snapshot"
            }
        || m.objects == 0
        || m.objects > 65536
        || m.object_bytes > 67108864
        || m.pack_bytes < 32
        || m.pack_bytes > MAX_BYTES as u64 - 256
        || mint["namespace"] != namespace
        || mint["name"] != name
        || mint["repo_id"].as_str() != a.expected_repo_id()
    {
        return Err("git_binding_mismatch".into());
    }
    for v in [&m.inventory_sha256, &m.pack_sha256, &m.request_sha256] {
        Digest::parse_hex(v)?;
    }
    let expires = o["expires_at"].as_u64().ok_or("git_binding_mismatch")?;
    if expires <= (js_sys::Date::now() / 1000.0) as u64
        || expires > a.deadline()
        || Some(expires) > mint["expires_at"].as_u64()
    {
        return Err("git_expired".into());
    }
    let observation = CredentialObservation::from_observed(
        &a,
        o["repo_id"].as_str().ok_or("git_binding_mismatch")?,
        o["token_id"].as_str().ok_or("git_binding_mismatch")?,
        a.purpose().scope(),
        Some(expires),
    )?;
    if o["scope"] != serde_json::to_value(a.purpose().scope())? {
        return Err("git_binding_mismatch".into());
    }
    let key = credential_key(
        env,
        mint["key_version"].as_u64().ok_or("git_binding_mismatch")?,
    )?;
    if mint["key_fingerprint"] != key.fingerprint().to_hex() {
        return Err("git_key_mismatch".into());
    }
    store
        .credential_for_git(attempt, &key, &observation)
        .await?;
    let prefix = prefix(m, a.purpose());
    if !body.starts_with(&prefix) {
        return Err("git_payload_mismatch".into());
    }
    let request_sha256 = sha(body);
    if a.purpose() == CredentialPurpose::Upload {
        let pack = &body[prefix.len()..];
        if request_sha256 != m.request_sha256
            || pack.len() != m.pack_bytes as usize
            || sha(pack) != m.pack_sha256
            || pack.get(..4) != Some(b"PACK")
            || pack.get(4..8) != Some(&2u32.to_be_bytes())
            || pack.get(8..12) != Some(&(m.objects as u32).to_be_bytes())
        {
            return Err("git_payload_mismatch".into());
        }
    } else if body != prefix {
        return Err("git_payload_mismatch".into());
    }
    let mut plan = serde_json::json!({"format_version":1,"effect":"git.copy","mint":mint,"observation":o,"manifest":m,"checkpoint":checkpoint,"request_sha256":request_sha256});
    plan["digest"] = sha(&serde_json::to_vec(&serde_json::json!([
        "mikaki-git-copy-plan-v1",
        plan
    ]))?)
    .into();
    if store.current_authority_checkpoint().await? != checkpoint {
        return Err("git_stale".into());
    }
    Ok(plan)
}
pub async fn handle(mut request: Request, env: &Env) -> worker::Result<Response> {
    if request.method() != Method::Post || request.url()?.path() != "/git-effect" {
        return Response::empty().map(|r| r.with_status(404));
    }
    match execute(&mut request, env).await {
        Ok(r) => Ok(r),
        Err(_) => Response::builder()
            .with_status(409)
            .with_header("Cache-Control", "no-store")?
            .from_json(&serde_json::json!({"error":"git_unavailable_or_denied"})),
    }
}
async fn execute(request: &mut Request, env: &Env) -> Result<Response> {
    if env.var("WORK_GIT_STORE_ENABLED")?.to_string() != "true"
        || request.headers().has("Authorization")?
    {
        return Err("git_disabled".into());
    }
    let action = request
        .headers()
        .get("X-Mikaki-Action")?
        .ok_or("git_invalid")?;
    let attempt = request
        .headers()
        .get("X-Mikaki-Attempt-ID")?
        .ok_or("git_invalid")?;
    let encoded = request
        .headers()
        .get("X-Mikaki-Copy")?
        .ok_or("git_invalid")?;
    if !matches!(action.as_str(), "plan" | "execute") {
        return Err("git_invalid".into());
    }
    mikaki_webauthn::strict_json(&encoded, 2048, 8).map_err(|_| "git_invalid")?;
    let m: Manifest = serde_json::from_str(&encoded)?;
    let mut stream = request.stream()?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > MAX_BYTES {
            return Err("git_capacity".into());
        }
        body.extend(chunk);
    }
    let store = WorkStore::from_env(env)?;
    let planned = plan(&store, env, &attempt, &m, &body).await?;
    if action == "plan" {
        return Ok(Response::builder()
            .with_header("Cache-Control", "no-store")?
            .from_json(&planned)?);
    }
    let records = metadata(env, &attempt).await?;
    let retained = &records["git"];
    if retained["consumed"] != false || retained["plan"] != planned {
        return Err("git_admission_missing".into());
    }
    let a = store.credential_plan(&attempt).await?;
    let o = &planned["observation"];
    let observation = CredentialObservation::from_observed(
        &a,
        o["repo_id"].as_str().ok_or("git_invalid")?,
        o["token_id"].as_str().ok_or("git_invalid")?,
        a.purpose().scope(),
        o["expires_at"].as_u64(),
    )?;
    let key = credential_key(
        env,
        planned["mint"]["key_version"]
            .as_u64()
            .ok_or("git_invalid")?,
    )?;
    let secret = store
        .credential_for_git(&attempt, &key, &observation)
        .await?;
    if store.current_authority_checkpoint().await?
        != serde_json::from_value(planned["checkpoint"].clone())?
    {
        return Err("git_stale".into());
    }
    let account = env.var("WORK_ARTIFACTS_ACCOUNT")?.to_string();
    if account.len() != 32
        || !account
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("git_invalid".into());
    }
    let headers = worker::Headers::new();
    let auth = Zeroizing::new(format!(
        "Bearer {}",
        std::str::from_utf8(secret.service_bytes())?
    ));
    headers.set("Authorization", &auth)?;
    headers.set("X-Mikaki-Attempt-ID", &attempt)?;
    headers.set(
        "X-Mikaki-Git-Digest",
        planned["digest"].as_str().ok_or("git_invalid")?,
    )?;
    let p = store.preparation(a.preparation_id()).await?;
    let (namespace, name) = p.credential_destination(a.role());
    let url = format!(
        "https://{account}.artifacts.cloudflare.net/git/{namespace}/{name}.git/{}",
        if a.purpose() == CredentialPurpose::Upload {
            "git-receive-pack"
        } else {
            "git-upload-pack"
        }
    );
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(js_sys::Uint8Array::from(body.as_slice()).into()));
    let mut result = env
        .service("WORK_GIT_TRANSPORT")?
        .fetch_request(Request::new_with_init(&url, &init)?)
        .await?;
    if result.status_code() != 200 {
        return Err("git_unknown".into());
    }
    // Final authority observation fences success; it cannot retract a send already in flight.
    store
        .credential_for_git(&attempt, &key, &observation)
        .await?;
    let mut bytes = Vec::new();
    let mut stream = result.stream()?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > MAX_BYTES {
            return Err("git_capacity".into());
        }
        bytes.extend(chunk);
    }
    let mut response = Response::from_bytes(bytes)?;
    response.headers_mut().set("Cache-Control", "no-store")?;
    response
        .headers_mut()
        .set("Content-Type", "application/octet-stream")?;
    response.headers_mut().set(
        "X-Mikaki-Git-Plan",
        planned["digest"].as_str().ok_or("git_invalid")?,
    )?;
    Ok(response)
}
