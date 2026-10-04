//! Dedicated recipient key boundary. No secret is returned to the OP Worker.

pub mod envelope;
pub mod envelope_v2;

#[cfg(any(test, target_arch = "wasm32"))]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(any(test, target_arch = "wasm32"))]
use ml_kem::{DecapsulationKey, MlKem768, Seed, kem::KeyExport};
#[cfg(any(test, target_arch = "wasm32"))]
use sha2::{Digest, Sha256};
#[cfg(any(test, target_arch = "wasm32"))]
use zeroize::Zeroizing;

#[cfg(target_arch = "wasm32")]
use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

#[cfg(any(test, target_arch = "wasm32"))]
const SECRET_PREFIX: &str = "VAULT_USERINFO_MLKEM_";

#[cfg(any(test, target_arch = "wasm32"))]
fn valid_binding(name: &str) -> bool {
    name.starts_with(SECRET_PREFIX)
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(any(test, target_arch = "wasm32"))]
fn decode_seed(encoded_seed: &str) -> Option<Zeroizing<[u8; 64]>> {
    let seed_bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded_seed).ok()?);
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(&seed_bytes));
    if canonical.as_str() != encoded_seed {
        return None;
    }
    let seed = seed_bytes.as_slice().try_into().ok()?;
    Some(Zeroizing::new(seed))
}

#[cfg(any(test, target_arch = "wasm32"))]
fn public_key_matches(key_id: &str, public_key: &[u8], encoded_seed: &str) -> bool {
    if key_id.len() != 43 || public_key.len() != 1184 {
        return false;
    }
    let Some(seed) = decode_seed(encoded_seed) else {
        return false;
    };
    let derived = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
    let derived_public = derived.encapsulation_key().to_bytes();
    URL_SAFE_NO_PAD.encode(Sha256::digest(derived_public)) == key_id
        && derived_public.as_slice() == public_key
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct RecipientKey {
    key_id: String,
    service_id: String,
    algorithm: String,
    public_key: Vec<u8>,
    secret_ref: String,
    state: String,
    generation: i64,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeValidation {
    origin: String,
    account_id: String,
    revision: u64,
    ciphertext: String,
    frame: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NameRequest {
    access_hash: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
struct NameRelease {
    storage_version: i64,
    source_origin: String,
    vault_id: String,
    collection_id: String,
    record_id: String,
    kind: String,
    key_generation: i64,
    owner_key_revision: i64,
    system_grant_version: i64,
    envelope_id: String,
    #[serde(default)]
    ciphertext: Option<Vec<u8>>,
    account_id: String,
    client_id: String,
    revision: i64,
    release_version: i64,
    object_key: String,
    ciphertext_sha256: String,
    frame: Vec<u8>,
    key_id: String,
    public_key: Vec<u8>,
    secret_ref: String,
    generation: i64,
}

#[cfg(target_arch = "wasm32")]
#[derive(Serialize)]
struct NameResponse<'a> {
    name: &'a str,
}

// This query is the release authority at both the decrypt preflight and the
// conditional disclosure-audit write. The caller supplies only a token hash.
#[cfg(target_arch = "wasm32")]
const ACTIVE_NAME_RELEASE: &str = include_str!("active_name_release.sql");

#[cfg(target_arch = "wasm32")]
const AUDIT_NAME_RELEASE: &str = include_str!("audit_name_release.sql");
#[cfg(target_arch = "wasm32")]
const ACTIVE_NAME_RECORD_RELEASE: &str = include_str!("active_name_record_release.sql");
#[cfg(target_arch = "wasm32")]
const AUDIT_NAME_RECORD_RELEASE: &str = include_str!("audit_name_record_release.sql");

#[cfg(target_arch = "wasm32")]
fn legacy_store(env: &worker::Env) -> bool {
    env.var("MIKAKI_LEGACY_CLAIM_STORE")
        .is_ok_and(|value| value.to_string() == "local-test")
}

#[cfg(target_arch = "wasm32")]
async fn store_call(
    env: &worker::Env,
    path: &str,
    input: serde_json::Value,
) -> worker::Result<serde_json::Value> {
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(JsValue::from_str(&input.to_string())));
    init.headers.set("Content-Type", "application/json")?;
    let mut response = env
        .service("CLAIM_STORE")?
        .fetch(format!("https://store.internal/{path}"), Some(init))
        .await?;
    if response.status_code() != 200 {
        return Err(worker::Error::RustError("claim_store_unavailable".into()));
    }
    response.json().await
}

#[cfg(target_arch = "wasm32")]
async fn load_key(
    env: &worker::Env,
    key_id: &str,
    active: bool,
) -> worker::Result<Option<RecipientKey>> {
    if env.service("CLAIM_STORE").is_ok() {
        return serde_json::from_value(
            store_call(
                env,
                "key",
                serde_json::json!({"key_id":key_id,"active":active}),
            )
            .await?,
        )
        .map_err(|_| worker::Error::RustError("invalid_claim_store_response".into()));
    }
    if !legacy_store(env) {
        return Err(worker::Error::RustError("claim_store_required".into()));
    }
    let sql = format!(
        "SELECT key_id,service_id,algorithm,public_key,secret_ref,state,generation FROM vault_recipient_key WHERE key_id=?1{}",
        if active { " AND state='active'" } else { "" }
    );
    env.d1("DB")?
        .prepare(&sql)
        .bind(&[JsValue::from_str(key_id)])?
        .first::<RecipientKey>(None)
        .await
}

#[cfg(target_arch = "wasm32")]
async fn bounded_body(request: &mut worker::Request, maximum: usize) -> worker::Result<Vec<u8>> {
    use futures_util::StreamExt;
    let mut stream = request.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > maximum {
            return Err(worker::Error::RustError("claim_request_too_large".into()));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(target_arch = "wasm32")]
async fn release_name(
    mut request: worker::Request,
    env: &worker::Env,
) -> worker::Result<worker::Response> {
    let unavailable = || -> worker::Result<worker::Response> {
        Ok(worker::Response::builder()
            .with_status(503)
            .with_header("Cache-Control", "no-store")?
            .empty())
    };
    let body = bounded_body(&mut request, 256).await?;
    let Ok(input) = serde_json::from_slice::<NameRequest>(&body) else {
        return unavailable();
    };
    if input.access_hash.len() != 43
        || !input
            .access_hash
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return unavailable();
    }
    let remote = env.service("CLAIM_STORE").is_ok();
    // One statement selects one ledger row's explicit version, never a guessed
    // source or a second consent ledger. Both arms use the same token and RP.
    let query = format!(
        "SELECT v.account_id,ac.client_id,h.revision,r.version AS release_version, \
        h.object_key,h.ciphertext_sha256,e.frame,k.key_id,k.public_key,k.secret_ref,k.generation, \
        1 AS storage_version,'' AS source_origin,'' AS vault_id,'' AS collection_id,'' AS record_id,'' AS kind, \
        0 AS key_generation,0 AS owner_key_revision,g.version AS system_grant_version,e.envelope_id {ACTIVE_NAME_RELEASE} \
        UNION ALL SELECT v.account_id,ac.client_id,h.revision,r.version AS release_version, \
        h.object_key,h.ciphertext_sha256,e.frame,k.key_id,k.public_key,k.secret_ref,k.generation, \
        2 AS storage_version,g.origin AS source_origin,g.vault_id,g.collection_id,g.record_id,g.kind, \
        g.key_generation,g.owner_key_revision,g.version AS system_grant_version,e.envelope_id {ACTIVE_NAME_RECORD_RELEASE}"
    );
    let row = if remote {
        serde_json::from_value::<Option<NameRelease>>(
            store_call(
                env,
                "release",
                serde_json::json!({"access_hash":input.access_hash}),
            )
            .await?,
        )
        .map_err(|_| worker::Error::RustError("invalid_claim_store_response".into()))?
    } else if legacy_store(env) {
        env.d1("DB")?
            .prepare(&query)
            .bind(&[JsValue::from_str(&input.access_hash)])?
            .first::<NameRelease>(None)
            .await?
    } else {
        return unavailable();
    };
    let Some(row) = row else {
        return Ok(worker::Response::builder()
            .with_status(204)
            .with_header("Cache-Control", "no-store")?
            .empty());
    };
    let issuer = env.var("MIKAKI_ISSUER")?.to_string();
    if !issuer.starts_with("https://")
        || issuer.ends_with('/')
        || row.revision <= 0
        || row.release_version <= 0
        || row.generation <= 0
        || !valid_binding(&row.secret_ref)
        || row.object_key.is_empty()
    {
        return unavailable();
    }
    let ciphertext = if remote {
        row.ciphertext
            .clone()
            .ok_or_else(|| worker::Error::RustError("missing_claim_blob".into()))?
    } else {
        let Some(object) = env
            .bucket("VAULT_BLOBS")?
            .get(&row.object_key)
            .execute()
            .await?
        else {
            return unavailable();
        };
        let Some(blob) = object.body() else {
            return unavailable();
        };
        blob.bytes().await?
    };
    if ciphertext.len() > 24 * 1024
        || URL_SAFE_NO_PAD.encode(Sha256::digest(&ciphertext)) != row.ciphertext_sha256
    {
        return unavailable();
    }
    let Some(secret) = env.secret_store(&row.secret_ref)?.get().await? else {
        return unavailable();
    };
    let secret = Zeroizing::new(secret);
    let Some(seed) = decode_seed(&secret) else {
        return unavailable();
    };
    if !public_key_matches(&row.key_id, &row.public_key, &secret) {
        return unavailable();
    }
    let name = if row.storage_version == 1 {
        let binding = envelope::UserInfoBinding {
            origin: &issuer,
            account_id: &row.account_id,
            revision: row.revision as u64,
            ciphertext: &ciphertext,
        };
        let Some(key) = envelope::open_userinfo_data_key(
            &seed,
            &row.public_key,
            &row.key_id,
            row.generation as u64,
            &row.frame,
            &binding,
        ) else {
            return unavailable();
        };
        envelope::decrypt_name_ciphertext(&key, &issuer, row.revision as u64, &ciphertext)
    } else if row.storage_version == 2 && row.source_origin == issuer {
        let source = envelope_v2::RecordSource {
            storage_version: 2,
            origin: row.source_origin.clone(),
            owner_id: row.account_id.clone(),
            vault_id: row.vault_id.clone(),
            collection_id: row.collection_id.clone(),
            record_id: row.record_id.clone(),
            kind: row.kind.clone(),
            revision: row.revision as u64,
            ciphertext_sha256: row.ciphertext_sha256.clone(),
        };
        let authority = envelope_v2::RecordAuthority {
            key_generation: row.key_generation as u64,
            owner_key_revision: row.owner_key_revision as u64,
        };
        let binding = envelope_v2::RecordBinding {
            source: &source,
            authority: &authority,
            ciphertext: &ciphertext,
        };
        let Some(key) = envelope_v2::open_record_data_key(
            &seed,
            &row.public_key,
            &row.key_id,
            row.generation as u64,
            &row.frame,
            &binding,
        ) else {
            return unavailable();
        };
        envelope_v2::decrypt_record_name(&key, &source, &ciphertext)
    } else {
        None
    };
    let Some(name) = name else {
        return unavailable();
    };

    // Compiled only into the local conformance artifact, never the release Worker.
    #[cfg(feature = "conformance-gate")]
    {
        let gate = env.service("CONFORMANCE_GATE")?;
        let request = worker::Request::new(
            "https://conformance.internal/after-decrypt",
            worker::Method::Get,
        )?;
        if gate.fetch_request(request).await?.status_code() != 200 {
            return unavailable();
        }
    }

    // The audit insert re-runs every live grant predicate immediately before
    // disclosure. A concurrent revoke before this point prevents a result.
    let (template, active) = if row.storage_version == 1 {
        (AUDIT_NAME_RELEASE, ACTIVE_NAME_RELEASE)
    } else {
        (AUDIT_NAME_RECORD_RELEASE, ACTIVE_NAME_RECORD_RELEASE)
    };
    let audit = template.replace("{ACTIVE_NAME_RELEASE}", active);
    let mut params = vec![
        JsValue::from_str(&input.access_hash),
        JsValue::from_str(&row.account_id),
        JsValue::from_str(&row.client_id),
        JsValue::from_f64(row.revision as f64),
        JsValue::from_f64(row.release_version as f64),
        JsValue::from_str(&row.ciphertext_sha256),
        JsValue::from_str(&row.key_id),
    ];
    if row.storage_version == 2 {
        params.extend([
            JsValue::from_str(&row.source_origin),
            JsValue::from_str(&row.vault_id),
            JsValue::from_str(&row.collection_id),
            JsValue::from_str(&row.record_id),
            JsValue::from_str(&row.kind),
            JsValue::from_f64(row.key_generation as f64),
            JsValue::from_f64(row.owner_key_revision as f64),
            JsValue::from_f64(row.system_grant_version as f64),
            JsValue::from_f64(row.generation as f64),
            JsValue::from_str(&row.envelope_id),
        ]);
    }
    let accepted = if remote {
        store_call(env,"audit",serde_json::json!({
            "access_hash":input.access_hash,"storage_version":row.storage_version,
            "account_id":row.account_id,"client_id":row.client_id,"revision":row.revision,
            "release_version":row.release_version,"ciphertext_sha256":row.ciphertext_sha256,"key_id":row.key_id,
            "source_origin":row.source_origin,"vault_id":row.vault_id,"collection_id":row.collection_id,
            "record_id":row.record_id,"kind":row.kind,"key_generation":row.key_generation,
            "owner_key_revision":row.owner_key_revision,"system_grant_version":row.system_grant_version,
            "generation":row.generation,"envelope_id":row.envelope_id
        })).await?["accepted"].as_bool()==Some(true)
    } else {
        env.d1("DB")?
            .prepare(&audit)
            .bind(&params)?
            .first::<i64>(Some("id"))
            .await?
            .is_some()
    };
    if !accepted {
        return unavailable();
    }
    worker::Response::builder()
        .with_header("Cache-Control", "no-store")?
        .from_json(&NameResponse { name: &name })
}

#[cfg(target_arch = "wasm32")]
async fn verify_key(env: &worker::Env, key_id: &str) -> worker::Result<bool> {
    if key_id.len() != 43
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Ok(false);
    }
    let row = load_key(env, key_id, false).await?;
    let Some(row) = row else {
        worker::console_warn!("recipient verification unavailable: directory row missing");
        return Ok(false);
    };
    if row.key_id != key_id
        || row.service_id != "userinfo"
        || row.algorithm != "ML-KEM-768"
        || row.state == "disabled"
        || !valid_binding(&row.secret_ref)
    {
        worker::console_warn!("recipient verification unavailable: directory state or metadata");
        return Ok(false);
    }
    let binding = match env.secret_store(&row.secret_ref) {
        Ok(binding) => binding,
        Err(_) => {
            worker::console_warn!("recipient verification unavailable: secret binding");
            return Ok(false);
        }
    };
    let value = match binding.get().await {
        Ok(Some(value)) => value,
        _ => {
            worker::console_warn!("recipient verification unavailable: secret read");
            return Ok(false);
        }
    };
    let value = Zeroizing::new(value);
    let matches = public_key_matches(key_id, &row.public_key, &value);
    if !matches {
        worker::console_warn!("recipient verification unavailable: public key mismatch");
    }
    Ok(matches)
}

#[cfg(target_arch = "wasm32")]
async fn validate_envelope(
    mut request: worker::Request,
    env: &worker::Env,
    key_id: &str,
) -> worker::Result<bool> {
    if key_id.len() != 43
        || !key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Ok(false);
    }
    // This Worker has no public route. The OP service binding sends at most 40 KiB.
    let body = bounded_body(&mut request, 40 * 1024).await?;
    let Ok(value) = serde_json::from_slice::<EnvelopeValidation>(&body) else {
        return Ok(false);
    };
    if value.origin.len() > 256
        || !value.origin.starts_with("https://")
        || value.account_id.is_empty()
        || value.account_id.len() > 128
        || value.revision == 0
    {
        return Ok(false);
    }
    let (Ok(frame), Ok(ciphertext)) = (
        URL_SAFE_NO_PAD.decode(&value.frame),
        URL_SAFE_NO_PAD.decode(&value.ciphertext),
    ) else {
        return Ok(false);
    };
    if frame.len() != 1187
        || ciphertext.len() > 24 * 1024
        || URL_SAFE_NO_PAD.encode(&frame) != value.frame
        || URL_SAFE_NO_PAD.encode(&ciphertext) != value.ciphertext
    {
        return Ok(false);
    }
    let row = load_key(env, key_id, true).await?;
    let Some(row) = row else {
        return Ok(false);
    };
    if row.key_id != key_id
        || row.service_id != "userinfo"
        || row.algorithm != "ML-KEM-768"
        || row.state != "active"
        || row.generation < 1
        || !valid_binding(&row.secret_ref)
    {
        return Ok(false);
    }
    let secret = match env.secret_store(&row.secret_ref) {
        Ok(binding) => match binding.get().await {
            Ok(Some(secret)) => Zeroizing::new(secret),
            _ => return Ok(false),
        },
        Err(_) => return Ok(false),
    };
    let Some(seed) = decode_seed(&secret) else {
        return Ok(false);
    };
    let binding = envelope::UserInfoBinding {
        origin: &value.origin,
        account_id: &value.account_id,
        revision: value.revision,
        ciphertext: &ciphertext,
    };
    let Some(data_key) = envelope::open_userinfo_data_key(
        &seed,
        &row.public_key,
        key_id,
        row.generation as u64,
        &frame,
        &binding,
    ) else {
        return Ok(false);
    };
    Ok(envelope::validates_name_ciphertext(
        &data_key,
        &value.origin,
        value.revision,
        &ciphertext,
    ))
}

#[cfg(target_arch = "wasm32")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordEnvelopeValidation {
    source: envelope_v2::RecordSource,
    authority: envelope_v2::RecordAuthority,
    ciphertext: String,
    frame: String,
}
#[cfg(target_arch = "wasm32")]
async fn validate_record_envelope(
    mut request: worker::Request,
    env: &worker::Env,
    key_id: &str,
) -> worker::Result<bool> {
    if key_id.len() != 43
        || !key_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Ok(false);
    }
    // This Worker has no public route. The OP service binding sends at most 40 KiB.
    let body = bounded_body(&mut request, 40 * 1024).await?;
    let Ok(value) = serde_json::from_slice::<RecordEnvelopeValidation>(&body) else {
        return Ok(false);
    };
    if !value.source.valid() || !value.authority.valid() {
        return Ok(false);
    }
    let (Ok(frame), Ok(ciphertext)) = (
        URL_SAFE_NO_PAD.decode(&value.frame),
        URL_SAFE_NO_PAD.decode(&value.ciphertext),
    ) else {
        return Ok(false);
    };
    if frame.len() != 1187
        || ciphertext.len() > 24 * 1024
        || URL_SAFE_NO_PAD.encode(&frame) != value.frame
        || URL_SAFE_NO_PAD.encode(&ciphertext) != value.ciphertext
    {
        return Ok(false);
    }
    let row = load_key(env, key_id, true).await?;
    let Some(row) = row else {
        return Ok(false);
    };
    if row.key_id != key_id
        || row.service_id != "userinfo"
        || row.algorithm != "ML-KEM-768"
        || row.state != "active"
        || row.generation < 1
        || !valid_binding(&row.secret_ref)
    {
        return Ok(false);
    }
    let secret = match env.secret_store(&row.secret_ref) {
        Ok(binding) => match binding.get().await {
            Ok(Some(secret)) => Zeroizing::new(secret),
            _ => return Ok(false),
        },
        Err(_) => return Ok(false),
    };
    let Some(seed) = decode_seed(&secret) else {
        return Ok(false);
    };
    let binding = envelope_v2::RecordBinding {
        source: &value.source,
        authority: &value.authority,
        ciphertext: &ciphertext,
    };
    let Some(key) = envelope_v2::open_record_data_key(
        &seed,
        &row.public_key,
        key_id,
        row.generation as u64,
        &frame,
        &binding,
    ) else {
        return Ok(false);
    };
    Ok(envelope_v2::decrypt_record_name(&key, &value.source, &ciphertext).is_some())
}

#[cfg(all(target_arch = "wasm32", feature = "worker-entry"))]
#[worker::event(fetch)]
pub async fn main(
    request: worker::Request,
    env: worker::Env,
    _context: worker::Context,
) -> worker::Result<worker::Response> {
    let path = request.url()?.path().to_owned();
    if request.method() == worker::Method::Post && path == "/internal/claims/name" {
        return match release_name(request, &env).await {
            Ok(response) => Ok(response),
            Err(_) => Ok(worker::Response::builder()
                .with_status(503)
                .with_header("Cache-Control", "no-store")?
                .empty()),
        };
    }
    if request.method() == worker::Method::Get && path == "/internal/ready" {
        let ready = async {
            if env.service("CLAIM_STORE").is_ok() {
                store_call(&env, "ready", serde_json::json!({})).await?;
            } else if legacy_store(&env) {
                env.d1("DB")?
                    .prepare("SELECT key_id FROM vault_recipient_key LIMIT 1")
                    .first::<serde_json::Value>(None)
                    .await?;
            } else {
                return Err(worker::Error::RustError("claim_store_required".into()));
            }
            Ok::<(), worker::Error>(())
        }
        .await;
        if ready.is_err() {
            worker::console_warn!("claim readiness unavailable");
        }
        return Ok(worker::Response::builder()
            .with_status(if ready.is_ok() { 204 } else { 503 })
            .with_header("Cache-Control", "no-store")?
            .empty());
    }
    let record_validation = path
        .strip_prefix("/internal/recipient-keys/")
        .and_then(|p| p.strip_suffix("/validate-record-envelope"));
    if request.method() == worker::Method::Post && record_validation.is_some() {
        let valid = validate_record_envelope(request, &env, record_validation.unwrap_or(""))
            .await
            .unwrap_or(false);
        return Ok(worker::Response::builder()
            .with_status(if valid { 204 } else { 503 })
            .with_header("Cache-Control", "no-store")?
            .empty());
    }
    let validation_key_id = path
        .strip_prefix("/internal/recipient-keys/")
        .and_then(|part| part.strip_suffix("/validate-envelope"));
    if request.method() == worker::Method::Post {
        let Some(key_id) = validation_key_id else {
            return Ok(worker::Response::builder().with_status(404).empty());
        };
        let valid = validate_envelope(request, &env, key_id)
            .await
            .unwrap_or(false);
        return Ok(worker::Response::builder()
            .with_status(if valid { 204 } else { 503 })
            .with_header("Cache-Control", "no-store")?
            .empty());
    }
    let key_id = path
        .strip_prefix("/internal/recipient-keys/")
        .and_then(|part| part.strip_suffix("/verify"));
    if request.method() != worker::Method::Get || key_id.is_none() {
        return Ok(worker::Response::builder().with_status(404).empty());
    }
    let Some(key_id) = key_id else {
        return Ok(worker::Response::builder().with_status(404).empty());
    };
    let verified = match verify_key(&env, key_id).await {
        Ok(verified) => verified,
        Err(_) => {
            worker::console_warn!("recipient verification unavailable: directory query");
            false
        }
    };
    Ok(worker::Response::builder()
        .with_status(if verified { 204 } else { 503 })
        .with_header("Cache-Control", "no-store")?
        .empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{Deserializable as _, OpModeR, aead::AesGcm256, kdf::HkdfSha256};

    fn context(parts: &[&[u8]]) -> Vec<u8> {
        let mut output = Vec::new();
        for part in parts {
            let length = u16::try_from(part.len()).expect("fixture context part fits");
            output.extend_from_slice(&length.to_be_bytes());
            output.extend_from_slice(part);
        }
        output
    }

    #[test]
    fn binding_name_and_public_key_must_match_seed() {
        assert!(valid_binding("VAULT_USERINFO_MLKEM_A"));
        assert!(!valid_binding("OP_PRIVATE_JWK"));
        let seed = [0x71; 64];
        let public = DecapsulationKey::<MlKem768>::from_seed(Seed::from(seed))
            .encapsulation_key()
            .to_bytes();
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(public));
        let encoded = URL_SAFE_NO_PAD.encode(seed);
        assert!(public_key_matches(&key_id, &public, &encoded));
        assert!(!public_key_matches(
            &key_id,
            &public,
            &URL_SAFE_NO_PAD.encode([0x72; 64])
        ));
        let mut changed = public;
        changed[0] ^= 1;
        assert!(!public_key_matches(&key_id, &changed, &encoded));
    }

    #[test]
    fn validated_seed_opens_noble_vault_envelope_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../design/probes/pqc/hpke-envelope-fixture.json"
        ))
        .unwrap();
        let encoded_seed = fixture["seed"].as_str().unwrap();
        let seed = decode_seed(encoded_seed).unwrap();
        assert!(decode_seed(&format!("{encoded_seed}=")).is_none());
        let public = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed))
            .encapsulation_key()
            .to_bytes();
        let key_id = Sha256::digest(public);
        assert!(public_key_matches(
            &URL_SAFE_NO_PAD.encode(key_id),
            public.as_slice(),
            encoded_seed
        ));
        let frame = URL_SAFE_NO_PAD
            .decode(fixture["frame"].as_str().unwrap())
            .unwrap();
        assert_eq!(frame.len(), 1187);
        assert_eq!(&frame[..4], b"MKVE");
        assert_eq!(frame[4], 1);
        assert_eq!(&frame[5..11], &[0, 0x41, 0, 1, 0, 2]);
        assert_eq!(&frame[11..43], key_id.as_slice());
        assert_eq!(&frame[43..51], &1_u64.to_be_bytes());

        let info = context(&[
            b"mikaki-vault-recipient-envelope-v1-draft04",
            &[1],
            &[0, 0x41, 0, 1, 0, 2],
            b"userinfo",
            key_id.as_slice(),
            &1_u64.to_be_bytes(),
        ]);
        let blob_digest = Sha256::digest(b"test-vault-ciphertext");
        let aad = context(&[
            b"https://mikaki.example",
            b"test-account-1",
            b"name",
            &9_u64.to_be_bytes(),
            b"userinfo",
            b"oidc.userinfo.name",
            blob_digest.as_slice(),
        ]);
        let private = <hpke::kem::MlKem768 as hpke::Kem>::PrivateKey::from_bytes(&*seed).unwrap();
        let enc =
            <hpke::kem::MlKem768 as hpke::Kem>::EncappedKey::from_bytes(&frame[51..1139]).unwrap();
        let open = |ciphertext: &[u8]| {
            let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, hpke::kem::MlKem768>(
                &OpModeR::Base,
                &private,
                &enc,
                &info,
            )
            .unwrap();
            receiver.open(ciphertext, &aad)
        };
        assert_eq!(open(&frame[1139..]).unwrap(), [0x51; 32]);
        let mut changed = frame[1139..].to_vec();
        changed[0] ^= 1;
        assert!(open(&changed).is_err());
    }
}
