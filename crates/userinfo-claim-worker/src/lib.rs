//! Dedicated recipient key boundary. No secret is returned to the OP Worker.

pub mod envelope;

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
    let body = request.bytes().await?;
    if body.len() > 256 {
        return unavailable();
    }
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
    let db = env.d1("DB")?;
    let query = format!(
        "SELECT v.account_id,ac.client_id,h.revision,r.version AS release_version, \
      h.object_key,h.ciphertext_sha256,e.frame,k.key_id,k.public_key,k.secret_ref,k.generation {ACTIVE_NAME_RELEASE}"
    );
    let row = db
        .prepare(&query)
        .bind(&[JsValue::from_str(&input.access_hash)])?
        .first::<NameRelease>(None)
        .await?;
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
    let ciphertext = blob.bytes().await?;
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
    let binding = envelope::UserInfoBinding {
        origin: &issuer,
        account_id: &row.account_id,
        revision: row.revision as u64,
        ciphertext: &ciphertext,
    };
    let Some(data_key) = envelope::open_userinfo_data_key(
        &seed,
        &row.public_key,
        &row.key_id,
        row.generation as u64,
        &row.frame,
        &binding,
    ) else {
        return unavailable();
    };
    let Some(name) =
        envelope::decrypt_name_ciphertext(&data_key, &issuer, row.revision as u64, &ciphertext)
    else {
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
    let audit = AUDIT_NAME_RELEASE.replace("{ACTIVE_NAME_RELEASE}", ACTIVE_NAME_RELEASE);
    let accepted = db
        .prepare(&audit)
        .bind(&[
            JsValue::from_str(&input.access_hash),
            JsValue::from_str(&row.account_id),
            JsValue::from_str(&row.client_id),
            JsValue::from_f64(row.revision as f64),
            JsValue::from_f64(row.release_version as f64),
            JsValue::from_str(&row.ciphertext_sha256),
            JsValue::from_str(&row.key_id),
        ])?
        .first::<i64>(Some("id"))
        .await?;
    if accepted.is_none() {
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
    let db = env.d1("DB")?;
    let row = db
        .prepare(
            "SELECT key_id,service_id,algorithm,public_key,secret_ref,state,generation \
             FROM vault_recipient_key WHERE key_id=?1",
        )
        .bind(&[wasm_bindgen::JsValue::from_str(key_id)])?
        .first::<RecipientKey>(None)
        .await?;
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
    let body = request.bytes().await?;
    if body.len() > 40 * 1024 {
        return Ok(false);
    }
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
    let db = env.d1("DB")?;
    let row = db
        .prepare(
            "SELECT key_id,service_id,algorithm,public_key,secret_ref,state,generation \
         FROM vault_recipient_key WHERE key_id=?1 AND state='active'",
        )
        .bind(&[wasm_bindgen::JsValue::from_str(key_id)])?
        .first::<RecipientKey>(None)
        .await?;
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
            let db = env.d1("DB")?;
            db.prepare("SELECT key_id FROM vault_recipient_key LIMIT 1")
                .first::<serde_json::Value>(None)
                .await?;
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
