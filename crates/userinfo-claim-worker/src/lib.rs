//! Dedicated recipient key boundary. No secret is returned to the OP Worker.

#[cfg(any(test, target_arch = "wasm32"))]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(any(test, target_arch = "wasm32"))]
use ml_kem::{DecapsulationKey, MlKem768, Seed, kem::KeyExport};
#[cfg(any(test, target_arch = "wasm32"))]
use sha2::{Digest, Sha256};
#[cfg(any(test, target_arch = "wasm32"))]
use zeroize::Zeroizing;

#[cfg(target_arch = "wasm32")]
use serde::Deserialize;

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
fn public_key_matches(key_id: &str, public_key: &[u8], encoded_seed: &str) -> bool {
    if key_id.len() != 43 || public_key.len() != 1184 {
        return false;
    }
    let Ok(seed_bytes) = URL_SAFE_NO_PAD.decode(encoded_seed) else {
        return false;
    };
    let seed_bytes = Zeroizing::new(seed_bytes);
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(&seed_bytes));
    if canonical.as_str() != encoded_seed {
        return false;
    }
    let Ok(seed): Result<[u8; 64], _> = seed_bytes.as_slice().try_into() else {
        return false;
    };
    let seed = Zeroizing::new(seed);
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
            "SELECT key_id,service_id,algorithm,public_key,secret_ref,state \
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

#[cfg(all(target_arch = "wasm32", feature = "worker-entry"))]
#[worker::event(fetch)]
pub async fn main(
    request: worker::Request,
    env: worker::Env,
    _context: worker::Context,
) -> worker::Result<worker::Response> {
    let path = request.url()?.path().to_owned();
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
}
