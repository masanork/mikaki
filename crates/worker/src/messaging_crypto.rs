//! Bounded application device profile. No MLS provider/secret state in the OP.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{Env, Result};

pub const MAX_SAFE: u64 = 9_007_199_254_740_991;
fn invalid() -> worker::Error {
    worker::Error::RustError("invalid_device_profile".into())
}
pub fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            14 => b == b'4',
            19 => matches!(b, b'8' | b'9' | b'a' | b'b'),
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}
pub fn decode(value: &str, size: usize) -> Result<Vec<u8>> {
    if value.len() != (size * 4).div_ceil(3) {
        return Err(invalid());
    }
    let bytes = B64.decode(value).map_err(|_| invalid())?;
    if bytes.len() != size || B64.encode(&bytes) != value {
        return Err(invalid());
    }
    Ok(bytes)
}
pub fn digest(bytes: &[u8]) -> String {
    B64.encode(Sha256::digest(bytes))
}
pub fn origin(value: &str) -> bool {
    value.len() <= 256
        && value.is_ascii()
        && url::Url::parse(value)
            .is_ok_and(|u| u.scheme() == "https" && u.origin().ascii_serialization() == value)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub issuer: String,
    pub account_id: String,
    pub device_id: String,
    pub generation: u64,
}
impl Identity {
    pub fn valid(&self) -> bool {
        origin(&self.issuer)
            && uuid(&self.account_id)
            && uuid(&self.device_id)
            && (1..=MAX_SAFE).contains(&self.generation)
    }
    pub fn fingerprint(&self, key: &str) -> Result<String> {
        Ok(digest(&serde_json::to_vec(&(
            "mikaki-device-fingerprint-v1",
            self,
            "Ed25519",
            key,
        ))?))
    }
    pub fn scope(&self, key: &str, storage: &str, custody: &str) -> Result<String> {
        Ok(digest(&serde_json::to_vec(&(
            "mikaki-mls-device-state-v1",
            &self.issuer,
            &self.issuer,
            &self.account_id,
            &self.device_id,
            self.generation,
            storage,
            custody,
            self.fingerprint(key)?,
        ))?))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    typ: String,
    alg: String,
    kid: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    aud: String,
    device: Identity,
    public_key: String,
    nonce: String,
    iat: u64,
    exp: u64,
}
fn subtle() -> Result<web_sys::SubtleCrypto> {
    Ok(js_sys::Reflect::get(&js_sys::global(), &"crypto".into())?
        .dyn_into::<web_sys::Crypto>()
        .map_err(|_| invalid())?
        .subtle())
}
async fn import(jwk: &serde_json::Value, usage: &str) -> Result<web_sys::CryptoKey> {
    let object = js_sys::JSON::parse(&serde_json::to_string(jwk)?)?
        .dyn_into::<js_sys::Object>()
        .map_err(|_| invalid())?;
    let usages = js_sys::Array::new();
    usages.push(&JsValue::from_str(usage));
    let algorithm = js_sys::Object::new();
    js_sys::Reflect::set(&algorithm, &"name".into(), &"Ed25519".into())?;
    JsFuture::from(subtle()?.import_key_with_object(
        "jwk",
        &object,
        &algorithm,
        false,
        usages.as_ref(),
    )?)
    .await?
    .dyn_into::<web_sys::CryptoKey>()
    .map_err(|_| invalid())
}
async fn verify(key: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
    decode(key, 32)?;
    let key = import(
        &serde_json::json!({"kty":"OKP","crv":"Ed25519","x":key}),
        "verify",
    )
    .await?;
    Ok(JsFuture::from(
        subtle()?.verify_with_str_and_u8_array_and_u8_array("Ed25519", &key, signature, data)?,
    )
    .await?
    .as_bool()
        == Some(true))
}
pub async fn verify_proof(
    token: &str,
    expected: &Identity,
    key: &str,
    nonce: &str,
    now: u64,
) -> Result<(u64, u64)> {
    if token.len() > 8192 || !token.is_ascii() || !expected.valid() || now > MAX_SAFE {
        return Err(invalid());
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid());
    }
    let parse = |value: &str| -> Result<Vec<u8>> {
        let bytes = B64.decode(value).map_err(|_| invalid())?;
        if B64.encode(&bytes) != value {
            return Err(invalid());
        }
        Ok(bytes)
    };
    let header: Header = serde_json::from_slice(&parse(parts[0])?)?;
    let claims: Proof = serde_json::from_slice(&parse(parts[1])?)?;
    if header.typ != "mikaki-device-registration+jwt"
        || header.alg != "EdDSA"
        || header.kid != digest(&decode(key, 32)?)
        || claims.aud != expected.issuer
        || claims.device != *expected
        || claims.public_key != key
        || claims.nonce != nonce
        || claims.iat > now
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.exp > MAX_SAFE
        || claims.exp - claims.iat > 60
        || decode(nonce, 32).is_err()
    {
        return Err(invalid());
    }
    let input = format!("{}.{}", parts[0], parts[1]);
    if !verify(key, input.as_bytes(), &decode(parts[2], 64)?).await? {
        return Err(invalid());
    }
    Ok((claims.iat, claims.exp))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateKey {
    kty: String,
    crv: String,
    x: String,
    d: String,
}
pub struct Signer {
    private: web_sys::CryptoKey,
    pub public_key: String,
}
impl Signer {
    pub async fn load(env: &Env) -> Result<Self> {
        let encoded = env.secret("MESSAGING_ISSUER_KEY")?.to_string();
        if encoded.len() > 512 {
            return Err(invalid());
        }
        let k: PrivateKey = serde_json::from_str(&encoded)?;
        if k.kty != "OKP" || k.crv != "Ed25519" {
            return Err(invalid());
        }
        decode(&k.x, 32)?;
        decode(&k.d, 32)?;
        let private = import(
            &serde_json::json!({"kty":k.kty,"crv":k.crv,"x":k.x,"d":k.d}),
            "sign",
        )
        .await?;
        let signer = Self {
            private,
            public_key: k.x,
        };
        let check = signer.sign(b"mikaki-messaging-issuer-key-check-v1").await?;
        if !verify(
            &signer.public_key,
            b"mikaki-messaging-issuer-key-check-v1",
            &check,
        )
        .await?
        {
            return Err(invalid());
        }
        Ok(signer)
    }
    async fn sign(&self, input: &[u8]) -> Result<Vec<u8>> {
        let value = JsFuture::from(subtle()?.sign_with_str_and_u8_array(
            "Ed25519",
            &self.private,
            input,
        )?)
        .await?;
        Ok(js_sys::Uint8Array::new(&value).to_vec())
    }
    pub async fn binding(
        &self,
        device: &Identity,
        key: &str,
        revision: u64,
        status: &str,
        now: u64,
    ) -> Result<String> {
        let header = Header {
            typ: "mikaki-device-binding+jwt".into(),
            alg: "EdDSA".into(),
            kid: digest(&decode(&self.public_key, 32)?),
        };
        let claims = serde_json::json!({"iss":device.issuer,"aud":"mikaki-mls-device-v1","device":device,"public_key":key,"revision":revision,"status":status,"iat":now,"exp":now+300});
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header)?),
            B64.encode(serde_json::to_vec(&claims)?)
        );
        Ok(format!(
            "{input}.{}",
            B64.encode(self.sign(input.as_bytes()).await?)
        ))
    }
}
