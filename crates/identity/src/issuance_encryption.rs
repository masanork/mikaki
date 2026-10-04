//! Bounded OID4VCI Final compact JWE. Response-only DEFLATE, no remote key resolution.
use crate::issuance::PublicJwk;
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::{SecretKey, ecdh::diffie_hellman};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
const ERROR: &str = "invalid_encryption_parameters";
#[derive(Clone, Deserialize)]
pub struct EncryptionKey {
    kty: String,
    crv: String,
    x: String,
    y: String,
    alg: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    key_ops: Option<Vec<String>>,
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, Value>,
}
impl EncryptionKey {
    pub fn public(&self) -> Result<PublicJwk, &'static str> {
        if self.alg != "ECDH-ES"
            || self
                .kid
                .as_ref()
                .is_some_and(|k| k.is_empty() || k.len() > 128)
            || self.usage.as_deref().is_some_and(|u| u != "enc")
            || self.key_ops.as_ref().is_some_and(|ops| {
                ops.is_empty()
                    || ops.len() > 2
                    || ops
                        .iter()
                        .any(|op| !matches!(op.as_str(), "deriveKey" | "deriveBits"))
            })
            || [
                "d", "p", "q", "dp", "dq", "qi", "oth", "k", "jku", "x5u", "x5c",
            ]
            .iter()
            .any(|k| self.extra.contains_key(*k))
        {
            return Err(ERROR);
        }
        let key = PublicJwk {
            kty: self.kty.clone(),
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
        };
        key.verifying_key().map_err(|_| ERROR)?;
        Ok(key)
    }
    pub fn metadata(&self) -> Value {
        let mut v =
            json!({"kty":self.kty,"crv":self.crv,"x":self.x,"y":self.y,"alg":self.alg,"use":"enc"});
        if let Some(kid) = &self.kid {
            v["kid"] = json!(kid);
        }
        v
    }
}
pub struct RequestKey {
    secret: SecretKey,
    public: EncryptionKey,
}
impl RequestKey {
    pub fn parse(raw: &str) -> Result<Self, &'static str> {
        if raw.len() > 4096 {
            return Err(ERROR);
        }
        let mut value: Value = serde_json::from_str(raw).map_err(|_| ERROR)?;
        let private = value
            .as_object_mut()
            .ok_or(ERROR)?
            .remove("d")
            .ok_or(ERROR)?;
        let Value::String(private) = private else {
            return Err(ERROR);
        };
        let private = Zeroizing::new(private);
        let scalar = Zeroizing::new(decode(&private)?);
        let secret = SecretKey::from_slice(&scalar).map_err(|_| ERROR)?;
        let public: EncryptionKey = serde_json::from_value(value).map_err(|_| ERROR)?;
        let key = public.public()?;
        if public.kid.is_none()
            || key != PublicJwk::from_key(&p256::ecdsa::VerifyingKey::from(secret.public_key()))
        {
            return Err(ERROR);
        }
        Ok(Self { secret, public })
    }
    pub fn public(&self) -> &EncryptionKey {
        &self.public
    }
}
#[derive(Deserialize)]
pub struct ResponseEncryption {
    pub jwk: EncryptionKey,
    pub enc: String,
    zip: Option<String>,
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, Value>,
}
impl ResponseEncryption {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.jwk.public()?;
        bits(&self.enc)?;
        if self.zip.as_deref().is_some_and(|z| z != "DEF") || self.extra.contains_key("alg") {
            return Err(ERROR);
        }
        Ok(())
    }
}
#[derive(Deserialize)]
struct Header {
    alg: String,
    enc: String,
    kid: Option<String>,
    epk: PublicJwk,
    apu: Option<String>,
    apv: Option<String>,
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, Value>,
}
fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let b = B64.decode(s).map_err(|_| ERROR)?;
    if B64.encode(&b) != s {
        return Err(ERROR);
    }
    Ok(b)
}
fn bits(enc: &str) -> Result<u32, &'static str> {
    match enc {
        "A128GCM" => Ok(128),
        "A256GCM" => Ok(256),
        _ => Err(ERROR),
    }
}
fn cek(
    secret: &SecretKey,
    public: &PublicJwk,
    enc: &str,
    apu: &[u8],
    apv: &[u8],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let n = bits(enc)?;
    let public = public.verifying_key().map_err(|_| ERROR)?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let mut hash = Sha256::new();
    hash.update(1u32.to_be_bytes());
    hash.update(shared.raw_secret_bytes());
    for part in [enc.as_bytes(), apu, apv] {
        hash.update((part.len() as u32).to_be_bytes());
        hash.update(part);
    }
    hash.update(n.to_be_bytes());
    let output = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
    Ok(Zeroizing::new(output[..(n / 8) as usize].to_vec()))
}
pub fn decrypt_request(
    compact: &str,
    key: &RequestKey,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    decrypt_message(compact, key, 32768, 20480, None, false)
}
fn decrypt_message(
    compact: &str,
    key: &RequestKey,
    wire_limit: usize,
    plain_limit: usize,
    expected_enc: Option<&str>,
    allow_deflate: bool,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if compact.len() > wire_limit {
        return Err(ERROR);
    }
    let p: Vec<_> = compact.split('.').collect();
    if p.len() != 5 || !p[1].is_empty() || p[0].len() > 4096 {
        return Err(ERROR);
    }
    let h: Header = serde_json::from_slice(&decode(p[0])?).map_err(|_| ERROR)?;
    if h.alg != "ECDH-ES"
        || h.kid != key.public.kid
        || expected_enc.is_some_and(|enc| h.enc != enc)
        || h.extra
            .get("zip")
            .is_some_and(|z| !allow_deflate || z != "DEF")
        || ["crit", "b64", "jku", "x5u"]
            .iter()
            .any(|k| h.extra.contains_key(*k))
    {
        return Err(ERROR);
    }
    let party = |s: Option<String>| -> Result<Vec<u8>, &'static str> {
        match s {
            Some(s) if s.len() <= 512 => decode(&s),
            None => Ok(Vec::new()),
            _ => Err(ERROR),
        }
    };
    let cek = cek(&key.secret, &h.epk, &h.enc, &party(h.apu)?, &party(h.apv)?)?;
    let iv = decode(p[2])?;
    let tag = decode(p[4])?;
    if iv.len() != 12 || tag.len() != 16 {
        return Err(ERROR);
    }
    let mut encrypted = decode(p[3])?;
    encrypted.extend(tag);
    let payload = Payload {
        msg: &encrypted,
        aad: p[0].as_bytes(),
    };
    let iv = Nonce::from(<[u8; 12]>::try_from(iv).map_err(|_| ERROR)?);
    let plain = match h.enc.as_str() {
        "A128GCM" => Aes128Gcm::new_from_slice(&cek)
            .map_err(|_| ERROR)?
            .decrypt(&iv, payload),
        "A256GCM" => Aes256Gcm::new_from_slice(&cek)
            .map_err(|_| ERROR)?
            .decrypt(&iv, payload),
        _ => return Err(ERROR),
    }
    .map_err(|_| ERROR)?;
    let plain = Zeroizing::new(plain);
    if h.extra.contains_key("zip") {
        use miniz_oxide::inflate::{
            TINFLStatus,
            core::{DecompressorOxide, decompress, inflate_flags},
        };
        let mut output = Zeroizing::new(vec![0u8; plain_limit]);
        let (status, consumed, written) = decompress(
            &mut DecompressorOxide::default(),
            &plain,
            &mut output,
            0,
            inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        if status != TINFLStatus::Done || consumed != plain.len() {
            return Err(ERROR);
        }
        output.truncate(written);
        return Ok(output);
    }
    if plain.len() > plain_limit {
        return Err(ERROR);
    }
    Ok(plain)
}
pub fn encrypt_response(
    plain: &[u8],
    recipient: &ResponseEncryption,
    entropy: [u8; 32],
    iv: [u8; 12],
) -> Result<String, &'static str> {
    recipient.validate()?;
    if plain.len() > 65536 {
        return Err(ERROR);
    }
    let entropy = Zeroizing::new(entropy);
    let ephemeral = SecretKey::from_slice(&*entropy).map_err(|_| ERROR)?;
    let cek = cek(
        &ephemeral,
        &recipient.jwk.public()?,
        &recipient.enc,
        &[],
        &[],
    )?;
    let epk = PublicJwk::from_key(&p256::ecdsa::VerifyingKey::from(ephemeral.public_key()));
    let mut header = json!({"alg":"ECDH-ES","enc":recipient.enc,"epk":epk,"cty":"json"});
    if let Some(kid) = &recipient.jwk.kid {
        header["kid"] = json!(kid);
    }
    let compressed = recipient.zip.as_ref().map(|_| {
        header["zip"] = json!("DEF");
        Zeroizing::new(miniz_oxide::deflate::compress_to_vec(plain, 6))
    });
    let plain = compressed.as_deref().map(Vec::as_slice).unwrap_or(plain);
    let protected = B64.encode(serde_json::to_vec(&header).map_err(|_| ERROR)?);
    let payload = Payload {
        msg: plain,
        aad: protected.as_bytes(),
    };
    let encrypted = match recipient.enc.as_str() {
        "A128GCM" => Aes128Gcm::new_from_slice(&cek)
            .map_err(|_| ERROR)?
            .encrypt(&Nonce::from(iv), payload),
        "A256GCM" => Aes256Gcm::new_from_slice(&cek)
            .map_err(|_| ERROR)?
            .encrypt(&Nonce::from(iv), payload),
        _ => return Err(ERROR),
    }
    .map_err(|_| ERROR)?;
    let (cipher, tag) = encrypted.split_at(encrypted.len() - 16);
    Ok(format!(
        "{protected}..{}.{}.{}",
        B64.encode(iv),
        B64.encode(cipher),
        B64.encode(tag)
    ))
}

/// One issuance's in-memory recipient key and immutable negotiated encryption policy.
/// Never serialize or persist this context, and never retry with plaintext on failure.
pub struct WalletEncryption {
    recipient: RequestKey,
    request: EncryptionKey,
    enc: String,
    deflate: bool,
}
impl WalletEncryption {
    pub fn from_metadata(
        metadata: &Value,
        entropy: [u8; 32],
        kid: &str,
    ) -> Result<Option<Self>, &'static str> {
        let entropy = Zeroizing::new(entropy);
        let req = metadata.get("credential_request_encryption");
        let res = metadata.get("credential_response_encryption");
        if req.is_none() && res.is_none() {
            return Ok(None);
        }
        let (req, res) = (req.ok_or(ERROR)?, res.ok_or(ERROR)?);
        for m in [req, res] {
            if !m.is_object() || !m["encryption_required"].is_boolean() {
                return Err(ERROR);
            }
        }
        let supported = |m: &Value, field: &str, wanted: &str| -> bool {
            m[field].as_array().is_some_and(|a| {
                !a.is_empty()
                    && a.len() <= 16
                    && a.iter().all(Value::is_string)
                    && a.iter().any(|v| v == wanted)
            })
        };
        if !supported(res, "alg_values_supported", "ECDH-ES") {
            return Err(ERROR);
        }
        let enc = ["A256GCM", "A128GCM"]
            .into_iter()
            .find(|e| {
                supported(req, "enc_values_supported", e)
                    && supported(res, "enc_values_supported", e)
            })
            .ok_or(ERROR)?
            .to_owned();
        let keys = req["jwks"]["keys"]
            .as_array()
            .filter(|a| !a.is_empty() && a.len() <= 8)
            .ok_or(ERROR)?;
        let mut ids = std::collections::HashSet::new();
        let mut request = None;
        for value in keys {
            let key: EncryptionKey = serde_json::from_value(value.clone()).map_err(|_| ERROR)?;
            key.public()?;
            let id = key.kid.as_deref().ok_or(ERROR)?;
            if !ids.insert(id.to_owned()) {
                return Err(ERROR);
            }
            if request.is_none() {
                request = Some(key);
            }
        }
        let request = request.ok_or(ERROR)?;
        let secret = SecretKey::from_slice(&*entropy).map_err(|_| ERROR)?;
        let public = PublicJwk::from_key(&p256::ecdsa::VerifyingKey::from(secret.public_key()));
        let public: EncryptionKey = serde_json::from_value(json!({
            "kty":public.kty,"crv":public.crv,"x":public.x,"y":public.y,
            "alg":"ECDH-ES","kid":kid,"use":"enc",
        }))
        .map_err(|_| ERROR)?;
        if public.public()? == request.public()? {
            return Err(ERROR);
        }
        Ok(Some(Self {
            recipient: RequestKey { secret, public },
            request,
            enc,
            deflate: supported(res, "zip_values_supported", "DEF"),
        }))
    }
    pub fn request_key(&self) -> Result<PublicJwk, &'static str> {
        self.request.public()
    }
    pub fn prepare_request(
        &self,
        mut payload: Value,
        entropy: [u8; 32],
        iv: [u8; 12],
    ) -> Result<String, &'static str> {
        let object = payload.as_object_mut().ok_or(ERROR)?;
        if object.contains_key("credential_response_encryption") {
            return Err(ERROR);
        }
        let mut parameters = json!({"jwk":self.recipient.public.metadata(),"enc":self.enc});
        if self.deflate {
            parameters["zip"] = json!("DEF");
        }
        object.insert("credential_response_encryption".into(), parameters);
        let plain = Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| ERROR)?);
        if plain.len() > 20480 {
            return Err(ERROR);
        }
        let recipient = ResponseEncryption {
            jwk: self.request.clone(),
            enc: self.enc.clone(),
            zip: None,
            extra: Default::default(),
        };
        let compact = encrypt_response(&plain, &recipient, entropy, iv)?;
        if compact.len() > 32768 {
            return Err(ERROR);
        }
        Ok(compact)
    }
    pub fn decrypt_response(&self, compact: &str) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        decrypt_message(
            compact,
            &self.recipient,
            96 * 1024,
            65536,
            Some(&self.enc),
            self.deflate,
        )
    }
}
