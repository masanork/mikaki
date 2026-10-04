//! Preregistered Final / Draft 18 encrypted response: ECDH-ES / A256GCM.
use super::*;
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use p256::{SecretKey, ecdh::diffie_hellman};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEncryption {
    pub kid: String,
    pub alg: String,
    pub enc: String,
    pub jwk: PublicJwk,
}
impl ResponseEncryption {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.kid.is_empty()
            || self.kid.len() > 128
            || self.alg != "ECDH-ES"
            || self.enc != "A256GCM"
        {
            return Err("invalid_response_encryption");
        }
        self.jwk.verifying_key()?;
        Ok(())
    }
    pub fn thumbprint(&self) -> Result<[u8; 32], &'static str> {
        self.validate()?;
        // RFC 7638 canonical member order; public P-256 key only.
        let canonical = serde_json::to_vec(
            &json!({"crv":self.jwk.crv,"kty":self.jwk.kty,"x":self.jwk.x,"y":self.jwk.y}),
        )
        .map_err(|_| "invalid_response_encryption")?;
        Ok(Sha256::digest(canonical).into())
    }
}
/// Select the first supported public recipient key in the authenticated request.
/// No remote keys are fetched; all advertised kids must be unambiguous.
pub fn from_client_metadata(metadata: &Value) -> Result<ResponseEncryption, &'static str> {
    let error = "invalid_response_encryption";
    let encs = metadata["encrypted_response_enc_values_supported"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 16)
        .ok_or(error)?;
    let mut names = HashSet::new();
    for enc in encs {
        let enc = enc
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 32)
            .ok_or(error)?;
        if !names.insert(enc) {
            return Err(error);
        }
    }
    if !names.contains("A256GCM") {
        return Err(error);
    }
    let keys = metadata["jwks"]["keys"]
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= 8)
        .ok_or(error)?;
    let mut kids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut selected = None;
    for key in keys {
        let object = key.as_object().ok_or(error)?;
        if ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "jku", "x5u"]
            .iter()
            .any(|k| object.contains_key(*k))
        {
            return Err(error);
        }
        let kid = key["kid"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 128)
            .ok_or(error)?;
        if !kids.insert(kid) {
            return Err(error);
        }
        key["alg"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 64)
            .ok_or(error)?;
        if key["kty"] != "EC" || key["crv"] != "P-256" || key["alg"] != "ECDH-ES" {
            continue;
        }
        if key.get("use").is_some_and(|u| u != "enc") {
            continue;
        }
        if let Some(ops) = key.get("key_ops") {
            let ops = ops.as_array().filter(|a| a.len() == 1).ok_or(error)?;
            if ops[0] != "deriveKey" && ops[0] != "deriveBits" {
                return Err(error);
            }
        }
        let jwk = PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: key["x"].as_str().ok_or(error)?.into(),
            y: key["y"].as_str().ok_or(error)?.into(),
        };
        jwk.verifying_key()?;
        if !public_keys.insert(jwk.thumbprint()?) {
            return Err(error);
        }
        let recipient = ResponseEncryption {
            jwk,
            kid: key["kid"].as_str().ok_or(error)?.into(),
            alg: "ECDH-ES".into(),
            enc: "A256GCM".into(),
        };
        recipient.validate()?;
        if selected.is_none() {
            selected = Some(recipient);
        }
    }
    selected.ok_or(error)
}
/// Caller generates a fresh ephemeral key and 96-bit IV for every approved response.
/// The response key is never the long-lived credential signing key.
pub fn encrypt_response(
    vp: &str,
    request: &ApprovedRequest,
    now: u64,
    ephemeral: SecretKey,
    iv: [u8; 12],
) -> Result<String, &'static str> {
    if now >= request.expires_at() || vp.is_empty() || vp.len() > 65536 {
        return Err("invalid_response");
    }
    let recipient = request
        .response_encryption()
        .ok_or("response_encryption_required")?;
    encrypt_payload(
        recipient,
        Some(request.nonce()),
        request.wallet_nonce(),
        &request.authorization_payload(vp),
        ephemeral,
        iv,
    )
}

pub(crate) fn encrypt_payload(
    recipient: &ResponseEncryption,
    nonce: Option<&str>,
    wallet_nonce: Option<&str>,
    payload: &Value,
    ephemeral: SecretKey,
    iv: [u8; 12],
) -> Result<String, &'static str> {
    recipient.validate()?;
    let public = recipient.jwk.verifying_key()?;
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), public.as_affine());
    // RFC 7518 4.6.2: SHA-256 Concat KDF, AlgorithmID=enc, optional wallet nonce PartyUInfo,
    // PartyVInfo=request nonce bytes, SuppPubInfo=256-bit key length.
    let mut hash = Sha256::new();
    hash.update(1u32.to_be_bytes());
    hash.update(shared.raw_secret_bytes());
    for value in [
        b"A256GCM".as_slice(),
        wallet_nonce.unwrap_or("").as_bytes(),
        nonce.unwrap_or("").as_bytes(),
    ] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    hash.update(256u32.to_be_bytes());
    let cek = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
    let epk = PublicJwk::from_key(&p256::ecdsa::VerifyingKey::from(ephemeral.public_key()));
    let mut header = json!({"alg":recipient.alg,"enc":recipient.enc,"kid":recipient.kid,"epk":epk});
    if let Some(nonce) = wallet_nonce {
        header["apu"] = json!(B64.encode(nonce.as_bytes()));
    }
    if let Some(nonce) = nonce {
        header["apv"] = json!(B64.encode(nonce.as_bytes()));
    }
    let protected = B64.encode(serde_json::to_vec(&header).map_err(|_| "invalid_response")?);
    let plaintext = Zeroizing::new(serde_json::to_vec(payload).map_err(|_| "invalid_response")?);
    if plaintext.len() > 65536 {
        return Err("invalid_response");
    }
    let encrypted = Aes256Gcm::new_from_slice(&*cek)
        .map_err(|_| "invalid_response")?
        .encrypt(
            &Nonce::from(iv),
            Payload {
                msg: &plaintext,
                aad: protected.as_bytes(),
            },
        )
        .map_err(|_| "response_encryption_failed")?;
    let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
    Ok(format!(
        "{protected}..{}.{}.{}",
        B64.encode(iv),
        B64.encode(ciphertext),
        B64.encode(tag)
    ))
}
