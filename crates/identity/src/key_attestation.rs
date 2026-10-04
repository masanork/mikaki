//! OID4VCI Appendix D / HAIP key attestation: explicit-purpose trust only.
use crate::{certificate, issuance::PublicJwk};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{Signature, signature::Verifier};
use serde::Deserialize;
use serde_json::Value;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub trust_anchors: Vec<String>,
    pub key_storage: Option<Vec<String>>,
    pub user_authentication: Option<Vec<String>>,
}
impl Trust {
    pub fn validate(&self) -> Result<(), &'static str> {
        certificate::validate_attester_roots(&self.trust_anchors).map_err(|_| "invalid_proof")?;
        for values in [&self.key_storage, &self.user_authentication]
            .into_iter()
            .flatten()
        {
            if values.is_empty()
                || values.len() > 8
                || values.iter().any(|s| s.is_empty() || s.len() > 256)
            {
                return Err("invalid_proof");
            }
        }
        Ok(())
    }
}
#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: String,
    x5c: Vec<String>,
    #[serde(flatten)]
    extensions: std::collections::BTreeMap<String, Value>,
}
#[derive(Deserialize)]
struct Key(#[serde(deserialize_with = "crate::issuance::proof_jwk")] PublicJwk);
#[derive(Deserialize)]
struct Claims {
    iat: u64,
    exp: Option<u64>,
    nonce: String,
    attested_keys: Vec<Key>,
    key_storage: Option<Vec<String>>,
    user_authentication: Option<Vec<String>>,
    #[serde(flatten)]
    extensions: std::collections::BTreeMap<String, Value>,
}
pub struct Verified {
    pub holder: PublicJwk,
    pub expires_at: u64,
}
fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = B64.decode(s).map_err(|_| "invalid_proof")?;
    if B64.encode(&bytes) != s {
        return Err("invalid_proof");
    }
    Ok(bytes)
}
fn component(actual: &Option<Vec<String>>, required: &Option<Vec<String>>) -> bool {
    if actual.as_ref().is_some_and(|a| {
        a.is_empty() || a.len() > 8 || a.iter().any(|s| s.is_empty() || s.len() > 256)
    }) {
        return false;
    }
    required.as_ref().is_none_or(|r| {
        actual
            .as_ref()
            .is_some_and(|a| a.iter().any(|s| r.contains(s)))
    })
}
pub fn verify(
    compact: &str,
    nonce: &str,
    policy: &Trust,
    jwt_proof: bool,
    now: u64,
) -> Result<Verified, &'static str> {
    if compact.len() > 16384 {
        return Err("invalid_proof");
    }
    let parts: Vec<_> = compact.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid_proof");
    }
    let h: Header = serde_json::from_slice(&decode(parts[0])?).map_err(|_| "invalid_proof")?;
    let c: Claims = serde_json::from_slice(&decode(parts[1])?).map_err(|_| "invalid_proof")?;
    if c.nonce != nonce {
        return Err("invalid_nonce");
    }
    if h.alg != "ES256"
        || h.typ != "key-attestation+jwt"
        || h.x5c.is_empty()
        || h.x5c.len() > 4
        || ["crit", "b64", "jku", "x5u", "jwk", "trust_chain"]
            .iter()
            .any(|k| h.extensions.contains_key(*k))
        || c.nonce.is_empty()
        || c.nonce.len() > 128
        || c.iat > now.saturating_add(30)
        || now.saturating_sub(c.iat) > 60
        || (jwt_proof && c.exp.is_none())
        || c.exp.is_some_and(|t| t <= now || t <= c.iat)
        || c.attested_keys.len() != 1
        || c.extensions.contains_key("status")
        || !component(&c.key_storage, &policy.key_storage)
        || !component(&c.user_authentication, &policy.user_authentication)
    {
        return Err("invalid_proof");
    }
    let chain = h
        .x5c
        .iter()
        .map(|s| certificate::decode_certificate(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid_proof")?;
    let (key, deadline) = certificate::verify_attester_chain(&chain, &policy.trust_anchors, now)
        .map_err(|_| "invalid_proof")?;
    let sig = Signature::from_slice(&decode(parts[2])?).map_err(|_| "invalid_proof")?;
    key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .map_err(|_| "invalid_proof")?;
    Ok(Verified {
        holder: c.attested_keys.into_iter().next().unwrap().0,
        expires_at: c.exp.unwrap_or(deadline).min(deadline),
    })
}
