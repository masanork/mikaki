//! Proof of possession for the private native attester enrollment API.
//! This proof establishes key ownership, never Android hardware/app assurance.
use crate::issuance::PublicJwk;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{Signature, signature::Verifier};
use serde::Deserialize;
use serde_json::json;
pub fn create(
    signer: &impl crate::wallet_authorization::Signer,
    client: &str,
    audience: &str,
    challenge: &str,
    purpose: &str,
    now: u64,
) -> Result<String, String> {
    let key = signer.public()?;
    let proof=signer.sign(json!({"typ":"mikaki-wallet-attester-proof+jwt","alg":"ES256","jwk":key}),
        json!({"iss":client,"aud":audience,"nonce":challenge,"purpose":purpose,"iat":now,"exp":now.saturating_add(60)}))?;
    verify(&proof, client, audience, challenge, purpose, &key, now).map_err(str::to_owned)?;
    Ok(proof)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    typ: String,
    alg: String,
    jwk: PublicJwk,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    aud: String,
    nonce: String,
    purpose: String,
    iat: u64,
    exp: u64,
}
pub fn verify(
    compact: &str,
    client: &str,
    audience: &str,
    challenge: &str,
    purpose: &str,
    key: &PublicJwk,
    now: u64,
) -> Result<(), &'static str> {
    const ERROR: &str = "invalid_attestation_proof";
    if compact.len() > 4096 || !matches!(purpose, "client" | "holder") {
        return Err(ERROR);
    }
    let parts: Vec<_> = compact.split('.').collect();
    if parts.len() != 3 {
        return Err(ERROR);
    }
    let decode = |s: &str| {
        let b = B64.decode(s).map_err(|_| ERROR)?;
        if B64.encode(&b) != s {
            return Err(ERROR);
        }
        Ok(b)
    };
    let h: Header = serde_json::from_slice(&decode(parts[0])?).map_err(|_| ERROR)?;
    let c: Claims = serde_json::from_slice(&decode(parts[1])?).map_err(|_| ERROR)?;
    if h.typ != "mikaki-wallet-attester-proof+jwt"
        || h.alg != "ES256"
        || &h.jwk != key
        || c.iss != client
        || c.aud != audience
        || c.nonce != challenge
        || c.purpose != purpose
        || c.iat > now.saturating_add(30)
        || now.saturating_sub(c.iat) > 60
        || c.exp <= now
        || c.exp <= c.iat
        || c.exp > c.iat.saturating_add(60)
    {
        return Err(ERROR);
    }
    key.verifying_key()
        .map_err(|_| ERROR)?
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &Signature::from_slice(&decode(parts[2])?).map_err(|_| ERROR)?,
        )
        .map_err(|_| ERROR)
}
