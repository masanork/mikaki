//! HAIP Appendix E: bounded ES256 attester certificates and instance-key PoP.
//! Trust is provisioned per attester; no network or system-root discovery.
use crate::{certificate::decode_certificate, issuance::PublicJwk};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{Signature, signature::Verifier};
use serde::Deserialize;

// RFC 7519 §4.1.5 permits a small leeway for clock skew; keep nbf aligned with iat.
const CLOCK_SKEW_LEEWAY_SECONDS: u64 = 30;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttesterTrust {
    pub issuer: String,
    pub trust_anchors: Vec<String>,
}
#[derive(Deserialize)]
struct Header {
    typ: String,
    alg: String,
    x5c: Option<Vec<String>>,
    crit: Option<serde_json::Value>,
    b64: Option<serde_json::Value>,
    jku: Option<serde_json::Value>,
    x5u: Option<serde_json::Value>,
}
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    d: Option<serde_json::Value>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
}
impl Jwk {
    fn public(self) -> Result<PublicJwk, &'static str> {
        if self.d.is_some()
            || self.alg.is_some_and(|a| a != "ES256")
            || self.usage.is_some_and(|u| u != "sig")
        {
            return Err("invalid_client");
        }
        let key = PublicJwk {
            kty: self.kty,
            crv: self.crv,
            x: self.x,
            y: self.y,
        };
        key.verifying_key()?;
        Ok(key)
    }
}
#[derive(Deserialize)]
struct Confirmation {
    jwk: Jwk,
}
#[derive(Deserialize)]
struct Attestation {
    iss: String,
    sub: String,
    exp: u64,
    iat: Option<u64>,
    nbf: Option<u64>,
    cnf: Confirmation,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
impl Audience {
    fn contains(&self, issuer: &str) -> bool {
        match self {
            Self::One(a) => a == issuer,
            Self::Many(a) => a.len() <= 8 && a.iter().any(|s| s == issuer),
        }
    }
}
#[derive(Deserialize)]
struct Pop {
    iss: String,
    aud: Audience,
    iat: u64,
    jti: String,
    exp: Option<u64>,
    nbf: Option<u64>,
}
/// Persist only this authenticated binding and a hashed, expiring replay ID.
pub struct VerifiedAttestation {
    pub thumbprint: String,
    pub attester: String,
    pub replay_id: String,
    pub replay_until: u64,
    pub expires_at: u64,
}
fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let b = B64.decode(s).map_err(|_| "invalid_client")?;
    if b.is_empty() || B64.encode(&b) != s {
        return Err("invalid_client");
    }
    Ok(b)
}
fn jwt<T: serde::de::DeserializeOwned>(
    s: &str,
    typ: &str,
) -> Result<(Header, T, String, Signature), &'static str> {
    if s.len() > 24576 {
        return Err("invalid_client");
    }
    let parts: Vec<_> = s.split('.').collect();
    if parts.len() != 3 {
        return Err("invalid_client");
    }
    let h: Header = serde_json::from_slice(&decode(parts[0])?).map_err(|_| "invalid_client")?;
    if h.typ != typ
        || h.alg != "ES256"
        || h.crit.is_some()
        || h.b64.is_some()
        || h.jku.is_some()
        || h.x5u.is_some()
    {
        return Err("invalid_client");
    }
    let payload = serde_json::from_slice(&decode(parts[1])?).map_err(|_| "invalid_client")?;
    let sig = Signature::from_slice(&decode(parts[2])?).map_err(|_| "invalid_client")?;
    Ok((h, payload, format!("{}.{}", parts[0], parts[1]), sig))
}
/// Routing hint only. The caller MUST verify both JWTs against this client before use.
pub fn unverified_client_id(attestation: &str) -> Result<String, &'static str> {
    let (_, claims, _, _) = jwt::<Attestation>(attestation, "oauth-client-attestation+jwt")?;
    if claims.sub.is_empty() || claims.sub.len() > 256 {
        return Err("invalid_client");
    }
    Ok(claims.sub)
}
pub fn verify(
    attestation: &str,
    pop: &str,
    client: &str,
    issuer: &str,
    policies: &[AttesterTrust],
    now: u64,
) -> Result<VerifiedAttestation, &'static str> {
    let (header, claims, message, sig) =
        jwt::<Attestation>(attestation, "oauth-client-attestation+jwt")?;
    if claims.sub != client
        || claims.exp <= now
        || claims
            .iat
            .is_some_and(|t| t > now.saturating_add(CLOCK_SKEW_LEEWAY_SECONDS) || t >= claims.exp)
        || claims
            .nbf
            .is_some_and(|t| t > now.saturating_add(CLOCK_SKEW_LEEWAY_SECONDS) || t >= claims.exp)
    {
        return Err("invalid_client");
    }
    let policy = policies
        .iter()
        .find(|p| p.issuer == claims.iss)
        .ok_or("invalid_client")?;
    let chain = header
        .x5c
        .ok_or("invalid_client")?
        .iter()
        .map(|c| decode_certificate(c))
        .collect::<Result<Vec<_>, _>>()?;
    let (key, deadline) =
        crate::certificate::verify_attester_chain(&chain, &policy.trust_anchors, now)?;
    key.verify(message.as_bytes(), &sig)
        .map_err(|_| "invalid_client")?;
    let instance = claims.cnf.jwk.public()?;
    let (header, proof, message, sig) = jwt::<Pop>(pop, "oauth-client-attestation-pop+jwt")?;
    if header.x5c.is_some()
        || proof.iss != client
        || !proof.aud.contains(issuer)
        || proof.iat > now.saturating_add(CLOCK_SKEW_LEEWAY_SECONDS)
        || now.saturating_sub(proof.iat) > 300
        || proof.exp.is_some_and(|t| t <= now || t <= proof.iat)
        || proof.nbf.is_some_and(|t| {
            t > now.saturating_add(CLOCK_SKEW_LEEWAY_SECONDS)
                || proof.exp.is_some_and(|exp| t >= exp)
        })
        || proof.jti.is_empty()
        || proof.jti.len() > 128
    {
        return Err("invalid_client");
    }
    instance
        .verifying_key()?
        .verify(message.as_bytes(), &sig)
        .map_err(|_| "invalid_client")?;
    Ok(VerifiedAttestation {
        thumbprint: instance.thumbprint()?,
        attester: claims.iss,
        replay_id: proof.jti,
        replay_until: proof.iat.saturating_add(331),
        expires_at: claims.exp.min(deadline),
    })
}
