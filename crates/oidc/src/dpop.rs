//! Bounded ES256 RFC 9449 verification. Replay acceptance belongs to D1,
//! after signature verification, never to a process-local cache.
#[cfg(test)]
mod tests;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub enum DpopTarget<'a> {
    Token,
    Resource {
        access_token: &'a str,
        thumbprint: &'a str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidDpopProof;

/// This capability cannot be deserialized or constructed by a caller. Accept
/// its `(thumbprint, jti_hash)` atomically in storage before using the request.
#[must_use]
pub struct VerifiedDpopProof {
    thumbprint: String,
    jti_hash: String,
    issued_at: u64,
    retain_until: u64,
    nonce: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    jwk: PublicKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    kty: String,
    crv: String,
    x: String,
    y: String,
    // Optional public JWK metadata; private and remote-key parameters fail closed.
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    use_: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
struct Claims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    #[serde(default)]
    ath: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

fn decode(value: &str) -> Result<Vec<u8>, InvalidDpopProof> {
    let bytes = B64.decode(value).map_err(|_| InvalidDpopProof)?;
    if B64.encode(&bytes) != value {
        return Err(InvalidDpopProof);
    }
    Ok(bytes)
}

fn endpoint(value: &str) -> Result<String, InvalidDpopProof> {
    if value.len() > 2048
        || value
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err(InvalidDpopProof);
    }
    let mut url = url::Url::parse(value).map_err(|_| InvalidDpopProof)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(InvalidDpopProof);
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

pub fn verify_dpop_proof(
    compact: &str,
    method: &str,
    request_uri: &str,
    target: DpopTarget<'_>,
    now: u64,
) -> Result<VerifiedDpopProof, InvalidDpopProof> {
    if compact.len() > 8192 || !matches!(method, "GET" | "POST") || now > i64::MAX as u64 - 80 {
        return Err(InvalidDpopProof);
    }
    let mut parts = compact.split('.');
    let (Some(h), Some(c), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(InvalidDpopProof);
    };
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| InvalidDpopProof)?;
    let claims: Claims = serde_json::from_slice(&decode(c)?).map_err(|_| InvalidDpopProof)?;
    let jwk = header.jwk;
    if header.alg != "ES256"
        || header.typ != "dpop+jwt"
        || jwk.kty != "EC"
        || jwk.crv != "P-256"
        || jwk.alg.as_deref().is_some_and(|a| a != "ES256")
        || jwk.use_.as_deref().is_some_and(|u| u != "sig")
        || jwk.kid.as_ref().is_some_and(|k| k.len() > 128)
        || claims.htm != method
        || endpoint(&claims.htu)? != endpoint(request_uri)?
        || claims.jti.is_empty()
        || claims.jti.len() > 256
        || claims.jti.bytes().any(|b| b.is_ascii_control())
        || claims.nonce.as_ref().is_some_and(|nonce| {
            nonce.is_empty()
                || nonce.len() > 128
                || !nonce.bytes().all(|b| (0x21..=0x7e).contains(&b))
        })
        || claims.iat > now.saturating_add(10)
        || now > claims.iat.saturating_add(70)
    {
        return Err(InvalidDpopProof);
    }
    let x = decode(&jwk.x)?;
    let y = decode(&jwk.y)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(InvalidDpopProof);
    }
    let mut sec1 = vec![4];
    sec1.extend(x);
    sec1.extend(y);
    let thumbprint = B64.encode(Sha256::digest(
        format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            jwk.x, jwk.y
        )
        .as_bytes(),
    ));
    if let DpopTarget::Resource {
        access_token,
        thumbprint: expected,
    } = target
        && (thumbprint != expected
            || !access_token.is_ascii()
            || claims.ath.as_deref()
                != Some(B64.encode(Sha256::digest(access_token.as_bytes())).as_str()))
    {
        return Err(InvalidDpopProof);
    }
    let signature = Signature::from_slice(&decode(s)?).map_err(|_| InvalidDpopProof)?;
    VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|_| InvalidDpopProof)?
        .verify(format!("{h}.{c}").as_bytes(), &signature)
        .map_err(|_| InvalidDpopProof)?;
    Ok(VerifiedDpopProof {
        thumbprint,
        jti_hash: B64.encode(Sha256::digest(claims.jti.as_bytes())),
        issued_at: claims.iat,
        retain_until: claims.iat + 70,
        nonce: claims.nonce,
    })
}

impl VerifiedDpopProof {
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }
    pub fn jti_hash(&self) -> &str {
        &self.jti_hash
    }
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    pub fn retain_until(&self) -> u64 {
        self.retain_until
    }
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }
}
