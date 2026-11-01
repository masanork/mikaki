//! Bounded ES256 W3C Device Bound Session Credentials (DBSC) verification.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

use crate::es256::Es256Verification;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidDbscProof;

/// Verified proof for DBSC session registration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct DbscRegistrationProof {
    pub sec1_public_key: Vec<u8>,
    pub public_key_jwk: String,
    pub thumbprint: String,
    pub challenge: String,
    pub issued_at: Option<u64>,
}

/// Verified proof for DBSC session refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub struct DbscRefreshProof {
    pub challenge: String,
    pub session_id: Option<String>,
    pub issued_at: Option<u64>,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: String,
    #[serde(default)]
    jwk: Option<PublicKey>,
    #[serde(flatten)]
    extensions: std::collections::BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKey {
    kty: String,
    crv: String,
    x: String,
    y: String,
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
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    iat: Option<u64>,
}

fn decode(value: &str) -> Result<Vec<u8>, InvalidDbscProof> {
    let bytes = B64.decode(value).map_err(|_| InvalidDbscProof)?;
    if B64.encode(&bytes) != value {
        return Err(InvalidDbscProof);
    }
    Ok(bytes)
}

fn split_compact(compact: &str) -> Result<(&str, &str, &str), InvalidDbscProof> {
    if compact.len() > 8192 {
        return Err(InvalidDbscProof);
    }
    let mut parts = compact.split('.');
    let (Some(h), Some(c), Some(s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(InvalidDbscProof);
    };
    Ok((h, c, s))
}

fn validate_claims(claims: &Claims, expected_challenge: &str, now: u64) -> Result<(), InvalidDbscProof> {
    if claims.jti != expected_challenge
        || expected_challenge.is_empty()
        || claims.jti.len() > 256
        || claims.jti.bytes().any(|b| b.is_ascii_control())
    {
        return Err(InvalidDbscProof);
    }
    if let Some(iat) = claims.iat {
        if iat > now.saturating_add(60) || now > iat.saturating_add(120) {
            return Err(InvalidDbscProof);
        }
    }
    Ok(())
}

fn parse_dbsc_registration(
    compact: &str,
    expected_challenge: &str,
    now: u64,
) -> Result<(Es256Verification, DbscRegistrationProof), InvalidDbscProof> {
    let (h, c, s) = split_compact(compact)?;
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| InvalidDbscProof)?;
    let claims: Claims = serde_json::from_slice(&decode(c)?).map_err(|_| InvalidDbscProof)?;

    if ["crit", "b64", "jku", "x5u"]
        .iter()
        .any(|key| header.extensions.contains_key(*key))
        || header.alg != "ES256"
        || header.typ != "dbsc+jwt"
    {
        return Err(InvalidDbscProof);
    }

    validate_claims(&claims, expected_challenge, now)?;

    let Some(jwk) = header.jwk else {
        return Err(InvalidDbscProof);
    };

    if jwk.kty != "EC"
        || jwk.crv != "P-256"
        || jwk.alg.as_deref().is_some_and(|a| a != "ES256")
        || jwk.use_.as_deref().is_some_and(|u| u != "sig")
        || jwk.kid.as_ref().is_some_and(|k| k.len() > 128)
    {
        return Err(InvalidDbscProof);
    }

    let x = decode(&jwk.x)?;
    let y = decode(&jwk.y)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(InvalidDbscProof);
    }

    let mut sec1 = vec![4];
    sec1.extend(x);
    sec1.extend(y);

    let canonical_jwk = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk.x, jwk.y
    );
    let thumbprint = B64.encode(Sha256::digest(canonical_jwk.as_bytes()));

    let verification = Es256Verification::new(&sec1, &decode(s)?, format!("{h}.{c}").as_bytes())
        .map_err(|_| InvalidDbscProof)?;

    Ok((
        verification,
        DbscRegistrationProof {
            sec1_public_key: sec1,
            public_key_jwk: canonical_jwk,
            thumbprint,
            challenge: claims.jti,
            issued_at: claims.iat,
        },
    ))
}

pub async fn verify_dbsc_registration_async(
    compact: &str,
    expected_challenge: &str,
    now: u64,
) -> Result<DbscRegistrationProof, InvalidDbscProof> {
    let (verification, proof) = parse_dbsc_registration(compact, expected_challenge, now)?;
    verification.verify_async().await.map_err(|_| InvalidDbscProof)?;
    Ok(proof)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_dbsc_registration(
    compact: &str,
    expected_challenge: &str,
    now: u64,
) -> Result<DbscRegistrationProof, InvalidDbscProof> {
    let (verification, proof) = parse_dbsc_registration(compact, expected_challenge, now)?;
    verification.verify_reference().map_err(|_| InvalidDbscProof)?;
    Ok(proof)
}

fn parse_dbsc_refresh(
    compact: &str,
    expected_challenge: &str,
    sec1_public_key: &[u8],
    now: u64,
) -> Result<(Es256Verification, DbscRefreshProof), InvalidDbscProof> {
    let (h, c, s) = split_compact(compact)?;
    let header: Header = serde_json::from_slice(&decode(h)?).map_err(|_| InvalidDbscProof)?;
    let claims: Claims = serde_json::from_slice(&decode(c)?).map_err(|_| InvalidDbscProof)?;

    if ["crit", "b64", "jku", "x5u"]
        .iter()
        .any(|key| header.extensions.contains_key(*key))
        || header.alg != "ES256"
        || header.typ != "dbsc+jwt"
    {
        return Err(InvalidDbscProof);
    }

    validate_claims(&claims, expected_challenge, now)?;

    let verification =
        Es256Verification::new(sec1_public_key, &decode(s)?, format!("{h}.{c}").as_bytes())
            .map_err(|_| InvalidDbscProof)?;

    Ok((
        verification,
        DbscRefreshProof {
            challenge: claims.jti,
            session_id: claims.sub,
            issued_at: claims.iat,
        },
    ))
}

pub async fn verify_dbsc_refresh_async(
    compact: &str,
    expected_challenge: &str,
    sec1_public_key: &[u8],
    now: u64,
) -> Result<DbscRefreshProof, InvalidDbscProof> {
    let (verification, proof) =
        parse_dbsc_refresh(compact, expected_challenge, sec1_public_key, now)?;
    verification.verify_async().await.map_err(|_| InvalidDbscProof)?;
    Ok(proof)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_dbsc_refresh(
    compact: &str,
    expected_challenge: &str,
    sec1_public_key: &[u8],
    now: u64,
) -> Result<DbscRefreshProof, InvalidDbscProof> {
    let (verification, proof) =
        parse_dbsc_refresh(compact, expected_challenge, sec1_public_key, now)?;
    verification.verify_reference().map_err(|_| InvalidDbscProof)?;
    Ok(proof)
}
