use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use serde::{Deserialize, Serialize};

/// ES256 signing capability loaded from a private P-256 JWK. The private
/// scalar is never serializable or printable.
pub struct P256TokenSigner {
    kid: String,
    key: SigningKey,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateJwk {
    kty: String,
    crv: String,
    kid: String,
    d: String,
    x: String,
    y: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    use_: Option<String>,
    #[serde(default)]
    key_ops: Option<Vec<String>>,
    #[serde(default)]
    ext: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicJwk {
    kty: String,
    crv: String,
    kid: String,
    x: String,
    y: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    use_: Option<String>,
    #[serde(default)]
    key_ops: Option<Vec<String>>,
    #[serde(default)]
    ext: Option<bool>,
}

#[derive(Serialize)]
struct ProtectedHeader<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'static str,
}

#[derive(Serialize)]
struct IdTokenClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
    nonce: &'a str,
    sid: &'a str,
    auth_time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSigningKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidIdTokenClaims;

impl P256TokenSigner {
    /// Validate and return a minimal public ES256 JWK suitable for a JWKS.
    /// Unknown/private parameters are rejected rather than reflected.
    pub fn canonical_public_jwk(input: &str) -> Option<String> {
        if input.len() > 4096 {
            return None;
        }
        let jwk: PublicJwk = serde_json::from_str(input).ok()?;
        if jwk.kty != "EC"
            || jwk.crv != "P-256"
            || jwk.kid.is_empty()
            || jwk.kid.len() > 128
            || jwk.kid.bytes().any(|byte| byte.is_ascii_control())
            || jwk.alg.as_deref().is_some_and(|alg| alg != "ES256")
            || jwk.use_.as_deref().is_some_and(|key_use| key_use != "sig")
            || jwk.key_ops.as_ref().is_some_and(|ops| ops != &["verify"])
            || jwk.ext == Some(false)
        {
            return None;
        }
        let x = decode_fixed::<32>(&jwk.x).ok()?;
        let y = decode_fixed::<32>(&jwk.y).ok()?;
        let mut point = [0u8; 65];
        point[0] = 4;
        point[1..33].copy_from_slice(&x);
        point[33..].copy_from_slice(&y);
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).ok()?;
        serde_json::to_string(&PublicJwk {
            kty: jwk.kty,
            crv: jwk.crv,
            kid: jwk.kid,
            x: jwk.x,
            y: jwk.y,
            alg: Some("ES256".into()),
            use_: Some("sig".into()),
            key_ops: None,
            ext: None,
        })
        .ok()
    }

    pub fn from_private_jwk(input: &str) -> Result<Self, InvalidSigningKey> {
        if input.len() > 8192 {
            return Err(InvalidSigningKey);
        }
        let jwk: PrivateJwk = serde_json::from_str(input).map_err(|_| InvalidSigningKey)?;
        if jwk.kty != "EC"
            || jwk.crv != "P-256"
            || jwk.kid.is_empty()
            || jwk.kid.len() > 128
            || jwk.kid.bytes().any(|byte| byte.is_ascii_control())
            || jwk.alg.as_deref().is_some_and(|alg| alg != "ES256")
            || jwk.use_.as_deref().is_some_and(|key_use| key_use != "sig")
            || jwk.key_ops.as_ref().is_some_and(|ops| ops != &["sign"])
            || jwk.ext == Some(false)
        {
            return Err(InvalidSigningKey);
        }
        let scalar = decode_fixed::<32>(&jwk.d)?;
        let x = decode_fixed::<32>(&jwk.x)?;
        let y = decode_fixed::<32>(&jwk.y)?;
        let key = SigningKey::from_slice(&scalar).map_err(|_| InvalidSigningKey)?;
        let mut encoded_public = [0u8; 65];
        encoded_public[0] = 4;
        encoded_public[1..33].copy_from_slice(&x);
        encoded_public[33..].copy_from_slice(&y);
        let expected = p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded_public)
            .map_err(|_| InvalidSigningKey)?;
        if key.verifying_key() != &expected {
            return Err(InvalidSigningKey);
        }
        Ok(Self { kid: jwk.kid, key })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn matches_public_jwk(&self, input: &str) -> bool {
        if input.len() > 4096 {
            return false;
        }
        let Ok(jwk) = serde_json::from_str::<PublicJwk>(input) else {
            return false;
        };
        if jwk.kty != "EC"
            || jwk.crv != "P-256"
            || jwk.kid != self.kid
            || jwk.alg.as_deref().is_some_and(|alg| alg != "ES256")
            || jwk.use_.as_deref().is_some_and(|key_use| key_use != "sig")
            || jwk
                .key_ops
                .as_ref()
                .is_some_and(|ops| ops.len() != 1 || ops[0] != "verify")
            || jwk.ext == Some(false)
        {
            return false;
        }
        let (Ok(x), Ok(y)) = (decode_fixed::<32>(&jwk.x), decode_fixed::<32>(&jwk.y)) else {
            return false;
        };
        let point = self.key.verifying_key().to_sec1_point(false);
        point.x().is_some_and(|actual| actual.as_slice() == x)
            && point.y().is_some_and(|actual| actual.as_slice() == y)
    }

    pub fn sign_id_token(
        &self,
        issuer: &str,
        subject: &str,
        audience: &str,
        sid: &str,
        nonce: &str,
        auth_time: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<String, InvalidIdTokenClaims> {
        if !issuer.starts_with("https://")
            || issuer.len() > 2048
            || subject.is_empty()
            || audience.is_empty()
            || sid.is_empty()
            || nonce.is_empty()
            || issued_at == 0
            || expires_at <= issued_at
            || auth_time > issued_at
        {
            return Err(InvalidIdTokenClaims);
        }
        let header = serde_json::to_vec(&ProtectedHeader {
            alg: "ES256",
            kid: &self.kid,
            typ: "JWT",
        })
        .map_err(|_| InvalidIdTokenClaims)?;
        let claims = serde_json::to_vec(&IdTokenClaims {
            iss: issuer,
            sub: subject,
            aud: audience,
            iat: issued_at,
            exp: expires_at,
            nonce,
            sid,
            auth_time,
        })
        .map_err(|_| InvalidIdTokenClaims)?;
        let signing_input = format!("{}.{}", B64.encode(header), B64.encode(claims));
        let signature: Signature = self.key.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            B64.encode(signature.to_bytes())
        ))
    }
}

fn decode_fixed<const N: usize>(input: &str) -> Result<[u8; N], InvalidSigningKey> {
    let decoded = B64.decode(input).map_err(|_| InvalidSigningKey)?;
    let value: [u8; N] = decoded.try_into().map_err(|_| InvalidSigningKey)?;
    if B64.encode(value) != input {
        return Err(InvalidSigningKey);
    }
    Ok(value)
}
