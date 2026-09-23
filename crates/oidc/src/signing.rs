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
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    use_: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    key_ops: Option<Vec<String>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    use_: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    key_ops: Option<Vec<String>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    ext: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RsaPrivateJwk {
    kty: String,
    kid: String,
    n: String,
    e: String,
    d: String,
    p: String,
    q: String,
    dp: String,
    dq: String,
    qi: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    use_: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    key_ops: Option<Vec<String>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    ext: Option<bool>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RsaPublicJwk {
    kty: String,
    kid: String,
    n: String,
    e: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(default, rename = "use", skip_serializing_if = "Option::is_none")]
    use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_ops: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ext: Option<bool>,
}

#[derive(Serialize)]
struct ProtectedHeader<'a> {
    alg: &'a str,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    sid: &'a str,
    auth_time: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidSigningKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidIdTokenClaims;

/// Validated RS256 JWK material for import into the platform WebCrypto API.
/// The private parameters are never serializable through Debug or public fields.
pub struct RsaPrivateTokenKey {
    jwk: RsaPrivateJwk,
}

/// A compact JWS payload ready for the platform's selected signing operation.
pub struct IdTokenSigningInput {
    algorithm: &'static str,
    signing_input: String,
}

impl P256TokenSigner {
    /// Validate and return a minimal public ES256 JWK suitable for a JWKS.
    /// Unknown/private parameters are rejected rather than reflected.
    pub fn canonical_public_jwk(input: &str) -> Option<String> {
        if input.len() > 4096 {
            return None;
        }
        let value: serde_json::Value = serde_json::from_str(input).ok()?;
        if value.get("kty")?.as_str()? == "RSA" {
            let jwk: RsaPublicJwk = serde_json::from_value(value).ok()?;
            validate_rsa_public_metadata(&jwk).then_some(())?;
            return serde_json::to_string(&RsaPublicJwk {
                kty: "RSA".into(),
                kid: jwk.kid,
                n: jwk.n,
                e: jwk.e,
                alg: Some("RS256".into()),
                use_: Some("sig".into()),
                key_ops: None,
                ext: None,
            })
            .ok();
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

    #[allow(clippy::too_many_arguments)]
    pub fn sign_id_token(
        &self,
        issuer: &str,
        subject: &str,
        audience: &str,
        sid: &str,
        nonce: Option<&str>,
        auth_time: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<String, InvalidIdTokenClaims> {
        if !issuer.starts_with("https://")
            || issuer.len() > 2048
            || subject.is_empty()
            || audience.is_empty()
            || sid.is_empty()
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

impl RsaPrivateTokenKey {
    pub fn from_private_jwk(input: &str) -> Result<Self, InvalidSigningKey> {
        if input.len() > 8192 {
            return Err(InvalidSigningKey);
        }
        let jwk: RsaPrivateJwk = serde_json::from_str(input).map_err(|_| InvalidSigningKey)?;
        if jwk.kty != "RSA"
            || jwk.kid.is_empty()
            || jwk.kid.len() > 128
            || jwk.kid.bytes().any(|byte| byte.is_ascii_control())
            || jwk.alg.as_deref().is_some_and(|alg| alg != "RS256")
            || jwk.use_.as_deref().is_some_and(|key_use| key_use != "sig")
            || jwk.key_ops.as_ref().is_some_and(|ops| ops != &["sign"])
            || jwk.ext == Some(false)
        {
            return Err(InvalidSigningKey);
        }
        let modulus = decode_base64url_uint(&jwk.n, 256, 512)?;
        let exponent = decode_base64url_uint(&jwk.e, 1, 4)?;
        if modulus[0] < 0x80
            || (modulus.len() == 512 && modulus[0] > 0x0f)
            || modulus.last().is_none_or(|byte| byte & 1 == 0)
            || exponent_value(&exponent).is_none_or(|value| value < 3 || value & 1 == 0)
        {
            return Err(InvalidSigningKey);
        }
        decode_base64url_uint(&jwk.d, 1, 512)?;
        decode_base64url_uint(&jwk.p, 1, 256)?;
        decode_base64url_uint(&jwk.q, 1, 256)?;
        decode_base64url_uint(&jwk.dp, 1, 256)?;
        decode_base64url_uint(&jwk.dq, 1, 256)?;
        decode_base64url_uint(&jwk.qi, 1, 256)?;
        Ok(Self { jwk })
    }

    pub fn kid(&self) -> &str {
        &self.jwk.kid
    }

    pub fn modulus_bytes(&self) -> usize {
        B64.decode(&self.jwk.n).map_or(0, |modulus| modulus.len())
    }

    pub fn webcrypto_private_jwk_json(&self) -> Result<String, InvalidSigningKey> {
        serde_json::to_string(&RsaPrivateJwk {
            kty: "RSA".into(),
            kid: self.jwk.kid.clone(),
            n: self.jwk.n.clone(),
            e: self.jwk.e.clone(),
            d: self.jwk.d.clone(),
            p: self.jwk.p.clone(),
            q: self.jwk.q.clone(),
            dp: self.jwk.dp.clone(),
            dq: self.jwk.dq.clone(),
            qi: self.jwk.qi.clone(),
            alg: Some("RS256".into()),
            use_: Some("sig".into()),
            key_ops: Some(vec!["sign".into()]),
            ext: None,
        })
        .map_err(|_| InvalidSigningKey)
    }

    pub fn matches_public_jwk(&self, input: &str) -> bool {
        let Some(canonical) = P256TokenSigner::canonical_public_jwk(input) else {
            return false;
        };
        let Ok(public) = serde_json::from_str::<RsaPublicJwk>(&canonical) else {
            return false;
        };
        public.kty == "RSA"
            && public.kid == self.jwk.kid
            && public.n == self.jwk.n
            && public.e == self.jwk.e
    }
}

impl IdTokenSigningInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        algorithm: &'static str,
        kid: &str,
        issuer: &str,
        subject: &str,
        audience: &str,
        sid: &str,
        nonce: Option<&str>,
        auth_time: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, InvalidIdTokenClaims> {
        if !["ES256", "RS256"].contains(&algorithm)
            || kid.is_empty()
            || kid.len() > 128
            || kid.bytes().any(|byte| byte.is_ascii_control())
            || !issuer.starts_with("https://")
            || issuer.len() > 2048
            || subject.is_empty()
            || audience.is_empty()
            || sid.is_empty()
            || issued_at == 0
            || expires_at <= issued_at
            || auth_time > issued_at
        {
            return Err(InvalidIdTokenClaims);
        }
        let header = serde_json::to_vec(&ProtectedHeader {
            alg: algorithm,
            kid,
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
        Ok(Self {
            algorithm,
            signing_input: format!("{}.{}", B64.encode(header), B64.encode(claims)),
        })
    }

    pub fn algorithm(&self) -> &str {
        self.algorithm
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.signing_input.as_bytes()
    }

    pub fn finish(self, signature: &[u8]) -> Result<String, InvalidIdTokenClaims> {
        let valid_length = match self.algorithm {
            "ES256" => signature.len() == 64,
            "RS256" => (256..=512).contains(&signature.len()),
            _ => false,
        };
        if !valid_length {
            return Err(InvalidIdTokenClaims);
        }
        Ok(format!("{}.{}", self.signing_input, B64.encode(signature)))
    }
}

fn validate_rsa_public_metadata(jwk: &RsaPublicJwk) -> bool {
    if jwk.kty != "RSA"
        || jwk.kid.is_empty()
        || jwk.kid.len() > 128
        || jwk.kid.bytes().any(|byte| byte.is_ascii_control())
        || jwk.alg.as_deref().is_some_and(|alg| alg != "RS256")
        || jwk.use_.as_deref().is_some_and(|key_use| key_use != "sig")
        || jwk
            .key_ops
            .as_ref()
            .is_some_and(|ops| !ops.is_empty() && ops != &["verify"])
        || jwk.ext == Some(false)
    {
        return false;
    }
    let (Ok(modulus), Ok(exponent)) = (
        decode_base64url_uint(&jwk.n, 256, 512),
        decode_base64url_uint(&jwk.e, 1, 4),
    ) else {
        return false;
    };
    modulus[0] >= 0x80
        && (modulus.len() < 512 || modulus[0] <= 0x0f)
        && modulus.last().is_some_and(|byte| byte & 1 == 1)
        && exponent_value(&exponent).is_some_and(|value| value >= 3 && value & 1 == 1)
}

fn decode_base64url_uint(
    input: &str,
    min_bytes: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, InvalidSigningKey> {
    let bytes = B64.decode(input).map_err(|_| InvalidSigningKey)?;
    if bytes.len() < min_bytes
        || bytes.len() > max_bytes
        || bytes.first().is_none_or(|byte| *byte == 0)
        || B64.encode(&bytes) != input
    {
        return Err(InvalidSigningKey);
    }
    Ok(bytes)
}

fn exponent_value(exponent: &[u8]) -> Option<u32> {
    exponent.iter().try_fold(0u32, |value, byte| {
        value.checked_mul(256)?.checked_add(u32::from(*byte))
    })
}

fn decode_fixed<const N: usize>(input: &str) -> Result<[u8; N], InvalidSigningKey> {
    let decoded = B64.decode(input).map_err(|_| InvalidSigningKey)?;
    let value: [u8; N] = decoded.try_into().map_err(|_| InvalidSigningKey)?;
    if B64.encode(value) != input {
        return Err(InvalidSigningKey);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rs256_public_jwk_is_canonicalized_and_private_fields_rejected() {
        let mut modulus = [0x80u8; 256];
        modulus[255] = 0x81;
        let jwk = serde_json::json!({
            "kty":"RSA", "kid":"op-1", "n":B64.encode(modulus), "e":"AQAB",
            "alg":"RS256", "use":"sig", "key_ops":["verify"]
        })
        .to_string();
        let canonical = P256TokenSigner::canonical_public_jwk(&jwk).unwrap();
        let value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        assert_eq!(value["alg"], "RS256");
        assert_eq!(value["use"], "sig");
        assert!(value.get("d").is_none());
        let private = jwk.replace("\"kid\":\"op-1\"", "\"kid\":\"op-1\",\"d\":\"AQ\"");
        assert!(P256TokenSigner::canonical_public_jwk(&private).is_none());
    }

    #[test]
    fn rsa_public_jwk_rejects_short_modulus_and_even_exponent() {
        let modulus = B64.encode([0x80u8; 255]);
        let jwk = format!(r#"{{"kty":"RSA","kid":"op-1","n":"{modulus}","e":"AQAB"}}"#);
        assert!(P256TokenSigner::canonical_public_jwk(&jwk).is_none());
        let mut modulus_bytes = [0x80u8; 256];
        modulus_bytes[255] = 0x81;
        let modulus = B64.encode(modulus_bytes);
        let jwk = format!(r#"{{"kty":"RSA","kid":"op-1","n":"{modulus}","e":"Ag"}}"#);
        assert!(P256TokenSigner::canonical_public_jwk(&jwk).is_none());
    }

    #[test]
    fn rsa_public_jwk_accepts_empty_webcrypto_key_ops() {
        let mut modulus_bytes = [0x80u8; 256];
        modulus_bytes[255] = 0x81;
        let modulus = B64.encode(modulus_bytes);
        let jwk =
            format!(r#"{{"kty":"RSA","kid":"op-1","n":"{modulus}","e":"AQAB","key_ops":[]}}"#);
        let canonical = P256TokenSigner::canonical_public_jwk(&jwk).unwrap();
        assert!(!canonical.contains("key_ops"));
    }

    #[test]
    fn es256_private_key_matches_its_registered_public_jwk() {
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        let key = SigningKey::from_slice(&scalar).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let public_jwk = serde_json::json!({
            "kty":"EC", "crv":"P-256", "kid":"op-1",
            "x":B64.encode(point.x().unwrap()), "y":B64.encode(point.y().unwrap()),
            "alg":"ES256", "use":"sig"
        })
        .to_string();
        let private_jwk = serde_json::json!({
            "kty":"EC", "crv":"P-256", "kid":"op-1",
            "d":B64.encode(scalar), "x":B64.encode(point.x().unwrap()),
            "y":B64.encode(point.y().unwrap()), "alg":"ES256", "use":"sig"
        })
        .to_string();
        let signer = P256TokenSigner::from_private_jwk(&private_jwk).unwrap();
        assert!(signer.matches_public_jwk(&public_jwk));
        let different = public_jwk.replace("op-1", "op-2");
        assert!(!signer.matches_public_jwk(&different));
    }

    #[test]
    fn rs256_jws_input_requires_a_modulus_sized_signature() {
        let input = IdTokenSigningInput::new(
            "RS256",
            "op-1",
            "https://issuer.example",
            "sub",
            "client",
            "sid",
            Some("nonce"),
            10,
            11,
            12,
        )
        .unwrap();
        assert_eq!(input.algorithm(), "RS256");
        assert!(input.finish(&[0u8; 255]).is_err());
        let input = IdTokenSigningInput::new(
            "RS256",
            "op-1",
            "https://issuer.example",
            "sub",
            "client",
            "sid",
            Some("nonce"),
            10,
            11,
            12,
        )
        .unwrap();
        let token = input.finish(&[0u8; 256]).unwrap();
        assert_eq!(token.split('.').count(), 3);
    }
}
