use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::Deserialize;

const MAX_ASSERTION_BYTES: usize = 16_384;

/// A public key snapshot loaded from trusted client registration storage.
/// Do not build this from the assertion itself. Its revision and key id must
/// be rechecked by the final D1 operation.
pub struct ClientAssertionKey {
    client_id: String,
    key_id: String,
    client_revision: u64,
    key_revision: u64,
    active: bool,
    sec1_public_key: Vec<u8>,
}

/// Validated timing policy for private_key_jwt assertions.
#[derive(Clone, Copy)]
pub struct ClientAssertionPolicy {
    maximum_lifetime_seconds: u64,
    clock_skew_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeader {
    alg: String,
    kid: String,
    #[serde(default)]
    typ: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn matches_exactly(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.len() == 1 && values[0] == expected,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    jti: String,
}

/// Proof that a compact private_key_jwt passed strict ES256 and claim checks.
/// It is not deserializable; the final store operation must still recheck the
/// client and key revisions and atomically reserve `(client_id, jti)`.
#[must_use = "reserve this assertion jti once in D1 before processing its grant"]
pub struct VerifiedClientAssertion {
    client_id: String,
    key_id: String,
    client_revision: u64,
    key_revision: u64,
    audience: String,
    jti: String,
    issued_at: u64,
    retain_until: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidClientAssertion;

impl ClientAssertionPolicy {
    pub fn from_seconds(
        maximum_lifetime_seconds: u64,
        clock_skew_seconds: u64,
    ) -> Result<Self, InvalidClientAssertion> {
        if maximum_lifetime_seconds == 0
            || clock_skew_seconds == 0
            || maximum_lifetime_seconds > i64::MAX as u64
            || clock_skew_seconds > i64::MAX as u64 - maximum_lifetime_seconds
        {
            return Err(InvalidClientAssertion);
        }
        Ok(Self {
            maximum_lifetime_seconds,
            clock_skew_seconds,
        })
    }
}

impl ClientAssertionKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: String,
        key_id: String,
        client_revision: u64,
        key_revision: u64,
        active: bool,
        sec1_public_key: Vec<u8>,
    ) -> Self {
        Self {
            client_id,
            key_id,
            client_revision,
            key_revision,
            active,
            sec1_public_key,
        }
    }

    pub fn verify_private_key_jwt(
        &self,
        compact: &str,
        expected_audience: &str,
        now: u64,
        policy: ClientAssertionPolicy,
    ) -> Result<VerifiedClientAssertion, InvalidClientAssertion> {
        if !self.active
            || self.client_id.is_empty()
            || self.key_id.is_empty()
            || compact.len() > MAX_ASSERTION_BYTES
            || expected_audience.is_empty()
        {
            return Err(InvalidClientAssertion);
        }

        let mut parts = compact.split('.');
        let (Some(header_part), Some(claims_part), Some(signature_part), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(InvalidClientAssertion);
        };
        if header_part.is_empty() || claims_part.is_empty() || signature_part.is_empty() {
            return Err(InvalidClientAssertion);
        }

        let header_bytes = decode_segment(header_part)?;
        let claims_bytes = decode_segment(claims_part)?;
        let signature_bytes = decode_segment(signature_part)?;
        let header: ProtectedHeader =
            serde_json::from_slice(&header_bytes).map_err(|_| InvalidClientAssertion)?;
        let claims: Claims =
            serde_json::from_slice(&claims_bytes).map_err(|_| InvalidClientAssertion)?;

        if header.alg != "ES256"
            || header.kid != self.key_id
            || header.typ.as_deref().is_some_and(|typ| typ != "JWT")
            || claims.iss != self.client_id
            || claims.sub != self.client_id
            || !claims.aud.matches_exactly(expected_audience)
            || claims.jti.is_empty()
            || claims.jti.len() > 256
            || claims.jti.bytes().any(|byte| byte.is_ascii_control())
            || claims.exp <= claims.iat
            || claims.exp.saturating_sub(claims.iat) > policy.maximum_lifetime_seconds
            || claims.iat > now.saturating_add(policy.clock_skew_seconds)
            || claims.exp <= now.saturating_sub(policy.clock_skew_seconds)
        {
            return Err(InvalidClientAssertion);
        }

        let verifying_key = VerifyingKey::from_sec1_bytes(&self.sec1_public_key)
            .map_err(|_| InvalidClientAssertion)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| InvalidClientAssertion)?;
        let signing_input = format!("{header_part}.{claims_part}");
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| InvalidClientAssertion)?;

        Ok(VerifiedClientAssertion {
            client_id: self.client_id.clone(),
            key_id: self.key_id.clone(),
            client_revision: self.client_revision,
            key_revision: self.key_revision,
            audience: expected_audience.to_owned(),
            jti: claims.jti,
            issued_at: claims.iat,
            retain_until: claims
                .exp
                .checked_add(policy.clock_skew_seconds)
                .ok_or(InvalidClientAssertion)?,
        })
    }
}

/// Read `kid` only for a bounded registration lookup. This does not establish
/// client identity or validate the assertion; callers must still verify the
/// complete JWS with the matching registered key.
pub fn client_assertion_key_id(compact: &str) -> Result<String, InvalidClientAssertion> {
    if compact.len() > MAX_ASSERTION_BYTES {
        return Err(InvalidClientAssertion);
    }
    let mut parts = compact.split('.');
    let (Some(header_part), Some(claims_part), Some(signature_part), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(InvalidClientAssertion);
    };
    if header_part.is_empty() || claims_part.is_empty() || signature_part.is_empty() {
        return Err(InvalidClientAssertion);
    }
    let header_bytes = decode_segment(header_part)?;
    let header: ProtectedHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| InvalidClientAssertion)?;
    if header.alg != "ES256"
        || header.kid.is_empty()
        || header.kid.len() > 128
        || header.typ.as_deref().is_some_and(|typ| typ != "JWT")
    {
        return Err(InvalidClientAssertion);
    }
    Ok(header.kid)
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, InvalidClientAssertion> {
    let bytes = B64.decode(segment).map_err(|_| InvalidClientAssertion)?;
    if B64.encode(&bytes) != segment {
        return Err(InvalidClientAssertion);
    }
    Ok(bytes)
}

impl VerifiedClientAssertion {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn client_revision(&self) -> u64 {
        self.client_revision
    }

    pub fn key_revision(&self) -> u64 {
        self.key_revision
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn jti(&self) -> &str {
        &self.jti
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn retain_until(&self) -> u64 {
        self.retain_until
    }
}
