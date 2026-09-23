//! Portable WebAuthn verification with explicit ceremony and attestation policy.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ciborium::Value;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Cursor;
mod attestation;
mod certificate;
mod key;
pub mod metadata;
pub use attestation::{
    AttestationEvidence, AttestationPolicy, Metadata, StatusReport, Trust, TrustEvidence,
    hint as attestation_hint,
};
use key::PublicKey;

mod error;
pub use error::Invalid;
use error::ensure;
type Result<T> = std::result::Result<T, Invalid>;

#[derive(Deserialize)]
pub struct Context {
    pub challenge: String,
    pub origin: String,
    pub rp_id: String,
    pub max_bytes: usize,
    pub max_depth: usize,
    #[serde(default)]
    pub user_verification: UserVerification,
    #[serde(default)]
    pub authentication: Authentication,
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<i32>,
    #[serde(default)]
    pub attestation: Option<Trust>,
    #[serde(default)]
    pub attestation_policy: AttestationPolicy,
}
impl Context {
    /// Validate trusted configuration at issuance and again before verification.
    /// This cannot prove randomness, origin ownership, or atomic challenge consumption.
    pub fn validate(&self) -> Result<()> {
        let valid_id =
            |value: &str, limit| decode(value, limit).is_ok_and(|bytes| !bytes.is_empty());
        ensure(
            self.max_bytes > 0
                && self.max_depth > 0
                && valid_id(&self.challenge, self.max_bytes)
                && !self.origin.trim().is_empty()
                && !self.rp_id.trim().is_empty()
                && self.origin == self.origin.trim()
                && self.rp_id == self.rp_id.trim()
                && !self.algorithms.is_empty()
                && self.algorithms.iter().enumerate().all(|(i, algorithm)| {
                    matches!(algorithm, -7 | -8 | -257 | -65535)
                        && !self.algorithms[..i].contains(algorithm)
                }),
            Invalid::Configuration,
        )?;
        if let Authentication::Identified {
            user_handle,
            allowed_credentials,
        } = &self.authentication
        {
            ensure(
                valid_id(user_handle, 64)
                    && !allowed_credentials.is_empty()
                    && allowed_credentials.iter().all(|id| valid_id(id, 1023)),
                Invalid::Configuration,
            )?;
        }
        Ok(())
    }
}
fn default_algorithms() -> Vec<i32> {
    vec![-7]
}

/// Set from trusted server policy, never from the credential response.
#[derive(Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserVerification {
    #[default]
    Required,
    Preferred,
    Discouraged,
}
/// Identified ceremonies bind both account and the issued allow-list.
#[derive(Default, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authentication {
    #[default]
    Discoverable,
    Identified {
        user_handle: String,
        allowed_credentials: Vec<String>,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(default)]
    cross_origin: bool,
    top_origin: Option<String>,
    #[serde(default, deserialize_with = "token_binding")]
    token_binding: Option<TokenBinding>,
}
fn token_binding<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<TokenBinding>, D::Error> {
    TokenBinding::deserialize(d).map(Some)
}
#[derive(Deserialize)]
struct TokenBinding {
    status: TokenBindingStatus,
    id: Option<String>,
}
#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
enum TokenBindingStatus {
    Present,
    Supported,
    NotSupported,
}
#[derive(Deserialize)]
pub struct Registration {
    pub id: String,
    pub client_data: String,
    pub attestation: String,
}
#[derive(Deserialize)]
pub struct Assertion {
    pub id: String,
    pub client_data: String,
    pub authenticator_data: String,
    pub signature: String,
    pub user_handle: Option<String>,
}
#[derive(Deserialize)]
pub struct StoredCredential {
    pub id: String,
    pub public_key: String,
    pub user_handle: String,
    pub counter: u32,
    pub backup_eligible: bool,
}
/// Only the verifier can construct this evidence; never deserialize it.
/// ```compile_fail
/// let forged: sakimori_webauthn::VerifiedRegistration = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Serialize)]
pub struct VerifiedRegistration {
    id: String,
    public_key: String,
    attestation: AttestationEvidence,
    counter: u32,
    backup_eligible: bool,
    backup_state: bool,
    user_verified: bool,
}
impl VerifiedRegistration {
    pub fn attestation(&self) -> &AttestationEvidence {
        &self.attestation
    }
}
#[derive(Serialize)]
/// ```compile_fail
/// let forged = sakimori_webauthn::VerifiedAssertion { counter: 0, backup_state: false };
/// ```
pub struct VerifiedAssertion {
    counter: u32,
    backup_state: bool,
    user_verified: bool,
}

fn require(ok: bool) -> Result<()> {
    if ok { Ok(()) } else { Err(Invalid::Input) }
}
fn decode(s: &str, limit: usize) -> Result<Vec<u8>> {
    ensure(
        s.len() <= limit.saturating_mul(4).div_ceil(3),
        Invalid::Limit,
    )?;
    let bytes = B64.decode(s).map_err(|_| Invalid::Input)?;
    ensure(bytes.len() <= limit, Invalid::Limit)?;
    require(B64.encode(&bytes) == s)?;
    Ok(bytes)
}

/// Bound JSON depth before serde allocates or descends, including unknown fields.
pub fn bounded_json(input: &str, bytes: usize, depth: usize) -> Result<()> {
    ensure(input.len() <= bytes && depth > 0, Invalid::Limit)?;
    let (mut nesting, mut string, mut escaped) = (0usize, false, false);
    for c in input.bytes() {
        if string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                string = false;
            }
        } else {
            match c {
                b'"' => string = true,
                b'{' | b'[' => {
                    nesting += 1;
                    ensure(nesting <= depth, Invalid::Limit)?;
                }
                b'}' | b']' => nesting = nesting.checked_sub(1).ok_or(Invalid::Input)?,
                _ => (),
            }
        }
    }
    require(!string && nesting == 0)
}
/// Validate duplicate keys too, without allocating a second JSON value tree.
pub fn strict_json(input: &str, bytes: usize, depth: usize) -> Result<()> {
    use serde::de::{self, MapAccess, SeqAccess, Visitor};
    struct Unique;
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: de::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct Check;
            impl<'de> Visitor<'de> for Check {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("JSON with unique keys")
                }
                fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> std::result::Result<Unique, A::Error> {
                    while seq.next_element::<Unique>()?.is_some() {}
                    Ok(Unique)
                }
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut keys = std::collections::BTreeSet::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if !keys.insert(key) {
                            return Err(de::Error::custom("duplicate key"));
                        }
                        map.next_value::<Unique>()?;
                    }
                    Ok(Unique)
                }
            }
            d.deserialize_any(Check)
        }
    }
    bounded_json(input, bytes, depth)?;
    serde_json::from_str::<Unique>(input)
        .map(|_| ())
        .map_err(|_| Invalid::Input)
}
fn client_data(ctx: &Context, encoded: &str, kind: &str) -> Result<Vec<u8>> {
    let bytes = decode(encoded, ctx.max_bytes)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Invalid::Input)?;
    strict_json(text, ctx.max_bytes, ctx.max_depth)?;
    let data: ClientData = serde_json::from_str(text).map_err(|_| Invalid::Input)?;
    ensure(data.kind == kind, Invalid::ClientDataType)?;
    ensure(data.challenge == ctx.challenge, Invalid::Challenge)?;
    ensure(
        data.origin == ctx.origin && !data.cross_origin && data.top_origin.is_none(),
        Invalid::Origin,
    )?;
    require(decode(&data.challenge, 32)?.len() == 32)?;
    if let Some(binding) = data.token_binding {
        require(
            binding.status != TokenBindingStatus::Present
                || binding.id.as_ref().is_some_and(|id| !id.is_empty()),
        )?;
    }
    Ok(bytes)
}
fn unique_maps(value: &Value) -> Result<()> {
    match value {
        Value::Map(entries) => {
            require(entries.len() <= 128)?;
            for (i, (key, value)) in entries.iter().enumerate() {
                require(!entries[..i].iter().any(|(prior, _)| prior == key))?;
                unique_maps(key)?;
                unique_maps(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                unique_maps(value)?;
            }
        }
        Value::Tag(_, value) => unique_maps(value)?,
        _ => (),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
fn cbor(bytes: &[u8], depth: usize) -> Result<(Value, usize)> {
    let mut reader = Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader_with_recursion_limit(&mut reader, depth)
        .map_err(|_| Invalid::Input)?;
    unique_maps(&value)?;
    Ok((value, reader.position() as usize))
}
fn field<'a>(map: &'a Value, key: &Value) -> Result<&'a Value> {
    map.as_map()
        .ok_or(Invalid::Input)?
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .ok_or(Invalid::Input)
}
fn text_field<'a>(map: &'a Value, key: &str) -> Result<&'a Value> {
    field(map, &Value::Text(key.into()))
}
fn key_field(map: &Value, key: i32) -> Result<&Value> {
    field(map, &Value::Integer(key.into()))
}
fn auth_header(ctx: &Context, bytes: &[u8], registration: bool) -> Result<(u32, bool, bool)> {
    require(bytes.len() >= 37 && bytes.len() <= ctx.max_bytes)?;
    ensure(
        bytes[..32] == Sha256::digest(ctx.rp_id.as_bytes())[..],
        Invalid::RpId,
    )?;
    let flags = bytes[32];
    ensure(flags & 1 != 0, Invalid::UserPresence)?;
    require(flags & 0x22 == 0)?; // UP; reserved bits
    ensure(
        ctx.user_verification != UserVerification::Required || flags & 4 != 0,
        Invalid::UserVerification,
    )?;
    require((flags & 0x40 != 0) == registration)?;
    let be = flags & 8 != 0;
    let bs = flags & 16 != 0;
    ensure(!bs || be, Invalid::Backup)?;
    Ok((
        u32::from_be_bytes(bytes[33..37].try_into().map_err(|_| Invalid::Input)?),
        be,
        bs,
    ))
}
fn extensions(bytes: &[u8], offset: usize, depth: usize) -> Result<()> {
    if bytes[32] & 0x80 == 0 {
        return ensure(offset == bytes.len(), Invalid::Extensions);
    }
    let (value, used) = cbor(bytes.get(offset..).ok_or(Invalid::Extensions)?, depth)
        .map_err(|_| Invalid::Extensions)?;
    let entries = value.as_map().ok_or(Invalid::Extensions)?;
    ensure(
        entries.iter().all(|(key, _)| matches!(key, Value::Text(_)))
            && offset + used == bytes.len(),
        Invalid::Extensions,
    )
}

pub fn register(ctx: &Context, response: Registration) -> Result<VerifiedRegistration> {
    ctx.validate()?;
    let client = client_data(ctx, &response.client_data, "webauthn.create")?;
    let bytes = decode(&response.attestation, ctx.max_bytes)?;
    let (object, used) = cbor(&bytes, ctx.max_depth)?;
    require(used == bytes.len())?;
    let data = text_field(&object, "authData")?
        .as_bytes()
        .ok_or(Invalid::Input)?;
    let (counter, backup_eligible, backup_state) = auth_header(ctx, data, true)?;
    require(data.len() >= 55)?;
    let id_len = u16::from_be_bytes([data[53], data[54]]) as usize;
    require(id_len > 0 && id_len <= 1023)?;
    let id = data.get(55..55 + id_len).ok_or(Invalid::Input)?;
    ensure(decode(&response.id, 1023)? == id, Invalid::Credential)?;
    let (key, used) = cbor(
        data.get(55 + id_len..).ok_or(Invalid::Input)?,
        ctx.max_depth,
    )?;
    let parsed_key = PublicKey::parse(&key)?;
    ensure(
        ctx.algorithms.contains(&parsed_key.algorithm()),
        Invalid::Algorithm,
    )?;
    let public_key = B64.encode(&data[55 + id_len..55 + id_len + used]);
    extensions(data, 55 + id_len + used, ctx.max_depth)?;
    let attestation = attestation::verify(ctx, &object, data, &client, &parsed_key, id)?;
    Ok(VerifiedRegistration {
        id: response.id,
        public_key,
        attestation,
        counter,
        backup_eligible,
        backup_state,
        user_verified: data[32] & 4 != 0,
    })
}
pub fn authenticate(
    ctx: &Context,
    stored: &StoredCredential,
    response: Assertion,
) -> Result<VerifiedAssertion> {
    ctx.validate()?;
    ensure(response.id == stored.id, Invalid::Credential)?;
    require(!decode(&response.id, 1023)?.is_empty())?;
    require(!decode(&stored.user_handle, 64)?.is_empty())?;
    match &ctx.authentication {
        Authentication::Discoverable => ensure(
            response.user_handle.as_deref() == Some(&stored.user_handle),
            Invalid::UserHandle,
        )?,
        Authentication::Identified {
            user_handle,
            allowed_credentials,
        } => {
            ensure(user_handle == &stored.user_handle, Invalid::UserHandle)?;
            ensure(allowed_credentials.contains(&stored.id), Invalid::AllowList)?;
            if let Some(handle) = &response.user_handle {
                ensure(handle == user_handle, Invalid::UserHandle)?;
            }
        }
    }
    let client = client_data(ctx, &response.client_data, "webauthn.get")?;
    let mut data = decode(&response.authenticator_data, ctx.max_bytes)?;
    let (counter, be, backup_state) = auth_header(ctx, &data, false)?;
    extensions(&data, 37, ctx.max_depth)?;
    ensure(be == stored.backup_eligible, Invalid::Backup)?;
    ensure(
        be || (counter == 0 && stored.counter == 0) || counter > stored.counter,
        Invalid::Counter,
    )?;
    let encoded_key = decode(&stored.public_key, 2048)?;
    let (key, used) = cbor(&encoded_key, ctx.max_depth)?;
    require(used == encoded_key.len())?;
    let key = PublicKey::parse(&key)?;
    ensure(
        ctx.algorithms.contains(&key.algorithm()),
        Invalid::Algorithm,
    )?;
    let signature = decode(&response.signature, 512)?;
    data.extend(Sha256::digest(&client));
    key.verify(&data, &signature)?;
    Ok(VerifiedAssertion {
        counter,
        backup_state,
        user_verified: data[32] & 4 != 0,
    })
}
