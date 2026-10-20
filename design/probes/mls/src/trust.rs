//! Application authentication above MLS: pinned issuer attestations and explicit
//! device-key confirmation. Issuer provisioning and authenticated enrollment are
//! adapter responsibilities; no wire-supplied key can become a trust anchor.
use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openmls_traits::{crypto::OpenMlsCrypto, types::SignatureScheme};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub const BINDING_TYPE: &str = "mikaki-device-binding+jwt";
pub const PROOF_TYPE: &str = "mikaki-device-registration+jwt";
pub const AUDIENCE: &str = "mikaki-mls-device-v1";
const MAX_SAFE: u64 = 9_007_199_254_740_991;
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceIdentity {
    pub issuer: String,
    pub account_id: String,
    pub device_id: String,
    pub generation: u64,
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            14 => b == b'4',
            19 => matches!(b, b'8' | b'9' | b'a' | b'b'),
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

fn issuer(value: &str) -> Result<()> {
    let url = url::Url::parse(value).map_err(|_| "invalid_issuer")?;
    if value.len() > 256
        || !value.is_ascii()
        || url.scheme() != "https"
        || url.origin().ascii_serialization() != value
    {
        return Err("invalid_issuer");
    }
    Ok(())
}

impl DeviceIdentity {
    pub fn validate(&self) -> Result<()> {
        issuer(&self.issuer)?;
        if !uuid(&self.account_id)
            || !uuid(&self.device_id)
            || !(1..=MAX_SAFE).contains(&self.generation)
        {
            return Err("invalid_device_identity");
        }
        Ok(())
    }
    /// Canonical credential bytes; display names are deliberately excluded.
    pub fn credential(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| "invalid_device_identity")
    }
    pub(crate) fn slot(&self) -> (String, String, String) {
        (
            self.issuer.clone(),
            self.account_id.clone(),
            self.device_id.clone(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub issuer: String,
    pub public_key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    Current,
    KeyChanged,
    Revoked,
    RegistryConflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub iss: String,
    pub aud: String,
    pub device: DeviceIdentity,
    pub public_key: String,
    pub revision: u64,
    pub status: Status,
    pub iat: u64,
    pub exp: u64,
}

/// Verified public display data, deliberately separate from trust acceptance.
#[derive(Serialize)]
pub(crate) struct DeviceView {
    device: DeviceIdentity,
    fingerprint: String,
    revision: u64,
    status: Status,
    issued_at: u64,
    expires_at: u64,
}
impl Binding {
    pub(crate) fn view(&self) -> Result<DeviceView> {
        Ok(DeviceView {
            device: self.device.clone(),
            fingerprint: fingerprint(&self.device, &decode(&self.public_key)?)?,
            revision: self.revision,
            status: self.status,
            issued_at: self.iat,
            expires_at: self.exp,
        })
    }
}

#[derive(Serialize)]
pub(crate) struct PinView {
    accepted: DeviceView,
    latest: DeviceView,
    state: &'static str,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub typ: String,
    pub alg: String,
    pub kid: String,
}

pub fn decode(value: &str) -> Result<Vec<u8>> {
    let bytes = B64.decode(value).map_err(|_| "invalid_base64url")?;
    if bytes.is_empty() || B64.encode(&bytes) != value {
        return Err("invalid_base64url");
    }
    Ok(bytes)
}

pub fn key_id(public_key: &[u8]) -> String {
    B64.encode(Sha256::digest(public_key))
}

pub fn fingerprint(identity: &DeviceIdentity, public_key: &[u8]) -> Result<String> {
    identity.validate()?;
    if public_key.len() != 32 {
        return Err("invalid_device_key");
    }
    let bytes = serde_json::to_vec(&(
        "mikaki-device-fingerprint-v1",
        identity,
        "Ed25519",
        B64.encode(public_key),
    ))
    .map_err(|_| "invalid_device_identity")?;
    Ok(B64.encode(Sha256::digest(bytes)))
}

pub fn parse<T: DeserializeOwned>(input: &str) -> Result<T> {
    if input.is_empty() || input.len() > 8192 {
        return Err("invalid_input_size");
    }
    serde_json::from_str(input).map_err(|_| "invalid_json")
}

fn jwt<'a, T: DeserializeOwned>(
    token: &'a str,
    typ: &str,
) -> Result<(Header, T, &'a str, Vec<u8>)> {
    if token.is_empty() || token.len() > 8192 {
        return Err("invalid_token_size");
    }
    let (input, signature) = token.rsplit_once('.').ok_or("invalid_token")?;
    let (header, payload) = input.split_once('.').ok_or("invalid_token")?;
    if payload.contains('.') {
        return Err("invalid_token");
    }
    let header: Header = serde_json::from_slice(&decode(header)?).map_err(|_| "invalid_header")?;
    if header.alg != "EdDSA" || header.typ != typ {
        return Err("invalid_header");
    }
    let payload = serde_json::from_slice(&decode(payload)?).map_err(|_| "invalid_claims")?;
    let signature = decode(signature)?;
    if signature.len() != 64 {
        return Err("invalid_signature");
    }
    Ok((header, payload, input, signature))
}

fn signature(crypto: &impl OpenMlsCrypto, input: &str, key: &[u8], sig: &[u8]) -> Result<()> {
    crypto
        .verify_signature(SignatureScheme::ED25519, input.as_bytes(), key, sig)
        .map_err(|_| "invalid_signature")
}

fn lifetime(iat: u64, exp: u64, now: u64, max: u64) -> Result<()> {
    if now > MAX_SAFE || iat > now || exp <= now || exp > MAX_SAFE || exp <= iat || exp - iat > max
    {
        return Err("binding_not_current");
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationProof {
    pub aud: String,
    pub device: DeviceIdentity,
    pub public_key: String,
    pub nonce: String,
    pub iat: u64,
    pub exp: u64,
}

/// A proof of device-key possession. The adapter must derive expected account,
/// issuer/device/generation and the single-use challenge from authenticated
/// server state, never from the enrollment request. Atomically consuming that
/// challenge and committing a registry revision belongs to the issuer adapter.
pub fn verify_registration(
    token: &str,
    expected: &DeviceIdentity,
    nonce: &str,
    now: u64,
    crypto: &impl OpenMlsCrypto,
) -> Result<Vec<u8>> {
    expected.validate()?;
    if decode(nonce)?.len() != 32 {
        return Err("invalid_challenge");
    }
    let (header, proof, input, sig) = jwt::<RegistrationProof>(token, PROOF_TYPE)?;
    if proof.device != *expected || proof.aud != expected.issuer || proof.nonce != nonce {
        return Err("registration_context_mismatch");
    }
    lifetime(proof.iat, proof.exp, now, 60)?;
    let key = decode(&proof.public_key)?;
    if key.len() != 32 || header.kid != key_id(&key) {
        return Err("invalid_device_key");
    }
    signature(crypto, input, &key, &sig)?;
    Ok(key)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    accepted: Binding,
    latest: Binding,
    review_required: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustStore {
    authorities: Vec<Authority>,
    // A bounded Vec is used so the test checkpoint has no JSON map-key encoding.
    pins: Vec<Pin>,
    last_time: u64,
    #[serde(default)]
    unconfirmed_revocations: Vec<Binding>,
}

impl TrustStore {
    pub(crate) fn accepted(&self, identity: &DeviceIdentity, now: u64) -> Result<&Binding> {
        let pin = self
            .pins
            .iter()
            .find(|p| p.accepted.device.slot() == identity.slot())
            .ok_or("first_trust_required")?;
        if now < self.last_time {
            return Err("clock_rollback");
        }
        Self::current(pin, now)?;
        Ok(&pin.accepted)
    }
    pub(crate) fn view(&self, identity: &DeviceIdentity, now: u64) -> Result<Option<PinView>> {
        if now < self.last_time || now > MAX_SAFE {
            return Err("clock_rollback");
        }
        let Some(pin) = self
            .pins
            .iter()
            .find(|p| p.accepted.device.slot() == identity.slot())
        else {
            return Ok(None);
        };
        let state = if pin.latest.status == Status::Revoked {
            "revoked"
        } else if pin.review_required {
            if pin.latest.device == pin.accepted.device
                && pin.latest.public_key == pin.accepted.public_key
            {
                "registry_conflict"
            } else {
                "key_changed"
            }
        } else if Self::current(pin, now).is_err() {
            "expired"
        } else {
            "current"
        };
        Ok(Some(PinView {
            accepted: pin.accepted.view()?,
            latest: pin.latest.view()?,
            state,
        }))
    }
    pub(crate) fn current_fingerprint(
        &self,
        identity: &DeviceIdentity,
        now: u64,
    ) -> Result<String> {
        if now < self.last_time {
            return Err("clock_rollback");
        }
        let pin = self
            .pins
            .iter()
            .find(|pin| pin.accepted.device.slot() == identity.slot())
            .ok_or("first_trust_required")?;
        Self::current(pin, now)?;
        fingerprint(&pin.accepted.device, &decode(&pin.accepted.public_key)?)
    }
    pub fn new(authorities: Vec<Authority>) -> Result<Self> {
        if authorities.is_empty() || authorities.len() > 8 {
            return Err("invalid_authorities");
        }
        let mut seen = BTreeMap::new();
        for authority in &authorities {
            issuer(&authority.issuer)?;
            if decode(&authority.public_key)?.len() != 32
                || seen.insert(&authority.issuer, ()).is_some()
            {
                return Err("invalid_authorities");
            }
        }
        Ok(Self {
            authorities,
            pins: Vec::new(),
            last_time: 0,
            unconfirmed_revocations: Vec::new(),
        })
    }

    pub fn same_authorities(&self, authorities: &[Authority]) -> bool {
        self.authorities == authorities && self.unconfirmed_revocations.len() <= 8
    }

    pub fn time(&mut self, now: u64) -> Result<()> {
        if now < self.last_time || now > MAX_SAFE {
            return Err("clock_rollback");
        }
        self.last_time = now;
        Ok(())
    }

    pub(crate) fn verify(
        &self,
        token: &str,
        now: u64,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<Binding> {
        let (header, binding, input, sig) = jwt::<Binding>(token, BINDING_TYPE)?;
        binding.device.validate()?;
        if binding.iss != binding.device.issuer
            || binding.aud != AUDIENCE
            || !(1..=MAX_SAFE).contains(&binding.revision)
            || decode(&binding.public_key)?.len() != 32
        {
            return Err("invalid_binding");
        }
        let authority = self
            .authorities
            .iter()
            .find(|a| a.issuer == binding.iss)
            .ok_or("untrusted_issuer")?;
        let key = decode(&authority.public_key)?;
        if header.kid != key_id(&key) {
            return Err("untrusted_issuer_key");
        }
        signature(crypto, input, &key, &sig)?;
        lifetime(binding.iat, binding.exp, now, 300)?;
        Ok(binding)
    }

    pub fn confirm(
        &mut self,
        token: &str,
        expected: &str,
        now: u64,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<()> {
        self.time(now)?;
        let binding = self.verify(token, now, crypto)?;
        if binding.status != Status::Active {
            return Err("device_revoked");
        }
        self.check_unconfirmed_revocation(&binding)?;
        if fingerprint(&binding.device, &decode(&binding.public_key)?)? != expected {
            return Err("fingerprint_mismatch");
        }
        if self
            .pins
            .iter()
            .any(|p| p.accepted.device.slot() == binding.device.slot())
        {
            return Err("device_already_pinned");
        }
        if self.pins.len() >= 2 {
            return Err("probe_is_one_to_one");
        }
        self.pins.push(Pin {
            accepted: binding.clone(),
            latest: binding,
            review_required: false,
        });
        Ok(())
    }

    fn check_unconfirmed_revocation(&self, binding: &Binding) -> Result<()> {
        if self.unconfirmed_revocations.iter().any(|old| {
            old.device.slot() == binding.device.slot()
                && (binding.device.generation <= old.device.generation
                    || binding.public_key == old.public_key)
        }) {
            return Err("device_revoked");
        }
        Ok(())
    }

    /// Retain a verified denial without turning an unconfirmed device into a pin.
    pub(crate) fn review_unconfirmed(
        &mut self,
        token: &str,
        now: u64,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<&'static str> {
        self.time(now)?;
        let binding = self.verify(token, now, crypto)?;
        if binding.status == Status::Revoked {
            if !self
                .unconfirmed_revocations
                .iter()
                .any(|old| old.device == binding.device && old.public_key == binding.public_key)
            {
                if self.unconfirmed_revocations.len() >= 8 {
                    return Err("revocation_ledger_full");
                }
                self.unconfirmed_revocations.push(binding);
            }
            Ok("revoked")
        } else {
            self.check_unconfirmed_revocation(&binding)?;
            Ok("unconfirmed")
        }
    }

    /// Even a signed key replacement freezes the old pin until explicit review.
    pub fn observe(
        &mut self,
        token: &str,
        now: u64,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<Observation> {
        self.time(now)?;
        let binding = self.verify(token, now, crypto)?;
        let pin = self
            .pins
            .iter_mut()
            .find(|p| p.accepted.device.slot() == binding.device.slot())
            .ok_or("first_trust_required")?;
        if binding.revision < pin.latest.revision
            || binding.device.generation < pin.latest.device.generation
            || binding.iat < pin.latest.iat
        {
            return Err("stale_binding");
        }
        if binding.revision == pin.latest.revision
            && (binding.device != pin.latest.device
                || binding.public_key != pin.latest.public_key
                || binding.status != pin.latest.status)
        {
            pin.review_required = true;
            return Ok(Observation::RegistryConflict);
        }
        if pin.latest.status == Status::Revoked
            && binding.status == Status::Active
            && binding.device.generation <= pin.latest.device.generation
        {
            return Err("device_revoked");
        }
        pin.review_required |=
            binding.device != pin.accepted.device || binding.public_key != pin.accepted.public_key;
        pin.latest = binding;
        Ok(if pin.latest.status == Status::Revoked {
            Observation::Revoked
        } else if pin.review_required {
            Observation::KeyChanged
        } else {
            Observation::Current
        })
    }

    pub fn accept_change(
        &mut self,
        token: &str,
        old: &str,
        new: &str,
        now: u64,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<()> {
        self.time(now)?;
        let binding = self.verify(token, now, crypto)?;
        let pin = self
            .pins
            .iter_mut()
            .find(|p| p.accepted.device.slot() == binding.device.slot())
            .ok_or("first_trust_required")?;
        if fingerprint(&pin.accepted.device, &decode(&pin.accepted.public_key)?)? != old
            || fingerprint(&binding.device, &decode(&binding.public_key)?)? != new
        {
            return Err("fingerprint_mismatch");
        }
        if binding.status != Status::Active
            || binding.device.generation <= pin.accepted.device.generation
            || binding.device.generation < pin.latest.device.generation
            || binding.revision <= pin.accepted.revision
            || binding.revision < pin.latest.revision
            || binding.iat < pin.latest.iat
            || binding.public_key == pin.accepted.public_key
            || (pin.latest.status == Status::Revoked
                && binding.device.generation <= pin.latest.device.generation)
            || (binding.revision == pin.latest.revision && binding != pin.latest)
        {
            return Err("invalid_key_change");
        }
        pin.accepted = binding.clone();
        pin.latest = binding;
        pin.review_required = false;
        Ok(())
    }

    fn current(pin: &Pin, now: u64) -> Result<()> {
        if pin.latest.status == Status::Revoked {
            return Err("device_revoked");
        }
        if pin.review_required
            || pin.latest.device != pin.accepted.device
            || pin.latest.public_key != pin.accepted.public_key
        {
            return Err("device_key_changed");
        }
        lifetime(pin.latest.iat, pin.latest.exp, now, 300)
    }

    pub fn check(&self, identity: &DeviceIdentity, key: &[u8], now: u64) -> Result<()> {
        if now < self.last_time {
            return Err("clock_rollback");
        }
        let pin = self
            .pins
            .iter()
            .find(|p| p.accepted.device.slot() == identity.slot())
            .ok_or("first_trust_required")?;
        Self::current(pin, now)?;
        if pin.accepted.device != *identity || decode(&pin.accepted.public_key)? != key {
            return Err("device_key_mismatch");
        }
        Ok(())
    }
}
