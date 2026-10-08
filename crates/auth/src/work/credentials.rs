//! Private service custody. Storage records are not browser DTOs or permission.
use super::*;
use aes_gcm::{
    Aes256Gcm, KeyInit as _, Nonce,
    aead::{Aead as _, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRole {
    Task,
    Snapshot,
}
impl CredentialRole {
    pub fn name(self) -> &'static str {
        match self {
            Self::Task => "task",
            Self::Snapshot => "snapshot",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialPurpose {
    Initial,
    Upload,
    Readback,
}
impl CredentialPurpose {
    pub fn name(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Upload => "upload",
            Self::Readback => "readback",
        }
    }
    pub fn scope(self) -> CredentialScope {
        if self == Self::Readback {
            CredentialScope::Read
        } else {
            CredentialScope::Write
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialScope {
    Read,
    Write,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    id: Id,
    preparation_id: Id,
    preparation_digest: Digest,
    owner_id: Id,
    role: CredentialRole,
    purpose: CredentialPurpose,
    namespace: String,
    name: String,
    expected_repo_id: Option<Id>,
    deadline: u64,
}
#[derive(Serialize)]
pub struct CredentialAttempt {
    plan: Plan,
    digest: Digest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    plan: Plan,
    digest: Digest,
}
impl Plan {
    fn digest(&self) -> Result<Digest, Denied> {
        let mut h = Hash::new("mikaki.work-credential-attempt.v1");
        h.bytes(
            serde_json::to_string(self)
                .map_err(|_| Denied::InvalidInput)?
                .as_bytes(),
        );
        Ok(h.finish())
    }
}
impl CredentialAttempt {
    pub fn from_preparation(
        p: &Preparation,
        id: &str,
        role: CredentialRole,
        purpose: CredentialPurpose,
        expected_repo_id: Option<&str>,
    ) -> Result<Self, Denied> {
        if p.state() != PreparationState::Dispatched
            || (purpose == CredentialPurpose::Initial) != expected_repo_id.is_none()
        {
            return Err(Denied::InvalidTransition);
        }
        let (namespace, name) = p.credential_destination(role);
        let plan = Plan {
            id: Id::parse(id)?,
            preparation_id: Id::parse(p.id())?,
            preparation_digest: p.digest(),
            owner_id: Id::parse(p.owner_id())?,
            role,
            purpose,
            namespace: namespace.into(),
            name: name.into(),
            expected_repo_id: expected_repo_id.map(Id::parse).transpose()?,
            deadline: p.expires_at(),
        };
        Ok(Self {
            digest: plan.digest()?,
            plan,
        })
    }
    pub fn restore_authority_record(body: &str, p: &Preparation) -> Result<Self, Denied> {
        if body.len() > 4096 {
            return Err(Denied::InvalidInput);
        }
        let stored: Stored = records::decode("credential_attempt", body)?;
        let plan = stored.plan;
        Id::parse(&plan.id.0)?;
        if let Some(id) = &plan.expected_repo_id {
            Id::parse(&id.0)?;
        }
        let (namespace, name) = p.credential_destination(plan.role);
        if plan.preparation_id.0 != p.id()
            || plan.preparation_digest != p.digest()
            || plan.owner_id.0 != p.owner_id()
            || plan.namespace != namespace
            || plan.name != name
            || plan.deadline != p.expires_at()
            || (plan.purpose == CredentialPurpose::Initial) != plan.expected_repo_id.is_none()
            || plan.digest()? != stored.digest
        {
            return Err(Denied::BindingMismatch);
        }
        Ok(Self {
            plan,
            digest: stored.digest,
        })
    }
    pub fn authority_record(&self) -> Result<String, Denied> {
        records::encode("credential_attempt", self)
    }
    pub fn id(&self) -> &str {
        &self.plan.id.0
    }
    pub fn preparation_id(&self) -> &str {
        &self.plan.preparation_id.0
    }
    pub fn digest(&self) -> Digest {
        self.digest
    }
    pub fn role(&self) -> CredentialRole {
        self.plan.role
    }
    pub fn purpose(&self) -> CredentialPurpose {
        self.plan.purpose
    }
    pub fn expected_repo_id(&self) -> Option<&str> {
        self.plan.expected_repo_id.as_ref().map(|id| id.0.as_str())
    }
    pub fn deadline(&self) -> u64 {
        self.plan.deadline
    }
}

/// Independently observed adapter facts; construction does not prove them.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    attempt_digest: Digest,
    repo_id: Id,
    token_id: Id,
    scope: CredentialScope,
    expires_at: Option<u64>,
}
pub struct CredentialObservation(Observation);
impl CredentialObservation {
    pub fn from_observed(
        a: &CredentialAttempt,
        repo_id: &str,
        token_id: &str,
        scope: CredentialScope,
        expires_at: Option<u64>,
    ) -> Result<Self, Denied> {
        if a.expected_repo_id().is_some_and(|id| id != repo_id) {
            return Err(Denied::BindingMismatch);
        }
        if let Some(expiry) = expires_at {
            stored_number(expiry, false)?;
        }
        Ok(Self(Observation {
            attempt_digest: a.digest,
            repo_id: Id::parse(repo_id)?,
            token_id: Id::parse(token_id)?,
            scope,
            expires_at,
        }))
    }
    pub fn authority_record(&self) -> Result<String, Denied> {
        records::encode("credential_observation", &self.0)
    }
    pub fn restore_authority_record(body: &str, a: &CredentialAttempt) -> Result<Self, Denied> {
        let o: Observation = records::decode("credential_observation", body)?;
        let validated = Self::from_observed(a, &o.repo_id.0, &o.token_id.0, o.scope, o.expires_at)?;
        if o.attempt_digest != a.digest {
            return Err(Denied::BindingMismatch);
        }
        Ok(validated)
    }
    pub fn repo_id(&self) -> &str {
        &self.0.repo_id.0
    }
    pub fn token_id(&self) -> &str {
        &self.0.token_id.0
    }
    pub fn scope(&self) -> CredentialScope {
        self.0.scope
    }
    pub fn expires_at(&self) -> Option<u64> {
        self.0.expires_at
    }
}

/// No Debug/Serialize/Clone; the trusted service must keep this off wire/logs.
pub struct CredentialSecret(Zeroizing<Vec<u8>>);
impl CredentialSecret {
    pub fn from_service_bytes(bytes: &[u8]) -> Result<Self, Denied> {
        if bytes.is_empty() || bytes.len() > 4096 || bytes.iter().any(|b| !(33..=126).contains(b)) {
            return Err(Denied::InvalidInput);
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
    pub fn service_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn matches(&self, other: &Self) -> bool {
        let left = Sha256::digest(&*self.0);
        let right = Sha256::digest(&*other.0);
        bool::from(left.as_slice().ct_eq(right.as_slice()))
    }
}
pub struct WrappingKey {
    version: u64,
    bytes: Zeroizing<[u8; 32]>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    key_version: u64,
    nonce: String,
    ciphertext: String,
}
fn decode(value: &str) -> Result<Vec<u8>, Denied> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Denied::InvalidInput)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Denied::InvalidInput);
    }
    Ok(bytes)
}
impl WrappingKey {
    pub fn from_service_secret(version: u64, secret: &str) -> Result<Self, Denied> {
        stored_number(version, false)?;
        let bytes = Zeroizing::new(decode(secret)?);
        if bytes.len() != 32 {
            return Err(Denied::InvalidInput);
        }
        let mut raw = Zeroizing::new([0; 32]);
        raw.copy_from_slice(&bytes);
        Ok(Self {
            version,
            bytes: raw,
        })
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn fingerprint(&self) -> Digest {
        let mut h = Hash::new("mikaki.work-credential-key.v1");
        h.bytes(&*self.bytes);
        h.finish()
    }
    fn aad(&self, a: &CredentialAttempt, o: &CredentialObservation) -> Result<Vec<u8>, Denied> {
        let mut h = Hash::new("mikaki.work-credential-envelope.v1");
        h.bytes(&a.digest.0);
        h.bytes(o.authority_record()?.as_bytes());
        h.bytes(&1u64.to_be_bytes());
        h.bytes(&self.version.to_be_bytes());
        Ok(h.finish().0.to_vec())
    }
    /// The trusted caller must supply a fresh platform CSPRNG nonce. WorkStore
    /// enforces same-key uniqueness with retained nonce tombstones.
    pub fn seal(
        &self,
        a: &CredentialAttempt,
        o: &CredentialObservation,
        secret: &CredentialSecret,
        nonce: [u8; 12],
    ) -> Result<String, Denied> {
        if o.0.attempt_digest != a.digest {
            return Err(Denied::BindingMismatch);
        }
        let cipher = Aes256Gcm::new_from_slice(&*self.bytes).map_err(|_| Denied::InvalidInput)?;
        let data = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: secret.service_bytes(),
                    aad: &self.aad(a, o)?,
                },
            )
            .map_err(|_| Denied::BindingMismatch)?;
        records::encode(
            "credential_envelope",
            &Envelope {
                version: 1,
                key_version: self.version,
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                ciphertext: URL_SAFE_NO_PAD.encode(data),
            },
        )
    }
    pub fn open(
        &self,
        a: &CredentialAttempt,
        o: &CredentialObservation,
        body: &str,
    ) -> Result<CredentialSecret, Denied> {
        if body.len() > 8192 || o.0.attempt_digest != a.digest {
            return Err(Denied::BindingMismatch);
        }
        let e: Envelope = records::decode("credential_envelope", body)?;
        if e.version != 1 || e.key_version != self.version {
            return Err(Denied::BindingMismatch);
        }
        let nonce: [u8; 12] = decode(&e.nonce)?
            .try_into()
            .map_err(|_| Denied::InvalidInput)?;
        let data = decode(&e.ciphertext)?;
        if !(17..=4112).contains(&data.len()) {
            return Err(Denied::InvalidInput);
        }
        let cipher = Aes256Gcm::new_from_slice(&*self.bytes).map_err(|_| Denied::InvalidInput)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::from(nonce),
                    Payload {
                        msg: &data,
                        aad: &self.aad(a, o)?,
                    },
                )
                .map_err(|_| Denied::BindingMismatch)?,
        );
        CredentialSecret::from_service_bytes(&plaintext)
    }
}
