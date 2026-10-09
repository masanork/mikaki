//! Portable rules for the bounded managed-work profile.
//!
//! `from_authority` / `from_verified_*` constructors are trusted adapter boundaries,
//! not authentication mechanisms. Never deserialize HTTP claims into those facts.
//! Plans and in-memory transitions do not commit D1 state, audit or external effects.
//! A storage adapter must repeat every guard atomically on current primary records.

mod adoption;
mod credentials;
mod delegation;
mod disclosure;
mod payload;
mod preparation;
mod records;
mod request;
mod selected_snapshot;
mod sources;
#[cfg(test)]
mod tests;

pub use adoption::{AdoptionContext, CodeApproval, ExternalOperation, OperationState};
pub use credentials::{
    CredentialAttempt, CredentialObservation, CredentialPurpose, CredentialRole, CredentialScope,
    CredentialSecret, WrappingKey,
};
pub use delegation::{
    Candidate, CandidateInput, Grant, ManagedActor, ManagedActorFacts, PreparedCandidate, Run,
    SubmissionGuard,
};
pub use disclosure::{GitDisclosureInput, RegisteredDisclosureInput, ResolvedDisclosure};
pub use payload::{CandidateGitFacts, CandidatePayload, MAX_CANDIDATE_BUNDLE_BYTES};
pub use preparation::{Preparation, PreparationState, VerifiedPreparation};
pub use request::{CodeTarget, RequestInput, TaskRepository, WorkRequest};
pub use sources::{RegisteredSource, SourceInput, SourceReadInput, VerifiedSourceSelection};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

pub const PROFILE: &str = "mikaki-managed-work-v1";
pub const SUBMIT: &str = "repo.proposal.submit";
pub const ADOPT_CODE: &str = "repo.change.adopt";
pub const MAX_WORK_SECONDS: u64 = 3600;
pub const MAX_APPROVAL_SECONDS: u64 = 300;
/// D1's JS binding represents integers as Numbers; never silently round guards.
pub const MAX_STORED_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denied {
    InvalidInput,
    UnsupportedAction,
    OwnerMismatch,
    InactiveOwner,
    Expired,
    ReviewMismatch,
    BindingMismatch,
    StaleRequest,
    StalePolicy,
    StaleTarget,
    StaleAuthority,
    Revoked,
    InvalidTransition,
    Conflict,
    CapacityExceeded,
}

/// A public digest / key thumbprint, never a private key or access credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Digest([u8; 32]);

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl Digest {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn parse_hex(value: &str) -> Result<Self, Denied> {
        if value.len() != 64 || !lower_hex(value) {
            return Err(Denied::InvalidInput);
        }
        let mut bytes = [0; 32];
        for (i, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            bytes[i] = digit(pair[0]) * 16 + digit(pair[1]);
        }
        Ok(Self(bytes))
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct Id(String);

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Denied {}

fn stored_number(value: u64, zero_allowed: bool) -> Result<(), Denied> {
    if value > MAX_STORED_INTEGER || (!zero_allowed && value == 0) {
        return Err(Denied::InvalidInput);
    }
    Ok(())
}

impl Id {
    fn parse(value: &str) -> Result<Self, Denied> {
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        {
            return Err(Denied::InvalidInput);
        }
        Ok(Self(value.into()))
    }
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn git_oid(value: &str) -> Result<String, Denied> {
    if !matches!(value.len(), 40 | 64) || !lower_hex(value) {
        return Err(Denied::InvalidInput);
    }
    Ok(value.into())
}

fn deadline(now: u64, expires: u64, maximum: u64) -> Result<(), Denied> {
    stored_number(now, true)?;
    stored_number(expires, false)?;
    if expires <= now || expires - now > maximum {
        return Err(Denied::Expired);
    }
    Ok(())
}

/// Explicit field encoding: each UTF-8/byte field has a u64 big-endian length;
/// integers are u64 big-endian. Call sites fix field order and a domain tag.
struct Hash(Sha256);

impl Hash {
    fn new(domain: &str) -> Self {
        let mut hash = Self(Sha256::new());
        hash.bytes(domain.as_bytes());
        hash
    }
    fn bytes(&mut self, value: &[u8]) {
        self.number(value.len() as u64);
        self.0.update(value);
    }
    fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }
    fn number(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }
    fn finish(self) -> Digest {
        Digest(self.0.finalize().into())
    }
}

/// Current account facts read from the authority, including inactive tombstones.
#[derive(Debug)]
pub struct OwnerState {
    id: Id,
    epoch: u64,
    active: bool,
}

impl OwnerState {
    pub fn from_authority(id: &str, epoch: u64, active: bool) -> Result<Self, Denied> {
        stored_number(epoch, true)?;
        Ok(Self {
            id: Id::parse(id)?,
            epoch,
            active,
        })
    }
}

/// Construct only after the OP has authenticated the human session.
#[derive(Debug)]
pub struct OwnerSession {
    id: Id,
    epoch: u64,
    expires_at: u64,
}

impl OwnerSession {
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn from_verified_session(id: &str, epoch: u64, expires_at: u64) -> Result<Self, Denied> {
        stored_number(epoch, true)?;
        stored_number(expires_at, false)?;
        Ok(Self {
            id: Id::parse(id)?,
            epoch,
            expires_at,
        })
    }

    fn check(&self, environment: &Environment<'_>) -> Result<(), Denied> {
        environment.check_owner(&self.id, self.epoch)?;
        if environment.now >= self.expires_at {
            return Err(Denied::Expired);
        }
        Ok(())
    }
}

/// Primary owner state, authoritative policy revision and service time.
/// Callers must not fill these from request body, token labels or Git policy files.
pub struct Environment<'a> {
    pub owner: &'a OwnerState,
    pub policy_revision: u64,
    pub now: u64,
}

impl Environment<'_> {
    fn check_owner(&self, id: &Id, epoch: u64) -> Result<(), Denied> {
        stored_number(self.policy_revision, false)?;
        stored_number(self.now, true)?;
        if &self.owner.id != id {
            return Err(Denied::OwnerMismatch);
        }
        if !self.owner.active {
            return Err(Denied::InactiveOwner);
        }
        if self.owner.epoch != epoch {
            return Err(Denied::StaleAuthority);
        }
        Ok(())
    }
}
