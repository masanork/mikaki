//! Local, one-shot installation registration preparation. This does not send
//! requests, authenticate the user, record success, or create a device session.
use crate::{
    installation_proof::{InstallationSigner, Step, opaque, proof_for_key},
    issuance::PublicJwk,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAX_CLOCK_SKEW_AND_LIFETIME: u64 = 130;

/// The caller sends `proof()` with an empty JSON object to the configured IdP.
/// Dropping this value cancels this local attempt; server-side expiry is separate.
pub struct Started {
    issuer: String,
    key: PublicJwk,
    start_jti: Zeroizing<String>,
    started_at: u64,
    proof: Zeroizing<String>,
}

pub struct Challenged {
    issuer: String,
    key: PublicJwk,
    start_jti: Zeroizing<String>,
    started_at: u64,
    id: String,
    nonce: Zeroizing<String>,
    expires_at: u64,
}

/// A request, not a successful registration receipt. The caller must handle
/// transport failure as an unknown outcome and reconcile with the server.
pub struct CompletionRequest {
    issuer: String,
    key: PublicJwk,
    started_at: u64,
    start_jti: Zeroizing<String>,
    completion_jti: Zeroizing<String>,
    status_jtis: Vec<Zeroizing<String>>,
    id: String,
    proof: Zeroizing<String>,
}

/// A signed status request. The outcome is only meaningful after the caller
/// verifies the HTTPS origin, response status, and authenticated SSO context.
pub struct StatusRequest {
    id: String,
    proof: Zeroizing<String>,
}

/// Recovery metadata only: no completion proof, nonce, private key or token.
/// The storage layer must authenticate, atomically persist and protect this
/// record from rollback. This type cannot provide those guarantees by itself.
#[derive(Serialize)]
pub struct RecoveryCheckpoint {
    version: u8,
    issuer: String,
    owner_binding: String,
    key: PublicJwk,
    id: String,
    started_at: u64,
    start_jti: String,
    completion_jti: String,
    status_jtis: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRecord {
    version: u8,
    issuer: String,
    owner_binding: String,
    key: PublicJwk,
    id: String,
    started_at: u64,
    start_jti: String,
    completion_jti: String,
    status_jtis: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationStatus {
    Pending,
    Active,
    Revoked,
    Unknown,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusResponse {
    id: String,
    status: RegistrationStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    id: String,
    nonce: String,
    expires_at: u64,
}

impl Started {
    /// Inputs are locally trusted issuer, cryptographically random 32-byte JTI,
    /// and a trustworthy wall clock. Never accept these from the WebView.
    pub fn begin(
        signer: &impl InstallationSigner,
        issuer: &str,
        jti: &str,
        now: u64,
    ) -> Result<Self, String> {
        let key = signer.public_key()?;
        let compact = proof_for_key(signer, issuer, Step::Start, jti, now, Some(&key))?;
        Ok(Self {
            issuer: issuer.to_owned(),
            key,
            start_jti: Zeroizing::new(jti.to_owned()),
            started_at: now,
            proof: Zeroizing::new(compact),
        })
    }
    pub fn proof(&self) -> &str {
        &self.proof
    }

    /// Process only a successful, authenticated, same-origin server response.
    /// Transport authentication/status checks remain the caller's responsibility.
    pub fn challenge(self, response: &[u8], now: u64) -> Result<Challenged, String> {
        let invalid = || "invalid_installation_challenge".to_owned();
        if response.len() > 1024
            || now < self.started_at
            || now.saturating_sub(self.started_at) > MAX_CLOCK_SKEW_AND_LIFETIME
        {
            return Err(invalid());
        }
        let value: Challenge = serde_json::from_slice(response).map_err(|_| invalid())?;
        if !opaque(&value.id)
            || !opaque(&value.nonce)
            || value.expires_at <= now
            || value.expires_at > self.started_at.saturating_add(MAX_CLOCK_SKEW_AND_LIFETIME)
        {
            return Err(invalid());
        }
        Ok(Challenged {
            issuer: self.issuer,
            key: self.key,
            start_jti: self.start_jti,
            started_at: self.started_at,
            id: value.id,
            nonce: Zeroizing::new(value.nonce),
            expires_at: value.expires_at,
        })
    }
}

impl Challenged {
    /// Consumes the pending state even on signing failure. JTI must be freshly
    /// generated; time and the original key are rechecked before signing.
    pub fn complete(
        self,
        signer: &impl InstallationSigner,
        jti: &str,
        now: u64,
    ) -> Result<CompletionRequest, String> {
        if now < self.started_at
            || now >= self.expires_at
            || now.saturating_sub(self.started_at) > MAX_CLOCK_SKEW_AND_LIFETIME
            || jti == self.start_jti.as_str()
        {
            return Err("invalid_installation_challenge".into());
        }
        let compact = proof_for_key(
            signer,
            &self.issuer,
            Step::Complete { nonce: &self.nonce },
            jti,
            now,
            Some(&self.key),
        )?;
        Ok(CompletionRequest {
            issuer: self.issuer,
            key: self.key,
            started_at: self.started_at,
            start_jti: self.start_jti,
            completion_jti: Zeroizing::new(jti.to_owned()),
            status_jtis: Vec::new(),
            id: self.id,
            proof: Zeroizing::new(compact),
        })
    }
}

impl CompletionRequest {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn proof(&self) -> &str {
        &self.proof
    }

    /// Persist the authenticated checkpoint before sending completion. The
    /// owner binding is a caller-derived opaque 32-byte account identifier,
    /// never a value accepted from the WebView or an unverified response.
    pub fn into_recovery(
        self,
        owner_binding: &str,
    ) -> Result<(RecoveryCheckpoint, Zeroizing<String>), String> {
        if !opaque(owner_binding) {
            return Err("invalid_installation_recovery".into());
        }
        let checkpoint = RecoveryCheckpoint {
            version: 1,
            issuer: self.issuer.clone(),
            owner_binding: owner_binding.to_owned(),
            key: self.key.clone(),
            id: self.id.clone(),
            started_at: self.started_at,
            start_jti: self.start_jti.to_string(),
            completion_jti: self.completion_jti.to_string(),
            status_jtis: self
                .status_jtis
                .iter()
                .map(|jti| jti.as_str().to_owned())
                .collect(),
        };
        Ok((checkpoint, self.proof))
    }

    /// A fresh JTI and the same native key are required. Failed transport does
    /// not establish an outcome; each retry must create a new status proof.
    pub fn status_request(
        &mut self,
        signer: &impl InstallationSigner,
        jti: &str,
        now: u64,
    ) -> Result<StatusRequest, String> {
        if now < self.started_at
            || self.status_jtis.len() >= 16
            || jti == self.start_jti.as_str()
            || jti == self.completion_jti.as_str()
            || self
                .status_jtis
                .iter()
                .any(|previous| previous.as_str() == jti)
        {
            return Err("invalid_installation_status".into());
        }
        let compact = proof_for_key(
            signer,
            &self.issuer,
            Step::Status,
            jti,
            now,
            Some(&self.key),
        )?;
        self.status_jtis.push(Zeroizing::new(jti.to_owned()));
        Ok(StatusRequest {
            id: self.id.clone(),
            proof: Zeroizing::new(compact),
        })
    }
}

impl RecoveryCheckpoint {
    /// Load only authenticated, rollback-protected storage. The caller must
    /// independently obtain the current account binding, configured issuer and
    /// native signer; a changed account or key must never resume this attempt.
    pub fn restore(
        bytes: &[u8],
        issuer: &str,
        owner_binding: &str,
        signer: &impl InstallationSigner,
        now: u64,
    ) -> Result<Self, String> {
        let invalid = || "invalid_installation_recovery".to_owned();
        if bytes.len() > 4096 || !opaque(owner_binding) {
            return Err(invalid());
        }
        let record: RecoveryRecord = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if record.version != 1
            || record.issuer != issuer
            || record.owner_binding != owner_binding
            || !opaque(&record.id)
            || !opaque(&record.start_jti)
            || !opaque(&record.completion_jti)
            || record.start_jti == record.completion_jti
            || record.started_at == 0
            || now < record.started_at
            || record.status_jtis.len() > 16
            || signer.public_key()? != record.key
            || record.key.verifying_key().is_err()
        {
            return Err(invalid());
        }
        let mut used = vec![&record.start_jti, &record.completion_jti];
        for jti in &record.status_jtis {
            if !opaque(jti) || used.contains(&jti) {
                return Err(invalid());
            }
            used.push(jti);
        }
        Ok(Self {
            version: record.version,
            issuer: record.issuer,
            owner_binding: record.owner_binding,
            key: record.key,
            id: record.id,
            started_at: record.started_at,
            start_jti: record.start_jti,
            completion_jti: record.completion_jti,
            status_jtis: record.status_jtis,
        })
    }

    /// Serialize for authenticated storage. This is not an authentication tag
    /// and must not be used as a receipt or as evidence of server completion.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| "invalid_installation_recovery".into())
    }

    /// Reserve a fresh proof ID. The caller must atomically persist `self`
    /// before transmitting the returned request; failure means do not send.
    pub fn status_request(
        &mut self,
        signer: &impl InstallationSigner,
        jti: &str,
        now: u64,
    ) -> Result<StatusRequest, String> {
        if now < self.started_at
            || self.status_jtis.len() >= 16
            || jti == self.start_jti
            || jti == self.completion_jti
            || self.status_jtis.iter().any(|previous| previous == jti)
        {
            return Err("invalid_installation_status".into());
        }
        let compact = proof_for_key(
            signer,
            &self.issuer,
            Step::Status,
            jti,
            now,
            Some(&self.key),
        )?;
        self.status_jtis.push(jti.to_owned());
        Ok(StatusRequest {
            id: self.id.clone(),
            proof: Zeroizing::new(compact),
        })
    }
}

impl StatusRequest {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn proof(&self) -> &str {
        &self.proof
    }

    /// Only parse a bounded, successful response from the configured IdP over
    /// authenticated transport. Neither `Pending` nor `Unknown` rules out an
    /// in-flight completion, and `Active` is not an app session or token.
    pub fn response(self, body: &[u8]) -> Result<RegistrationStatus, String> {
        if body.len() > 1024 {
            return Err("invalid_installation_status".into());
        }
        let response: StatusResponse =
            serde_json::from_slice(body).map_err(|_| "invalid_installation_status")?;
        if response.id != self.id {
            return Err("invalid_installation_status".into());
        }
        Ok(response.status)
    }
}
