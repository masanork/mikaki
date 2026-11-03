//! Local, one-shot installation registration preparation. This does not send
//! requests, authenticate the user, record success, or create a device session.
use crate::{
    installation_proof::{InstallationSigner, Step, opaque, proof_for_key},
    issuance::PublicJwk,
};
use serde::Deserialize;
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
    pub id: String,
    pub proof: Zeroizing<String>,
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
            id: self.id,
            proof: Zeroizing::new(compact),
        })
    }
}
