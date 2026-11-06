//! Persist-before-send orchestration. Storage must authenticate records, offer
//! atomic compare-and-set across writers, and separately address rollback.
use crate::{
    installation_proof::InstallationSigner,
    installation_transaction::{CompletionRequest, RecoveryCheckpoint, StatusRequest},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub trait RecoveryStore {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    /// An error can mean an unknown write outcome. Do not transmit the proof.
    fn compare_and_set(&self, expected: Option<[u8; 32]>, value: &[u8]) -> Result<(), String>;
}

pub struct PersistedCompletion {
    id: String,
    proof: Zeroizing<String>,
}
impl PersistedCompletion {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn proof(&self) -> &str {
        &self.proof
    }
}

/// Persist the initial checkpoint before the completion proof is made available.
/// A failed or lost storage response is an unknown outcome, not permission to send.
pub fn persist_completion(
    store: &impl RecoveryStore,
    request: CompletionRequest,
    owner_binding: &str,
) -> Result<PersistedCompletion, String> {
    let id = request.id().to_owned();
    let (checkpoint, proof) = request.into_recovery(owner_binding)?;
    let bytes = checkpoint.encode()?;
    store.compare_and_set(None, &bytes)?;
    Ok(PersistedCompletion { id, proof })
}

/// Validate the authenticated record and durably reserve this proof ID before
/// making the status request available. No automatic retry on CAS failure.
pub fn persist_status_request(
    store: &impl RecoveryStore,
    signer: &impl InstallationSigner,
    issuer: &str,
    owner_binding: &str,
    jti: &str,
    now: u64,
) -> Result<StatusRequest, String> {
    let prior = store.load()?.ok_or("installation_recovery_unavailable")?;
    if prior.len() > 4096 {
        return Err("invalid_installation_recovery".into());
    }
    let mut checkpoint = RecoveryCheckpoint::restore(&prior, issuer, owner_binding, signer, now)?;
    let request = checkpoint.status_request(signer, jti, now)?;
    let bytes = checkpoint.encode()?;
    let expected: [u8; 32] = Sha256::digest(&*prior).into();
    store.compare_and_set(Some(expected), &bytes)?;
    Ok(request)
}
