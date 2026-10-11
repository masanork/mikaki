use super::super::records::{decode, encode, producer, state};
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredApproval {
    id: Id,
    owner: Id,
    owner_epoch: u64,
    policy_revision: u64,
    candidate: Digest,
    producer: ProducerRevision,
    target_revision: u64,
    expires_at: u64,
}

impl CodeApproval {
    pub fn authority_record(&self) -> Result<String, Denied> {
        encode("code_approval", self)
    }
    pub fn restore_authority_record(
        text: &str,
        revision: u64,
        revoked: bool,
    ) -> Result<Self, Denied> {
        let raw: StoredApproval = decode("code_approval", text)?;
        state(revision, revoked)?;
        stored_number(raw.owner_epoch, true)?;
        stored_number(raw.policy_revision, false)?;
        stored_number(raw.target_revision, false)?;
        stored_number(raw.expires_at, false)?;
        producer(&raw.producer)?;
        Ok(Self {
            id: raw.id,
            owner: raw.owner,
            owner_epoch: raw.owner_epoch,
            policy_revision: raw.policy_revision,
            candidate: raw.candidate,
            producer: raw.producer,
            target_revision: raw.target_revision,
            expires_at: raw.expires_at,
            revision,
            revoked,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEffect {
    approval: Id,
    approval_revision: u64,
    owner: Id,
    owner_epoch: u64,
    policy_revision: u64,
    producer: ProducerRevision,
    candidate: Digest,
    target_revision: u64,
    repository: Id,
    reference: String,
    expected_head: String,
    commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOperation {
    id: Id,
    effect: StoredEffect,
}

impl ExternalOperation {
    pub fn authority_record(&self) -> Result<String, Denied> {
        encode("code_operation", self)
    }
    pub fn restore_authority_record(
        text: &str,
        current: OperationState,
        receipt: Option<&str>,
    ) -> Result<Self, Denied> {
        let raw: StoredOperation = decode("code_operation", text)?;
        let effect = raw.effect;
        stored_number(effect.owner_epoch, true)?;
        for revision in [
            effect.approval_revision,
            effect.policy_revision,
            effect.target_revision,
        ] {
            stored_number(revision, false)?;
        }
        producer(&effect.producer)?;
        request::branch_ref(&effect.reference)?;
        git_oid(&effect.expected_head)?;
        git_oid(&effect.commit)?;
        if effect.expected_head.len() != effect.commit.len() {
            return Err(Denied::InvalidInput);
        }
        let terminal = matches!(current, OperationState::Applied | OperationState::Rejected);
        if terminal != receipt.is_some() {
            return Err(Denied::InvalidInput);
        }
        let receipt = receipt.map(Id::parse).transpose()?;
        Ok(Self {
            id: raw.id,
            effect: Effect {
                approval: effect.approval,
                approval_revision: effect.approval_revision,
                owner: effect.owner,
                owner_epoch: effect.owner_epoch,
                policy_revision: effect.policy_revision,
                producer: effect.producer,
                candidate: effect.candidate,
                target_revision: effect.target_revision,
                repository: effect.repository,
                reference: effect.reference,
                expected_head: effect.expected_head,
                commit: effect.commit,
            },
            state: current,
            receipt,
        })
    }
}
