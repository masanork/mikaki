use super::super::records::{decode, encode, state};
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredGrant {
    id: Id,
    request: Digest,
    task_revision: u64,
    expires_at: u64,
}

impl Grant {
    pub fn authority_record(&self) -> Result<String, Denied> {
        encode("grant", self)
    }
    pub fn restore_authority_record(
        text: &str,
        revision: u64,
        revoked: bool,
    ) -> Result<Self, Denied> {
        let raw: StoredGrant = decode("grant", text)?;
        state(revision, revoked)?;
        stored_number(raw.task_revision, false)?;
        stored_number(raw.expires_at, false)?;
        Ok(Self {
            id: raw.id,
            request: raw.request,
            task_revision: raw.task_revision,
            expires_at: raw.expires_at,
            revision,
            revoked,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRun {
    id: Id,
    grant: Id,
    request: Digest,
    issuer: Id,
    issuer_revision: u64,
    client: Id,
    workload: Id,
    proof_key: Digest,
    expires_at: u64,
}

impl Run {
    pub fn authority_record(&self) -> Result<String, Denied> {
        encode("run", self)
    }
    pub fn restore_authority_record(
        text: &str,
        revision: u64,
        revoked: bool,
    ) -> Result<Self, Denied> {
        let raw: StoredRun = decode("run", text)?;
        state(revision, revoked)?;
        stored_number(raw.issuer_revision, false)?;
        stored_number(raw.expires_at, false)?;
        Ok(Self {
            id: raw.id,
            grant: raw.grant,
            request: raw.request,
            issuer: raw.issuer,
            issuer_revision: raw.issuer_revision,
            client: raw.client,
            workload: raw.workload,
            proof_key: raw.proof_key,
            expires_at: raw.expires_at,
            revision,
            revoked,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredGuard {
    owner: Id,
    owner_epoch: u64,
    policy_revision: u64,
    request: Digest,
    request_revision: u64,
    producer: ProducerRevision,
    task: Id,
    task_revision: u64,
    disclosure: Digest,
    proof_key: Digest,
    authentication_expires: u64,
    expires_at: u64,
    adoption_repository: String,
    adoption_ref: String,
    expected_head: String,
    git_oid_length: usize,
}

impl StoredGuard {
    fn restore(
        self,
        request: &WorkRequest,
        grant: &Grant,
        run: &Run,
    ) -> Result<SubmissionGuard, Denied> {
        if self.owner != request.owner
            || self.owner_epoch != request.owner_epoch
            || self.policy_revision != request.policy_revision
            || self.request != request.digest
            || self.request_revision != request.revision()
            || !self.producer.same_producer(grant, run)
            || self.producer.grant_revision != 1
            || self.producer.run_revision != 1
            || grant.request != request.digest
            || run.request != request.digest
            || self.proof_key != run.proof_key
            || self.task.0 != request.input.task_repository
            || self.task_revision != grant.task_revision
            || self.disclosure != Digest::parse_hex(&request.input.disclosure_digest)?
            || self.adoption_repository != request.input.adoption_repository
            || self.adoption_ref != request.input.adoption_ref
            || self.expected_head != request.input.expected_head
            || self.git_oid_length != request.input.base_commit.len()
            || self.expires_at != run.expires_at.min(grant.expires_at)
        {
            return Err(Denied::BindingMismatch);
        }
        stored_number(self.authentication_expires, false)?;
        stored_number(self.expires_at, false)?;
        Ok(SubmissionGuard {
            owner: self.owner,
            owner_epoch: self.owner_epoch,
            policy_revision: self.policy_revision,
            request: self.request,
            request_revision: self.request_revision,
            producer: self.producer,
            task: self.task,
            task_revision: self.task_revision,
            disclosure: self.disclosure,
            proof_key: self.proof_key,
            authentication_expires: self.authentication_expires,
            expires_at: self.expires_at,
            adoption_repository: self.adoption_repository,
            adoption_ref: self.adoption_ref,
            expected_head: self.expected_head,
            git_oid_length: self.git_oid_length,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCandidate {
    provenance: StoredGuard,
    owner: Id,
    producer: ProducerRevision,
    request: Digest,
    adoption_repository: String,
    adoption_ref: String,
    expected_head: String,
    commit: String,
    tree: String,
    evidence: Digest,
    digest: Digest,
}

impl Candidate {
    pub fn authority_record(&self) -> Result<String, Denied> {
        encode("candidate", self)
    }
    /// Reconstruct immutable provenance against its original request and producer
    /// bindings. The CURRENT producer may be revoked; this grants no new work.
    pub fn restore_authority_record(
        text: &str,
        request: &WorkRequest,
        grant: &Grant,
        run: &Run,
    ) -> Result<Self, Denied> {
        let raw: StoredCandidate = decode("candidate", text)?;
        let guard = raw.provenance.restore(request, grant, run)?;
        let current = guard.clone();
        let candidate = guard
            .prepare_candidate(CandidateInput {
                commit: raw.commit,
                tree: raw.tree,
                evidence: raw.evidence,
            })?
            .confirm(current)?;
        if candidate.digest != raw.digest
            || candidate.owner != raw.owner
            || candidate.producer != raw.producer
            || candidate.request != raw.request
            || candidate.adoption_repository != raw.adoption_repository
            || candidate.adoption_ref != raw.adoption_ref
            || candidate.expected_head != raw.expected_head
        {
            return Err(Denied::ReviewMismatch);
        }
        Ok(candidate)
    }
}
