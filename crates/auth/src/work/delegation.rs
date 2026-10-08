use super::*;
mod records;

/// Owner-approved request; revocation changes the revision even if tokens survive.
#[derive(Debug, Serialize)]
pub struct Grant {
    pub(super) id: Id,
    #[serde(skip)]
    pub(super) revision: u64,
    request: Digest,
    task_revision: u64,
    expires_at: u64,
    #[serde(skip)]
    revoked: bool,
}

impl Grant {
    pub fn id(&self) -> &str {
        &self.id.0
    }
    pub fn request_digest(&self) -> Digest {
        self.request
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn approve(
        id: &str,
        request: &WorkRequest,
        reviewed: Digest,
        session: &OwnerSession,
        task: &TaskRepository,
        environment: &Environment<'_>,
    ) -> Result<Self, Denied> {
        session.check(environment)?;
        request.check(environment)?;
        if session.id != request.owner {
            return Err(Denied::OwnerMismatch);
        }
        if request.digest != reviewed {
            return Err(Denied::ReviewMismatch);
        }
        task.check(request)?;
        Ok(Self {
            id: Id::parse(id)?,
            revision: 1,
            request: reviewed,
            task_revision: task.revision,
            expires_at: request.expires_at(),
            revoked: false,
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }
    pub fn revoke(&mut self) -> Result<(), Denied> {
        if !self.revoked {
            self.revision = self
                .revision
                .checked_add(1)
                .ok_or(Denied::InvalidTransition)?;
            self.revoked = true;
        }
        Ok(())
    }

    fn check(
        &self,
        request: &WorkRequest,
        task: &TaskRepository,
        environment: &Environment<'_>,
    ) -> Result<(), Denied> {
        request.check(environment)?;
        if self.revoked {
            return Err(Denied::Revoked);
        }
        if environment.now >= self.expires_at {
            return Err(Denied::Expired);
        }
        if self.request != request.digest {
            return Err(Denied::StaleRequest);
        }
        task.check(request)?;
        if task.revision != self.task_revision {
            return Err(Denied::StaleTarget);
        }
        Ok(())
    }
}

/// Verified managed-launcher and requester/proof facts, not raw token claims.
/// The adapter must authenticate the requester, validate the registered issuer,
/// signature/audience/times/replay and proof key, then resolve internal IDs.
#[derive(Debug)]
pub struct ManagedActor {
    issuer: Id,
    issuer_revision: u64,
    client: Id,
    workload: Id,
    run: Id,
    grant: Id,
    proof_key: Digest,
    expires_at: u64,
}

/// Construction belongs only to the trusted verifier, never unverified HTTP input.
pub struct ManagedActorFacts<'a> {
    pub issuer: &'a str,
    pub issuer_revision: u64,
    pub client: &'a str,
    pub workload: &'a str,
    pub run: &'a str,
    pub grant: &'a str,
    pub proof_key: Digest,
    pub expires_at: u64,
}

impl ManagedActor {
    pub fn run_id(&self) -> &str {
        &self.run.0
    }
    pub fn grant_id(&self) -> &str {
        &self.grant.0
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn from_verified_request(facts: ManagedActorFacts<'_>) -> Result<Self, Denied> {
        stored_number(facts.issuer_revision, false)?;
        stored_number(facts.expires_at, false)?;
        Ok(Self {
            issuer: Id::parse(facts.issuer)?,
            issuer_revision: facts.issuer_revision,
            client: Id::parse(facts.client)?,
            workload: Id::parse(facts.workload)?,
            run: Id::parse(facts.run)?,
            grant: Id::parse(facts.grant)?,
            proof_key: facts.proof_key,
            expires_at: facts.expires_at,
        })
    }
}

/// One registered instance. This status describes authorization, not execution.
#[derive(Debug, Serialize)]
pub struct Run {
    pub(super) id: Id,
    #[serde(skip)]
    pub(super) revision: u64,
    pub(super) grant: Id,
    request: Digest,
    issuer: Id,
    issuer_revision: u64,
    client: Id,
    workload: Id,
    proof_key: Digest,
    expires_at: u64,
    #[serde(skip)]
    revoked: bool,
}

impl Run {
    pub fn id(&self) -> &str {
        &self.id.0
    }
    pub fn grant_id(&self) -> &str {
        &self.grant.0
    }
    pub fn request_digest(&self) -> Digest {
        self.request
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    /// Called only by the managed registration authority after verifying launch.
    pub fn register(
        actor: &ManagedActor,
        grant: &Grant,
        request: &WorkRequest,
        task: &TaskRepository,
        expires_at: u64,
        environment: &Environment<'_>,
    ) -> Result<Self, Denied> {
        grant.check(request, task, environment)?;
        if actor.expires_at <= environment.now {
            return Err(Denied::Expired);
        }
        if actor.grant != grant.id
            || actor.client.0 != request.input.recipient
            || actor.workload.0 != request.input.workload
        {
            return Err(Denied::BindingMismatch);
        }
        deadline(environment.now, expires_at, MAX_WORK_SECONDS)?;
        if expires_at > grant.expires_at {
            return Err(Denied::Expired);
        }
        Ok(Self {
            id: actor.run.clone(),
            revision: 1,
            grant: grant.id.clone(),
            request: request.digest,
            issuer: actor.issuer.clone(),
            issuer_revision: actor.issuer_revision,
            client: actor.client.clone(),
            workload: actor.workload.clone(),
            proof_key: actor.proof_key,
            expires_at,
            revoked: false,
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }
    pub fn revoke(&mut self) -> Result<(), Denied> {
        if !self.revoked {
            self.revision = self
                .revision
                .checked_add(1)
                .ok_or(Denied::InvalidTransition)?;
            self.revoked = true;
        }
        Ok(())
    }

    /// Local ABAC intersection; a guard is a read set, not a bearer permission.
    pub fn authorize_submission(
        &self,
        action: &str,
        grant: &Grant,
        request: &WorkRequest,
        actor: &ManagedActor,
        task: &TaskRepository,
        environment: &Environment<'_>,
    ) -> Result<SubmissionGuard, Denied> {
        if action != SUBMIT {
            return Err(Denied::UnsupportedAction);
        }
        grant.check(request, task, environment)?;
        if self.revoked {
            return Err(Denied::Revoked);
        }
        if environment.now >= self.expires_at || environment.now >= actor.expires_at {
            return Err(Denied::Expired);
        }
        if self.request != request.digest {
            return Err(Denied::StaleRequest);
        }
        if self.grant != grant.id
            || actor.grant != grant.id
            || actor.run != self.id
            || actor.issuer != self.issuer
            || actor.issuer_revision != self.issuer_revision
            || actor.client != self.client
            || actor.workload != self.workload
            || actor.proof_key != self.proof_key
        {
            return Err(Denied::BindingMismatch);
        }
        Ok(SubmissionGuard {
            owner: request.owner.clone(),
            owner_epoch: request.owner_epoch,
            policy_revision: environment.policy_revision,
            request: request.digest,
            request_revision: request.revision(),
            producer: ProducerRevision::current(grant, self),
            task: task.id.clone(),
            task_revision: task.revision,
            disclosure: task.disclosure,
            proof_key: actor.proof_key,
            authentication_expires: actor.expires_at,
            expires_at: self.expires_at.min(grant.expires_at),
            adoption_repository: request.input.adoption_repository.clone(),
            adoption_ref: request.input.adoption_ref.clone(),
            expected_head: request.input.expected_head.clone(),
            git_oid_length: request.input.base_commit.len(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProducerRevision {
    grant: Id,
    grant_revision: u64,
    run: Id,
    run_revision: u64,
}

impl ProducerRevision {
    pub(super) fn grant_revision(&self) -> u64 {
        self.grant_revision
    }
    pub(super) fn run_revision(&self) -> u64 {
        self.run_revision
    }
    pub(super) fn current(grant: &Grant, run: &Run) -> Self {
        Self {
            grant: grant.id.clone(),
            grant_revision: grant.revision,
            run: run.id.clone(),
            run_revision: run.revision,
        }
    }
    pub(super) fn same_producer(&self, grant: &Grant, run: &Run) -> bool {
        self.grant == grant.id && self.run == run.id && run.grant == grant.id
    }
}

/// Exact read set for the future atomic submit/audit transaction. No Deserialize.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[must_use = "repeat this read set in an atomic primary-store transition with audit"]
pub struct SubmissionGuard {
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

#[derive(Serialize)]
pub struct CandidateInput {
    pub commit: String,
    pub tree: String,
    /// References to assertions/checks; this digest is not a passing CI verdict.
    pub evidence: Digest,
}

#[must_use = "confirm against current guards and persist/audit before exposing a candidate"]
pub struct PreparedCandidate {
    guard: SubmissionGuard,
    candidate: Candidate,
}

impl SubmissionGuard {
    pub fn prepare_candidate(self, input: CandidateInput) -> Result<PreparedCandidate, Denied> {
        let commit = git_oid(&input.commit)?;
        let tree = git_oid(&input.tree)?;
        if commit.len() != self.git_oid_length || tree.len() != self.git_oid_length {
            return Err(Denied::InvalidInput);
        }
        let mut hash = Hash::new("mikaki.work-candidate.v1");
        hash.bytes(&self.request.0);
        hash.text(&self.owner.0);
        hash.number(self.owner_epoch);
        hash.number(self.policy_revision);
        hash.text(&self.producer.grant.0);
        hash.number(self.producer.grant_revision);
        hash.text(&self.producer.run.0);
        hash.number(self.producer.run_revision);
        hash.bytes(&self.proof_key.0);
        hash.text(&self.task.0);
        hash.number(self.task_revision);
        hash.bytes(&self.disclosure.0);
        hash.text(&commit);
        hash.text(&tree);
        hash.bytes(&input.evidence.0);
        let candidate = Candidate {
            provenance: self.clone(),
            owner: self.owner.clone(),
            producer: self.producer.clone(),
            request: self.request,
            adoption_repository: self.adoption_repository.clone(),
            adoption_ref: self.adoption_ref.clone(),
            expected_head: self.expected_head.clone(),
            commit,
            tree,
            evidence: input.evidence,
            digest: hash.finish(),
        };
        Ok(PreparedCandidate {
            guard: self,
            candidate,
        })
    }
}

impl PreparedCandidate {
    /// Obtain `current` by reevaluation of primary records and commit the matching
    /// read set + candidate + audit atomically. This pure comparison is not a
    /// concurrency or successful persistence guarantee.
    pub fn confirm(self, current: SubmissionGuard) -> Result<Candidate, Denied> {
        if self.guard != current {
            return Err(Denied::StaleAuthority);
        }
        Ok(self.candidate)
    }
}

/// Immutable bound result. Actual Git object/tree/ancestry verification is an
/// adapter responsibility; agent evidence is not silently treated as trusted CI.
#[derive(Debug, Serialize)]
pub struct Candidate {
    provenance: SubmissionGuard,
    pub(super) owner: Id,
    pub(super) producer: ProducerRevision,
    pub(super) request: Digest,
    pub(super) adoption_repository: String,
    pub(super) adoption_ref: String,
    pub(super) expected_head: String,
    pub(super) commit: String,
    tree: String,
    evidence: Digest,
    pub(super) digest: Digest,
}

impl Candidate {
    pub fn owner_id(&self) -> &str {
        &self.owner.0
    }
    pub fn request_digest(&self) -> Digest {
        self.request
    }
    pub fn grant_id(&self) -> &str {
        &self.producer.grant.0
    }
    pub fn run_id(&self) -> &str {
        &self.producer.run.0
    }
    pub(super) fn check_producer(&self, grant: &Grant, run: &Run) -> Result<(), Denied> {
        if !self.producer.same_producer(grant, run)
            || self.request != grant.request
            || self.request != run.request
        {
            return Err(Denied::BindingMismatch);
        }
        Ok(())
    }
    pub fn digest(&self) -> Digest {
        self.digest
    }
    pub fn commit(&self) -> &str {
        &self.commit
    }
    pub fn tree(&self) -> &str {
        &self.tree
    }
    pub fn evidence_digest(&self) -> Digest {
        self.evidence
    }
}
