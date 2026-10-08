use super::delegation::ProducerRevision;
mod records;
use super::*;

/// Primary authority records, including revoked producer tombstones. They must
/// remain available while retained candidates or pending operations refer to them.
pub struct AdoptionContext<'a> {
    pub candidate: &'a Candidate,
    pub grant: &'a Grant,
    pub run: &'a Run,
    pub target: &'a CodeTarget,
    pub environment: &'a Environment<'a>,
}

impl AdoptionContext<'_> {
    fn check_target(&self) -> Result<(), Denied> {
        self.candidate.check_producer(self.grant, self.run)?;
        if self.target.owner != self.candidate.owner {
            return Err(Denied::OwnerMismatch);
        }
        if !self.target.writable
            || self.target.repository.0 != self.candidate.adoption_repository
            || self.target.reference != self.candidate.adoption_ref
            || self.target.head != self.candidate.expected_head
        {
            return Err(Denied::StaleTarget);
        }
        Ok(())
    }
}

/// Exact human code approval. It cannot approve a context-decision write.
#[derive(Debug, Serialize)]
pub struct CodeApproval {
    id: Id,
    #[serde(skip)]
    revision: u64,
    owner: Id,
    owner_epoch: u64,
    policy_revision: u64,
    candidate: Digest,
    producer: ProducerRevision,
    target_revision: u64,
    expires_at: u64,
    #[serde(skip)]
    revoked: bool,
}

impl CodeApproval {
    pub fn candidate_digest(&self) -> Digest {
        self.candidate
    }
    pub fn id(&self) -> &str {
        &self.id.0
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
    pub fn approve(
        id: &str,
        reviewed: Digest,
        session: &OwnerSession,
        context: &AdoptionContext<'_>,
        expires_at: u64,
    ) -> Result<Self, Denied> {
        session.check(context.environment)?;
        context.check_target()?;
        if context.candidate.owner != session.id {
            return Err(Denied::OwnerMismatch);
        }
        if context.candidate.digest != reviewed {
            return Err(Denied::ReviewMismatch);
        }
        deadline(context.environment.now, expires_at, MAX_APPROVAL_SECONDS)?;
        if expires_at > session.expires_at {
            return Err(Denied::Expired);
        }
        // Producer liveness is deliberately not required for a FRESH owner review.
        // Changes after this approval invalidate it through the revision comparison.
        Ok(Self {
            id: Id::parse(id)?,
            revision: 1,
            owner: session.id.clone(),
            owner_epoch: session.epoch,
            policy_revision: context.environment.policy_revision,
            candidate: reviewed,
            producer: ProducerRevision::current(context.grant, context.run),
            target_revision: context.target.revision,
            expires_at,
            revoked: false,
        })
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

    fn check(&self, action: &str, context: &AdoptionContext<'_>) -> Result<(), Denied> {
        if action != ADOPT_CODE {
            return Err(Denied::UnsupportedAction);
        }
        context
            .environment
            .check_owner(&self.owner, self.owner_epoch)?;
        if self.revoked {
            return Err(Denied::Revoked);
        }
        if context.environment.now >= self.expires_at {
            return Err(Denied::Expired);
        }
        if context.environment.policy_revision != self.policy_revision {
            return Err(Denied::StalePolicy);
        }
        context.check_target()?;
        if context.candidate.owner != self.owner || context.candidate.digest != self.candidate {
            return Err(Denied::ReviewMismatch);
        }
        if self.target_revision != context.target.revision {
            return Err(Denied::StaleTarget);
        }
        if self.producer != ProducerRevision::current(context.grant, context.run) {
            return Err(Denied::StaleAuthority);
        }
        Ok(())
    }

    pub fn prepare_operation(
        &self,
        action: &str,
        operation_id: &str,
        context: &AdoptionContext<'_>,
    ) -> Result<ExternalOperation, Denied> {
        self.check(action, context)?;
        Ok(ExternalOperation {
            id: Id::parse(operation_id)?,
            effect: self.effect(context),
            state: OperationState::Prepared,
            receipt: None,
        })
    }

    /// Repeat live guards at the dispatch boundary. Persist this transition with
    /// its audit BEFORE calling the external adapter. Only primary-store CAS can
    /// provide one-winner dispatch; this in-memory method does not do so.
    pub fn dispatch(
        &self,
        operation: &mut ExternalOperation,
        context: &AdoptionContext<'_>,
    ) -> Result<(), Denied> {
        if operation.state != OperationState::Prepared {
            return Err(Denied::InvalidTransition);
        }
        self.check(ADOPT_CODE, context)?;
        if operation.effect != self.effect(context) {
            return Err(Denied::Conflict);
        }
        operation.state = OperationState::Dispatched;
        Ok(())
    }

    fn effect(&self, context: &AdoptionContext<'_>) -> Effect {
        Effect {
            approval: self.id.clone(),
            approval_revision: self.revision,
            owner: self.owner.clone(),
            owner_epoch: self.owner_epoch,
            policy_revision: self.policy_revision,
            producer: self.producer.clone(),
            candidate: self.candidate,
            target_revision: context.target.revision,
            repository: context.target.repository.clone(),
            reference: context.target.reference.clone(),
            expected_head: context.target.head.clone(),
            commit: context.candidate.commit.clone(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct Effect {
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

/// External outcome is independent of current owner/producer authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Prepared,
    Dispatched,
    OutcomeUnknown,
    Applied,
    Rejected,
    Cancelled,
}

/// No Clone/Deserialize: storage must reserve a unique stable operation ID and
/// retain exact effect identity across retries. Core values alone do not enforce
/// global ID uniqueness or consume an approval in the durable ledger.
#[derive(Debug, Serialize)]
#[must_use = "persist operation identity, guards and audit before any external effect"]
pub struct ExternalOperation {
    id: Id,
    effect: Effect,
    #[serde(skip)]
    state: OperationState,
    #[serde(skip)]
    receipt: Option<Id>,
}

impl ExternalOperation {
    pub fn id(&self) -> &str {
        &self.id.0
    }
    pub fn state(&self) -> OperationState {
        self.state
    }
    pub fn repository(&self) -> &str {
        &self.effect.repository.0
    }
    pub fn reference(&self) -> &str {
        &self.effect.reference
    }
    pub fn expected_head(&self) -> &str {
        &self.effect.expected_head
    }
    pub fn commit(&self) -> &str {
        &self.effect.commit
    }
    pub fn receipt(&self) -> Option<&str> {
        self.receipt.as_ref().map(|id| id.0.as_str())
    }

    pub fn cancel_undispatched(&mut self) -> Result<(), Denied> {
        match self.state {
            OperationState::Prepared | OperationState::Cancelled => {
                self.state = OperationState::Cancelled;
                Ok(())
            }
            _ => Err(Denied::InvalidTransition),
        }
    }

    pub fn mark_outcome_unknown(&mut self) -> Result<(), Denied> {
        match self.state {
            OperationState::Dispatched | OperationState::OutcomeUnknown => {
                self.state = OperationState::OutcomeUnknown;
                Ok(())
            }
            _ => Err(Denied::InvalidTransition),
        }
    }

    /// Call only after authenticating/reconciling the adapter's exact external
    /// effect. A receipt ID is a safe reference, not a credential or proof itself.
    pub fn confirm_applied(&mut self, receipt: &str) -> Result<(), Denied> {
        self.finish(OperationState::Applied, receipt)
    }
    pub fn confirm_rejected(&mut self, receipt: &str) -> Result<(), Denied> {
        self.finish(OperationState::Rejected, receipt)
    }

    fn finish(&mut self, outcome: OperationState, receipt: &str) -> Result<(), Denied> {
        let receipt = Id::parse(receipt)?;
        match self.state {
            OperationState::Dispatched | OperationState::OutcomeUnknown => {
                self.state = outcome;
                self.receipt = Some(receipt);
                Ok(())
            }
            OperationState::Applied | OperationState::Rejected => {
                if self.state == outcome && self.receipt.as_ref() == Some(&receipt) {
                    Ok(())
                } else {
                    Err(Denied::Conflict)
                }
            }
            _ => Err(Denied::InvalidTransition),
        }
    }
}
