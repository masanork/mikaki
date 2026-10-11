//! Durable pre-I/O identity and unreleased resource accounting. These records
//! never grant a workload permission or prove Git/token facts by themselves.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub owner: Id,
    pub owner_epoch: u64,
    pub policy_revision: u64,
    pub policy_projection: Digest,
    pub disclosure: Digest,
    pub expires_at: u64,
    pub reserved_bytes: u64,
    pub source_ids: Vec<String>,
    pub snapshot_repository: Id,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    operation_id: Id,
    binding: Binding,
    task_repository: Id,
    task_namespace: String,
    snapshot_namespace: String,
    task_name: String,
    snapshot_name: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationState {
    Reserved,
    Dispatched,
    Verified,
    CleanupPending,
    Cleaned,
}
impl PreparationState {
    pub fn name(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Dispatched => "dispatched",
            Self::Verified => "verified",
            Self::CleanupPending => "cleanup_pending",
            Self::Cleaned => "cleaned",
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Preparation {
    plan: Plan,
    digest: Digest,
    #[serde(skip)]
    state: PreparationState,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    plan: Plan,
    digest: Digest,
}

/// Trusted adapter result, not Deserialize or a browser DTO. Construct only
/// after exact refs, complete reachable objects and selected bytes were checked,
/// AND every initial credential was identified and independently refused after
/// revocation. A response, token list or last_push_at alone is not that evidence.
/// No plaintext credentials belong here. Protected adapter receipts retain the
/// concrete token handles; this public commitment carries their receipt digests.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    preparation: Digest,
    task_repo_id: Id,
    snapshot_repo_id: Id,
    payload_receipt: Digest,
    credential_receipt: Digest,
}
#[derive(Debug)]
pub struct VerifiedPreparation(Evidence);
impl VerifiedPreparation {
    pub fn credential_receipt(&self) -> Digest {
        self.0.credential_receipt
    }
    pub fn from_independently_verified(
        preparation: &Preparation,
        task_repo_id: &str,
        snapshot_repo_id: &str,
        payload_receipt: Digest,
        credential_receipt: Digest,
    ) -> Result<Self, Denied> {
        let evidence = Evidence {
            preparation: preparation.digest,
            task_repo_id: Id::parse(task_repo_id)?,
            snapshot_repo_id: Id::parse(snapshot_repo_id)?,
            payload_receipt,
            credential_receipt,
        };
        if evidence.task_repo_id == evidence.snapshot_repo_id {
            return Err(Denied::BindingMismatch);
        }
        Ok(Self(evidence))
    }
    pub fn authority_record(&self) -> Result<String, Denied> {
        records::encode("preparation_evidence", &self.0)
    }
    pub fn restore_authority_record(body: &str) -> Result<Self, Denied> {
        let evidence: Evidence = records::decode("preparation_evidence", body)?;
        if evidence.task_repo_id == evidence.snapshot_repo_id {
            return Err(Denied::BindingMismatch);
        }
        Ok(Self(evidence))
    }
}

fn namespace(value: &str) -> Result<(), Denied> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(Denied::InvalidInput);
    }
    Ok(())
}
fn names(id: &Id) -> (String, String) {
    let mut h = Hash::new("mikaki.work-preparation-name.v1");
    h.text(&id.0);
    let digest = h.finish().to_hex();
    (
        format!("wk-{}-code", &digest[..32]),
        format!("wk-{}-snapshot", &digest[..32]),
    )
}
impl Plan {
    fn validate(&self) -> Result<(), Denied> {
        namespace(&self.task_namespace)?;
        namespace(&self.snapshot_namespace)?;
        let b = &self.binding;
        stored_number(b.owner_epoch, true)?;
        stored_number(b.policy_revision, false)?;
        stored_number(b.expires_at, false)?;
        if b.reserved_bytes > 67_239_936
            || b.source_ids.is_empty()
            || b.source_ids.len() > 5
            || b.source_ids.iter().any(|id| Id::parse(id).is_err())
            || b.source_ids
                .iter()
                .enumerate()
                .any(|(i, id)| b.source_ids[..i].contains(id))
            || self.task_repository == b.snapshot_repository
            || b.source_ids.contains(&self.task_repository.0)
            || b.source_ids.contains(&b.snapshot_repository.0)
            || names(&self.operation_id) != (self.task_name.clone(), self.snapshot_name.clone())
        {
            return Err(Denied::BindingMismatch);
        }
        Ok(())
    }
    fn digest(&self) -> Digest {
        let mut h = Hash::new("mikaki.work-preparation.v1");
        h.text(&self.operation_id.0);
        h.text(&self.binding.owner.0);
        h.number(self.binding.owner_epoch);
        h.number(self.binding.policy_revision);
        h.bytes(&self.binding.policy_projection.0);
        h.bytes(&self.binding.disclosure.0);
        h.number(self.binding.expires_at);
        h.number(self.binding.reserved_bytes);
        h.number(self.binding.source_ids.len() as u64);
        for id in &self.binding.source_ids {
            h.text(id);
        }
        h.text(&self.binding.snapshot_repository.0);
        h.text(&self.task_repository.0);
        h.text(&self.task_namespace);
        h.text(&self.snapshot_namespace);
        h.text(&self.task_name);
        h.text(&self.snapshot_name);
        h.finish()
    }
}
impl Preparation {
    pub fn credential_destination(&self, role: CredentialRole) -> (&str, &str) {
        match role {
            CredentialRole::Task => (&self.plan.task_namespace, &self.plan.task_name),
            CredentialRole::Snapshot => (&self.plan.snapshot_namespace, &self.plan.snapshot_name),
        }
    }
    pub fn expires_at(&self) -> u64 {
        self.plan.binding.expires_at
    }
    /// Owner-visible fixed destinations only; no token handles, credentials or
    /// private custody records. Availability is a separate current-store fact.
    pub fn review(
        &self,
        evidence: Option<&VerifiedPreparation>,
    ) -> Result<serde_json::Value, Denied> {
        if evidence.is_some_and(|e| {
            e.0.preparation != self.digest
                || matches!(
                    self.state,
                    PreparationState::Reserved | PreparationState::Dispatched
                )
        }) || (self.state == PreparationState::Verified && evidence.is_none())
        {
            return Err(Denied::BindingMismatch);
        }
        let destination_digest = evidence.map(|e| {
            let mut h = Hash::new("mikaki.work-prepared-destination.v1");
            h.bytes(&self.digest.0);
            h.text(self.task_repository());
            h.text(&self.plan.binding.snapshot_repository.0);
            h.text(&self.plan.task_namespace);
            h.text(&self.plan.task_name);
            h.text(&e.0.task_repo_id.0);
            h.text(&self.plan.snapshot_namespace);
            h.text(&self.plan.snapshot_name);
            h.text(&e.0.snapshot_repo_id.0);
            h.finish()
        });
        Ok(serde_json::json!({
            "id":self.id(), "digest":self.digest, "disclosure_digest":self.disclosure_digest(),
            "destination_digest":destination_digest,
            "task_repository":self.task_repository(), "snapshot_repository":self.plan.binding.snapshot_repository,
            "state":self.state, "expires_at":self.plan.binding.expires_at,
            "task":{"namespace":self.plan.task_namespace,"name":self.plan.task_name,
                "repository_id":evidence.map(|e| &e.0.task_repo_id)},
            "snapshot":{"namespace":self.plan.snapshot_namespace,"name":self.plan.snapshot_name,
                "repository_id":evidence.map(|e| &e.0.snapshot_repo_id)},
        }))
    }
    /// Restore historical task facts too, but only Verified/current facts can
    /// authorize production. The adapter repeats availability at D1 commit.
    pub fn task_authority(
        &self,
        evidence: &VerifiedPreparation,
        disclosure: ResolvedDisclosure,
        revision: u64,
        sources_current: bool,
    ) -> Result<TaskRepository, Denied> {
        if evidence.0.preparation != self.digest
            || disclosure.preparation_binding()? != self.plan.binding
        {
            return Err(Denied::BindingMismatch);
        }
        let mut task = TaskRepository::from_authority(
            self.owner_id(),
            &self.plan.task_repository.0,
            revision,
            self.disclosure_digest(),
        )?;
        task.available =
            self.state == PreparationState::Verified && sources_current && revision == 1;
        task.prepared_disclosure = Some(disclosure);
        Ok(task)
    }
    /// Internal deployment/onboarding mapping only. Namespace names and logical
    /// task IDs are not owner input authority. Remote names are generated once.
    pub fn from_registered_disclosure(
        disclosure: &ResolvedDisclosure,
        operation_id: &str,
        task_repository: &str,
        task_namespace: &str,
        snapshot_namespace: &str,
    ) -> Result<Self, Denied> {
        let id = Id::parse(operation_id)?;
        let (task_name, snapshot_name) = names(&id);
        let plan = Plan {
            operation_id: id,
            binding: disclosure.preparation_binding()?,
            task_repository: Id::parse(task_repository)?,
            task_namespace: task_namespace.into(),
            snapshot_namespace: snapshot_namespace.into(),
            task_name,
            snapshot_name,
        };
        plan.validate()?;
        Ok(Self {
            digest: plan.digest(),
            plan,
            state: PreparationState::Reserved,
        })
    }
    pub fn id(&self) -> &str {
        &self.plan.operation_id.0
    }
    pub fn owner_id(&self) -> &str {
        &self.plan.binding.owner.0
    }
    pub fn task_repository(&self) -> &str {
        &self.plan.task_repository.0
    }
    pub fn disclosure_digest(&self) -> Digest {
        self.plan.binding.disclosure
    }
    pub fn digest(&self) -> Digest {
        self.digest
    }
    pub fn state(&self) -> PreparationState {
        self.state
    }
    pub fn reserved_bytes(&self) -> u64 {
        self.plan.binding.reserved_bytes
    }
    pub fn authority_record(&self) -> Result<String, Denied> {
        records::encode("preparation", self)
    }
    pub fn restore_authority_record(body: &str, state: PreparationState) -> Result<Self, Denied> {
        let stored: Stored = records::decode("preparation", body)?;
        stored.plan.validate()?;
        if stored.digest != stored.plan.digest() {
            return Err(Denied::ReviewMismatch);
        }
        Ok(Self {
            plan: stored.plan,
            digest: stored.digest,
            state,
        })
    }
    pub fn dispatch(&mut self, environment: &Environment<'_>) -> Result<(), Denied> {
        if self.state != PreparationState::Reserved {
            return Err(Denied::InvalidTransition);
        }
        environment.check_owner(&self.plan.binding.owner, self.plan.binding.owner_epoch)?;
        if environment.policy_revision != self.plan.binding.policy_revision {
            return Err(Denied::StalePolicy);
        }
        if environment.now >= self.plan.binding.expires_at {
            return Err(Denied::Expired);
        }
        self.state = PreparationState::Dispatched;
        Ok(())
    }
    pub fn verify(&mut self, evidence: &VerifiedPreparation) -> Result<(), Denied> {
        if evidence.0.preparation != self.digest {
            return Err(Denied::BindingMismatch);
        }
        if !matches!(
            self.state,
            PreparationState::Dispatched | PreparationState::Verified
        ) {
            return Err(Denied::InvalidTransition);
        }
        self.state = PreparationState::Verified;
        Ok(())
    }
    pub fn require_cleanup(&mut self) {
        self.state = match self.state {
            PreparationState::Reserved => PreparationState::Cleaned,
            PreparationState::Cleaned => PreparationState::Cleaned,
            _ => PreparationState::CleanupPending,
        };
    }
    /// Receipt must independently establish repo/token cleanup at the fixed
    /// destinations. Never infer cleanup from expiry, missing source ACL or an
    /// empty token list; the trusted adapter establishes concrete remote reality.
    pub fn confirm_cleaned(&mut self) -> Result<(), Denied> {
        if !matches!(
            self.state,
            PreparationState::CleanupPending | PreparationState::Cleaned
        ) {
            return Err(Denied::InvalidTransition);
        }
        self.state = PreparationState::Cleaned;
        Ok(())
    }
}
