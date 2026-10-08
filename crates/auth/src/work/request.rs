use super::*;
use serde::{Deserialize, Serialize};
mod records;

/// Untrusted owner input. Parsing this does not authorize a repository or disclosure.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestInput {
    pub profile: String,
    pub request_id: String,
    pub revision: u64,
    pub goal: String,
    pub acceptance: String,
    pub code_repository: String,
    pub base_commit: String,
    pub disclosure_digest: String,
    pub recipient: String,
    pub workload: String,
    pub task_repository: String,
    pub adoption_repository: String,
    pub adoption_ref: String,
    pub expected_head: String,
    pub operations: Vec<String>,
    pub deadline: u64,
}

/// Private fields, no Deserialize: only a validated owner request has this type.
/// Actual disclosure/history and repository access need trusted adapter resolution.
///
/// ```compile_fail
/// let _: mikaki_auth::work::WorkRequest = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Serialize)]
pub struct WorkRequest {
    pub(super) input: RequestInput,
    pub(super) owner: Id,
    pub(super) owner_epoch: u64,
    pub(super) policy_revision: u64,
    pub(super) digest: Digest,
}

impl RequestInput {
    pub fn validate(
        self,
        session: &OwnerSession,
        environment: &Environment<'_>,
    ) -> Result<WorkRequest, Denied> {
        session.check(environment)?;
        self.validate_shape()?;
        deadline(environment.now, self.deadline, MAX_WORK_SECONDS)?;
        Ok(self.bind(
            session.id.clone(),
            session.epoch,
            environment.policy_revision,
        ))
    }

    fn validate_shape(&self) -> Result<(), Denied> {
        if self.profile != PROFILE || self.operations != [SUBMIT] {
            return Err(Denied::UnsupportedAction);
        }
        stored_number(self.revision, false)?;
        if !text(&self.goal, 4096) || !text(&self.acceptance, 8192) {
            return Err(Denied::InvalidInput);
        }
        for id in [
            &self.request_id,
            &self.code_repository,
            &self.recipient,
            &self.workload,
            &self.task_repository,
            &self.adoption_repository,
        ] {
            Id::parse(id)?;
        }
        if self.task_repository == self.code_repository
            || self.task_repository == self.adoption_repository
        {
            return Err(Denied::BindingMismatch);
        }
        git_oid(&self.base_commit)?;
        git_oid(&self.expected_head)?;
        if self.base_commit.len() != self.expected_head.len() {
            return Err(Denied::InvalidInput);
        }
        branch_ref(&self.adoption_ref)?;
        Digest::parse_hex(&self.disclosure_digest)?;
        stored_number(self.deadline, false)?;
        Ok(())
    }

    fn bind(self, owner: Id, owner_epoch: u64, policy_revision: u64) -> WorkRequest {
        let mut hash = Hash::new("mikaki.work-request.v1");
        hash.text(&self.profile);
        hash.text(&owner.0);
        hash.number(owner_epoch);
        hash.number(policy_revision);
        hash.text(&self.request_id);
        hash.number(self.revision);
        for field in [
            &self.goal,
            &self.acceptance,
            &self.code_repository,
            &self.base_commit,
            &self.disclosure_digest,
            &self.recipient,
            &self.workload,
            &self.task_repository,
            &self.adoption_repository,
            &self.adoption_ref,
            &self.expected_head,
        ] {
            hash.text(field);
        }
        hash.number(self.operations.len() as u64);
        for operation in &self.operations {
            hash.text(operation);
        }
        hash.number(self.deadline);
        WorkRequest {
            input: self,
            owner,
            owner_epoch,
            policy_revision,
            digest: hash.finish(),
        }
    }
}

impl WorkRequest {
    pub fn digest(&self) -> Digest {
        self.digest
    }
    pub fn request_id(&self) -> &str {
        &self.input.request_id
    }
    pub fn revision(&self) -> u64 {
        self.input.revision
    }
    pub fn expires_at(&self) -> u64 {
        self.input.deadline
    }

    pub(super) fn check(&self, environment: &Environment<'_>) -> Result<(), Denied> {
        environment.check_owner(&self.owner, self.owner_epoch)?;
        if self.policy_revision != environment.policy_revision {
            return Err(Denied::StalePolicy);
        }
        if environment.now >= self.input.deadline {
            return Err(Denied::Expired);
        }
        Ok(())
    }
}

fn text(value: &str, limit: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= limit
        && !value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
}

pub(super) fn branch_ref(value: &str) -> Result<(), Denied> {
    if !value.starts_with("refs/heads/")
        || value.len() > 256
        || value.contains("..")
        || value.contains("@{")
        || value
            .bytes()
            .any(|b| b <= b' ' || b == 127 || b"~^:?*[\\".contains(&b))
        || value.split('/').any(|part| {
            part.is_empty()
                || part.starts_with('.')
                || part.ends_with('.')
                || part.ends_with(".lock")
        })
    {
        return Err(Denied::InvalidInput);
    }
    Ok(())
}

/// Resolved task-only resource mapping. A task token can never authorize an upstream.
#[derive(Debug)]
pub struct TaskRepository {
    pub(super) owner: Id,
    pub(super) id: Id,
    pub(super) revision: u64,
    pub(super) disclosure: Digest,
    pub(super) available: bool,
    pub(super) prepared_disclosure: Option<ResolvedDisclosure>,
}

impl TaskRepository {
    /// Adapter must verify task role, readable code/history and approved recipient.
    /// The digest refers to that exact server-resolved disclosure manifest.
    pub fn from_authority(
        owner: &str,
        id: &str,
        revision: u64,
        disclosure: Digest,
    ) -> Result<Self, Denied> {
        stored_number(revision, false)?;
        Ok(Self {
            owner: Id::parse(owner)?,
            id: Id::parse(id)?,
            revision,
            disclosure,
            available: true,
            prepared_disclosure: None,
        })
    }

    pub(super) fn check(&self, request: &WorkRequest) -> Result<(), Denied> {
        self.check_request(request)
    }

    /// A retained legacy row remains usable for history, never new authority.
    pub fn retain_only(mut self) -> Self {
        self.available = false;
        self
    }

    pub fn check_request(&self, request: &WorkRequest) -> Result<(), Denied> {
        if !self.available {
            return Err(Denied::StaleAuthority);
        }
        if self.owner != request.owner
            || self.id.0 != request.input.task_repository
            || self.disclosure != Digest::parse_hex(&request.input.disclosure_digest)?
        {
            return Err(Denied::BindingMismatch);
        }
        if let Some(disclosure) = &self.prepared_disclosure {
            disclosure.check_request_binding(request)?;
        }
        Ok(())
    }
}

/// Current independently resolved upstream write authority and exact ref head.
#[derive(Debug)]
pub struct CodeTarget {
    pub(super) owner: Id,
    pub(super) repository: Id,
    pub(super) reference: String,
    pub(super) head: String,
    pub(super) revision: u64,
    pub(super) writable: bool,
}

impl CodeTarget {
    pub fn from_authority(
        owner: &str,
        repository: &str,
        reference: &str,
        head: &str,
        revision: u64,
        writable: bool,
    ) -> Result<Self, Denied> {
        stored_number(revision, false)?;
        branch_ref(reference)?;
        Ok(Self {
            owner: Id::parse(owner)?,
            repository: Id::parse(repository)?,
            reference: reference.into(),
            head: git_oid(head)?,
            revision,
            writable,
        })
    }
}
