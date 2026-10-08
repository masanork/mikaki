use super::*;

pub struct OwnerContext {
    owner: OwnerState,
    session: OwnerSession,
    id: String,
    generation: u64,
    pub(super) projection: String,
}
impl OwnerContext {
    pub fn session(&self) -> &OwnerSession {
        &self.session
    }
    pub fn owner_id(&self) -> &str {
        &self.id
    }
    pub fn environment(&self) -> Environment<'_> {
        Environment {
            owner: &self.owner,
            policy_revision: self.generation,
            now: now(),
        }
    }
}

#[derive(Deserialize)]
struct OwnerRow {
    account_id: String,
    epoch: u64,
    expires_at: u64,
    generation: u64,
    projection_revision: String,
}
#[derive(Deserialize)]
struct AccountRow {
    account_id: String,
    epoch: u64,
    active: u8,
    generation: u64,
}
pub(super) struct AccountContext {
    pub(super) owner: OwnerState,
    pub(super) id: String,
    pub(super) generation: u64,
}
impl AccountContext {
    pub(super) fn environment(&self) -> Environment<'_> {
        Environment {
            owner: &self.owner,
            policy_revision: self.generation,
            now: now(),
        }
    }
}

#[derive(Deserialize)]
struct TaskRow {
    owner_id: String,
    repository_id: String,
    revision: u64,
    disclosure_digest: String,
}
#[derive(Deserialize)]
struct TargetRow {
    owner_id: String,
    repository_id: String,
    reference: String,
    head: String,
    revision: u64,
    writable: u8,
}

pub struct ProducerContext {
    pub request: WorkRequest,
    pub grant: Grant,
    pub run: Run,
    pub task: TaskRepository,
}
pub(super) struct CandidateContext {
    pub(super) producer: ProducerContext,
    pub(super) candidate: Candidate,
    pub(super) target: CodeTarget,
    pub(super) account: AccountContext,
}
impl CandidateContext {
    pub(super) fn adoption<'a>(&'a self, environment: &'a Environment<'a>) -> AdoptionContext<'a> {
        AdoptionContext {
            candidate: &self.candidate,
            grant: &self.producer.grant,
            run: &self.producer.run,
            target: &self.target,
            environment,
        }
    }
}

impl WorkStore {
    /// SSO hash is computed by the OP owner handler, never supplied as a workload
    /// identity. SQL repeats this credential/session/account check on owner writes.
    pub async fn owner(&self, session_hash: &str) -> Result<OwnerContext> {
        let row: OwnerRow = self.first("SELECT ss.account_id,ss.epoch,ss.expires_at,p.generation,p.projection_revision \
          FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
          JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1 \
          JOIN account_security a ON a.account_id=ss.account_id AND a.epoch=ss.epoch AND a.active=1 \
          JOIN runtime_policy_active p ON p.id=1 WHERE sx.secret_hash=?1 AND ss.revoked=0 AND ss.expires_at>unixepoch()", &[text(session_hash)]).await?;
        Ok(OwnerContext {
            owner: OwnerState::from_authority(&row.account_id, row.epoch, true)?,
            session: OwnerSession::from_verified_session(
                &row.account_id,
                row.epoch,
                row.expires_at,
            )?,
            id: row.account_id,
            generation: row.generation,
            projection: row.projection_revision,
        })
    }

    pub(super) async fn account(&self, id: &str) -> Result<AccountContext> {
        let row: AccountRow = self.first("SELECT a.account_id,a.epoch,a.active,p.generation,p.projection_revision FROM account_security a \
          JOIN runtime_policy_active p ON p.id=1 WHERE a.account_id=?1", &[text(id)]).await?;
        Ok(AccountContext {
            owner: OwnerState::from_authority(&row.account_id, row.epoch, row.active == 1)?,
            id: row.account_id,
            generation: row.generation,
        })
    }

    pub async fn request(&self, digest: Digest) -> Result<WorkRequest> {
        let row: ImmutableRow = self
            .first(
                "SELECT body FROM work_request WHERE digest=?1",
                &[text(&digest.to_hex())],
            )
            .await?;
        let request = WorkRequest::restore_authority_record(&row.body)?;
        if request.digest() != digest {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(request)
    }
    pub async fn grant(&self, id: &str) -> Result<Grant> {
        let row: RevocableRow = self
            .first(
                "SELECT body,revision,revoked FROM work_grant WHERE grant_id=?1",
                &[text(id)],
            )
            .await?;
        let grant = Grant::restore_authority_record(&row.body, row.revision, row.revoked == 1)?;
        if grant.id() != id {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(grant)
    }
    pub async fn run(&self, id: &str) -> Result<Run> {
        let row: RevocableRow = self
            .first(
                "SELECT body,revision,revoked FROM work_run WHERE run_id=?1",
                &[text(id)],
            )
            .await?;
        let run = Run::restore_authority_record(&row.body, row.revision, row.revoked == 1)?;
        if run.id() != id {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(run)
    }
    pub async fn task(&self, id: &str) -> Result<TaskRepository> {
        let row: TaskRow = self.first("SELECT owner_id,repository_id,revision,disclosure_digest FROM work_task_repository WHERE repository_id=?1", &[text(id)]).await?;
        #[derive(Deserialize)]
        struct PreparedRow {
            body: String,
            state: PreparationState,
            evidence: String,
        }
        let prepared: Option<PreparedRow> = self.statement(
            "SELECT p.body,p.state,p.evidence FROM work_prepared_task t JOIN work_preparation p ON p.operation_id=t.preparation_id WHERE t.repository_id=?1",
            &[text(id)],
        )?.first(None).await?;
        if let Some(prepared) = prepared {
            let p = Preparation::restore_authority_record(&prepared.body, prepared.state)?;
            let evidence = VerifiedPreparation::restore_authority_record(&prepared.evidence)?;
            let d = self.disclosure(p.disclosure_digest()).await?;
            let current = self.confirm_disclosure_sources(p.disclosure_digest()).await;
            let sources_current = match current {
                Ok(()) => true,
                Err(StoreError::Denied(Denied::StaleAuthority)) => false,
                Err(error) => return Err(error),
            };
            let task = p.task_authority(&evidence, d, row.revision, sources_current)?;
            // Table guards freeze metadata; Native repeats the stored association.
            if p.owner_id() != row.owner_id
                || p.disclosure_digest().to_hex() != row.disclosure_digest
                || p.task_repository() != row.repository_id
            {
                return Err(Denied::BindingMismatch.into());
            }
            return Ok(task);
        }
        let task = TaskRepository::from_authority(
            &row.owner_id,
            &row.repository_id,
            row.revision,
            Digest::parse_hex(&row.disclosure_digest)?,
        )?;
        #[cfg(feature = "work-qualification")]
        return Ok(task); // explicitly weak legacy local fixtures only
        #[cfg(not(feature = "work-qualification"))]
        Ok(task.retain_only())
    }
    pub async fn target(&self, repository: &str, reference: &str) -> Result<CodeTarget> {
        let row: TargetRow = self.first("SELECT owner_id,repository_id,reference,head,revision,writable FROM work_code_target WHERE repository_id=?1 AND reference=?2", &[text(repository),text(reference)]).await?;
        Ok(CodeTarget::from_authority(
            &row.owner_id,
            &row.repository_id,
            &row.reference,
            &row.head,
            row.revision,
            row.writable == 1,
        )?)
    }
    pub async fn producer(&self, run_id: &str) -> Result<ProducerContext> {
        let run = self.run(run_id).await?;
        let grant = self.grant(run.grant_id()).await?;
        let request = self.request(grant.request_digest()).await?;
        let task = self.task(&request.input().task_repository).await?;
        Ok(ProducerContext {
            request,
            grant,
            run,
            task,
        })
    }
    pub async fn candidate(&self, digest: Digest) -> Result<Candidate> {
        let row: ImmutableRow = self
            .first(
                "SELECT body FROM work_candidate WHERE digest=?1",
                &[text(&digest.to_hex())],
            )
            .await?;
        #[derive(Deserialize)]
        struct Reference {
            run_id: String,
        }
        let reference: Reference = self
            .first(
                "SELECT run_id FROM work_candidate WHERE digest=?1",
                &[text(&digest.to_hex())],
            )
            .await?;
        let producer = self.producer(&reference.run_id).await?;
        let candidate = Candidate::restore_authority_record(
            &row.body,
            &producer.request,
            &producer.grant,
            &producer.run,
        )?;
        if candidate.digest() != digest {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(candidate)
    }
    pub async fn approval(&self, id: &str) -> Result<CodeApproval> {
        let row: RevocableRow = self
            .first(
                "SELECT body,revision,revoked FROM work_code_approval WHERE approval_id=?1",
                &[text(id)],
            )
            .await?;
        let approval =
            CodeApproval::restore_authority_record(&row.body, row.revision, row.revoked == 1)?;
        if approval.id() != id {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(approval)
    }
    pub(super) async fn candidate_context(&self, digest: Digest) -> Result<CandidateContext> {
        let candidate = self.candidate(digest).await?;
        let producer = self.producer(candidate.run_id()).await?;
        let target = self
            .target(
                &producer.request.input().adoption_repository,
                &producer.request.input().adoption_ref,
            )
            .await?;
        let account = self.account(candidate.owner_id()).await?;
        Ok(CandidateContext {
            producer,
            candidate,
            target,
            account,
        })
    }
}
