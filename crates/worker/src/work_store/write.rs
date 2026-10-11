use super::*;

impl WorkStore {
    /// Same identity/body is an immutable retry. A conflicting payload is never
    /// overwritten. Recover only by primary read; no mutation is blindly resent.
    pub(super) async fn put(
        &self,
        lookup: &str,
        key: &str,
        body: &str,
        mutations: Vec<D1PreparedStatement>,
        audit: Audit<'_>,
    ) -> Result<()> {
        // An immutable row in a restored DB is historical evidence, not a
        // successful current creation/approval retry. Check the independent
        // authority even when no new D1 batch is needed.
        self.require_current_authority().await?;
        let existing = self
            .statement(lookup, &[text(key)])?
            .first::<ImmutableRow>(None)
            .await?;
        if let Some(existing) = existing {
            return if existing.body == body {
                Ok(())
            } else {
                Err(Denied::Conflict.into())
            };
        }
        match self.atomic(mutations, audit, vec![]).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let existing = self
                    .statement(lookup, &[text(key)])?
                    .first::<ImmutableRow>(None)
                    .await?;
                match existing {
                    Some(existing) if existing.body == body => {
                        self.require_current_authority().await?;
                        Ok(())
                    }
                    Some(_) => Err(Denied::Conflict.into()),
                    None => Err(error),
                }
            }
        }
    }

    /// Weak resource facts exist only in the local qualification build. Product
    /// callers must bind a verified disclosure through save_resolved_request.
    #[cfg(feature = "work-qualification")]
    pub async fn save_request(
        &self,
        session_hash: &str,
        request: &WorkRequest,
    ) -> Result<WorkRequest> {
        self.save_request_with_binding(session_hash, request, None, None)
            .await
    }

    pub(super) async fn save_request_with_binding(
        &self,
        session_hash: &str,
        request: &WorkRequest,
        disclosure: Option<&ResolvedDisclosure>,
        preparation_id: Option<&str>,
    ) -> Result<WorkRequest> {
        let owner = self.owner(session_hash).await?;
        let validated = request
            .input()
            .clone()
            .validate(owner.session(), &owner.environment())?;
        if validated.digest() != request.digest() {
            return Err(Denied::ReviewMismatch.into());
        }
        if let Some(disclosure) = disclosure {
            disclosure.check_request(request, &owner.environment())?;
        }
        let body = request.authority_record()?;
        let id = request.digest().to_hex();
        let mut mutations = vec![
            self.statement(
                include_str!("../../sql/work/save-request.sql"),
                &[text(&body), text(&owner.projection), text(session_hash)],
            )?,
            self.statement(include_str!("../../sql/work/save-head.sql"), &[text(&id)])?,
        ];
        if let Some(disclosure) = disclosure {
            mutations.push(self.statement(
                include_str!("../../sql/work/bind-disclosure.sql"),
                &[
                    text(&id),
                    text(&disclosure.digest().to_hex()),
                    text(owner.owner_id()),
                    text(session_hash),
                ],
            )?);
        }
        if let Some(preparation_id) = preparation_id {
            mutations.push(self.statement(
                include_str!("../../sql/work/bind-preparation.sql"),
                &[text(&id), text(preparation_id)],
            )?);
        }
        self.put(
            "SELECT body FROM work_request WHERE digest=?1",
            &id,
            &body,
            mutations,
            owner_audit(
                owner.owner_id(),
                "request",
                &id,
                "request.save",
                request.revision(),
            ),
        )
        .await?;
        // An immutable retry may encounter a legacy unbound row. It must never
        // silently promote that row to a qualified resource association.
        if let Some(disclosure) = disclosure {
            let bound: Option<String> = self.statement(
                "SELECT disclosure_digest FROM work_request_disclosure WHERE request_digest=?1 AND owner_id=?2",
                &[text(&id), text(owner.owner_id())],
            )?.first(Some("disclosure_digest")).await?;
            if bound.as_deref() != Some(disclosure.digest().to_hex().as_str()) {
                return Err(Denied::BindingMismatch.into());
            }
        }
        if let Some(preparation_id) = preparation_id {
            let bound: Option<String> = self.statement(
                "SELECT p.preparation_id FROM work_request_preparation r JOIN work_prepared_task p ON p.repository_id=r.repository_id WHERE r.request_digest=?1",
                &[text(&id)],
            )?.first(Some("preparation_id")).await?;
            if bound.as_deref() != Some(preparation_id) {
                return Err(Denied::BindingMismatch.into());
            }
        }
        self.request(request.digest()).await
    }

    pub async fn save_grant(&self, session_hash: &str, grant: &Grant) -> Result<Grant> {
        let owner = self.owner(session_hash).await?;
        let request = self.request(grant.request_digest()).await?;
        let task = self.task(&request.input().task_repository).await?;
        let validated = Grant::approve(
            grant.id(),
            &request,
            request.digest(),
            owner.session(),
            &task,
            &owner.environment(),
        )?;
        let body = grant.authority_record()?;
        if validated.authority_record()? != body || grant.revision() != 1 || grant.is_revoked() {
            return Err(Denied::BindingMismatch.into());
        }
        let disclosure = self.registered_request_disclosure(&request).await?;
        self.require_request_preparation(&request).await?;
        self.put(
            "SELECT body FROM work_grant WHERE grant_id=?1",
            grant.id(),
            &body,
            vec![self.statement(
                include_str!("../../sql/work/save-grant.sql"),
                &[
                    text(&body),
                    text(session_hash),
                    nullable(disclosure.as_deref()),
                ],
            )?],
            owner_audit(owner.owner_id(), "grant", grant.id(), "grant.approve", 1),
        )
        .await?;
        self.grant(grant.id()).await
    }

    /// Actor facts originate only from the trusted managed verifier, not a body
    /// decoded by an HTTP handler or the existing Agent public-client AS.
    pub async fn save_run(&self, actor: &ManagedActor, run: &Run) -> Result<Run> {
        let grant = self.grant(run.grant_id()).await?;
        let request = self.request(grant.request_digest()).await?;
        let task = self.task(&request.input().task_repository).await?;
        let account = self.account(request.owner_id()).await?;
        let validated = Run::register(
            actor,
            &grant,
            &request,
            &task,
            run.expires_at(),
            &account.environment(),
        )?;
        let body = run.authority_record()?;
        if validated.authority_record()? != body || run.revision() != 1 || run.is_revoked() {
            return Err(Denied::BindingMismatch.into());
        }
        let disclosure = self.registered_request_disclosure(&request).await?;
        self.require_request_preparation(&request).await?;
        self.put(
            "SELECT body FROM work_run WHERE run_id=?1",
            run.id(),
            &body,
            vec![self.statement(
                include_str!("../../sql/work/save-run.sql"),
                &[
                    text(&body),
                    number(actor.expires_at())?,
                    nullable(disclosure.as_deref()),
                ],
            )?],
            Audit {
                actor: run.id(),
                ..owner_audit(request.owner_id(), "run", run.id(), "run.register", 1)
            },
        )
        .await?;
        self.run(run.id()).await
    }

    pub async fn save_candidate(
        &self,
        actor: &ManagedActor,
        candidate: &Candidate,
    ) -> Result<Candidate> {
        let context = self.producer(actor.run_id()).await?;
        self.require_request_preparation(&context.request).await?;
        let account = self.account(context.request.owner_id()).await?;
        let environment = account.environment();
        let fresh = || {
            context.run.authorize_submission(
                SUBMIT,
                &context.grant,
                &context.request,
                actor,
                &context.task,
                &environment,
            )
        };
        let validated = fresh()?
            .prepare_candidate(CandidateInput {
                commit: candidate.commit().into(),
                tree: candidate.tree().into(),
                evidence: candidate.evidence_digest(),
            })?
            .confirm(fresh()?)?;
        if validated.authority_record()? != candidate.authority_record()? {
            return Err(Denied::BindingMismatch.into());
        }
        let body = candidate.authority_record()?;
        let id = candidate.digest().to_hex();
        let result = self
            .put(
                "SELECT body FROM work_candidate WHERE digest=?1",
                &id,
                &body,
                vec![self.statement(
                    include_str!("../../sql/work/save-candidate.sql"),
                    &[text(&body)],
                )?],
                Audit {
                    actor: context.run.id(),
                    ..owner_audit(candidate.owner_id(), "candidate", &id, SUBMIT, 1)
                },
            )
            .await;
        // A renewed proof may change only the authentication-expiry snapshot; the
        // same verified review digest still denotes the already committed result.
        match result {
            Ok(()) | Err(StoreError::Denied(Denied::Conflict)) => {
                self.candidate(candidate.digest()).await
            }
            Err(error) => Err(error),
        }
    }

    pub async fn save_approval(
        &self,
        session_hash: &str,
        approval: &CodeApproval,
    ) -> Result<CodeApproval> {
        let context = self.candidate_context(approval.candidate_digest()).await?;
        let owner = self.owner(session_hash).await?;
        let environment = owner.environment();
        let validated = CodeApproval::approve(
            approval.id(),
            context.candidate.digest(),
            owner.session(),
            &context.adoption(&environment),
            approval.expires_at(),
        )?;
        let body = approval.authority_record()?;
        if validated.authority_record()? != body
            || approval.revision() != 1
            || approval.is_revoked()
        {
            return Err(Denied::BindingMismatch.into());
        }
        self.put(
            "SELECT body FROM work_code_approval WHERE approval_id=?1",
            approval.id(),
            &body,
            vec![self.statement(
                include_str!("../../sql/work/save-approval.sql"),
                &[text(&body), text(&owner.projection), text(session_hash)],
            )?],
            owner_audit(owner.owner_id(), "approval", approval.id(), ADOPT_CODE, 1),
        )
        .await?;
        self.approval(approval.id()).await
    }

    async fn revoke(
        &self,
        session_hash: &str,
        id: &str,
        kind: &str,
        sql: &str,
        lookup: &str,
    ) -> Result<()> {
        let owner = self.owner(session_hash).await?;
        let row: RevocableRow = self
            .first(lookup, &[text(id), text(owner.owner_id())])
            .await?;
        if row.revoked == 1 {
            return Ok(());
        }
        match self
            .atomic(
                vec![self.statement(sql, &[text(id), text(session_hash)])?],
                owner_audit(owner.owner_id(), kind, id, "authority.revoke", 2),
                vec![],
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(StoreError::Denied(Denied::StaleAuthority)) => {
                let row: RevocableRow = self
                    .first(lookup, &[text(id), text(owner.owner_id())])
                    .await?;
                if row.revoked == 1 {
                    Ok(())
                } else {
                    Err(Denied::StaleAuthority.into())
                }
            }
            Err(error) => Err(error),
        }
    }
    pub async fn revoke_grant(&self, session_hash: &str, id: &str) -> Result<()> {
        self.revoke(session_hash,id,"grant",include_str!("../../sql/work/revoke-grant.sql"),
            "SELECT g.body,g.revision,g.revoked FROM work_grant g JOIN work_request w ON w.digest=g.request_digest WHERE g.grant_id=?1 AND w.owner_id=?2").await
    }
    pub async fn revoke_run(&self, session_hash: &str, id: &str) -> Result<()> {
        self.revoke(session_hash,id,"run",include_str!("../../sql/work/revoke-run.sql"),
            "SELECT r.body,r.revision,r.revoked FROM work_run r JOIN work_request w ON w.digest=r.request_digest WHERE r.run_id=?1 AND w.owner_id=?2").await
    }
    pub async fn revoke_approval(&self, session_hash: &str, id: &str) -> Result<()> {
        self.revoke(session_hash,id,"approval",include_str!("../../sql/work/revoke-approval.sql"),
            "SELECT body,revision,revoked FROM work_code_approval WHERE approval_id=?1 AND owner_id=?2").await
    }
}
