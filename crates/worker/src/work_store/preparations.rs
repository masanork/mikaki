use super::*;

/// Only Started permits the first external attempt. Existing (including an
/// unknown/lost response) requires inspection of the same fixed destinations.
pub enum PreparationDispatch {
    Started(Preparation),
    Existing(Preparation),
}
#[derive(Deserialize)]
struct PreparationRow {
    body: String,
    state: PreparationState,
    revision: u64,
    evidence: Option<String>,
    cleanup_receipt: Option<String>,
}
const LOOKUP: &str = "SELECT body,state,revision,evidence,cleanup_receipt FROM work_preparation WHERE operation_id=?1";
impl PreparationRow {
    fn restore(&self) -> Result<Preparation> {
        let p = Preparation::restore_authority_record(&self.body, self.state)?;
        if let Some(body) = &self.evidence {
            let e = VerifiedPreparation::restore_authority_record(body)?;
            let mut verified =
                Preparation::restore_authority_record(&self.body, PreparationState::Dispatched)?;
            verified.verify(&e)?;
        }
        if let Some(receipt) = &self.cleanup_receipt {
            Digest::parse_hex(receipt)?;
        }
        Ok(p)
    }
}
impl WorkStore {
    pub(super) async fn task_from_preparation(
        &self,
        p: &Preparation,
        revision: u64,
        sources_current: bool,
    ) -> Result<TaskRepository> {
        let row: PreparationRow = self.first(LOOKUP, &[text(p.id())]).await?;
        let body = row.evidence.ok_or(Denied::BindingMismatch)?;
        let evidence = VerifiedPreparation::restore_authority_record(&body)?;
        let disclosure = self.disclosure(p.disclosure_digest()).await?;
        Ok(p.task_authority(&evidence, disclosure, revision, sources_current)?)
    }
    pub async fn preparation(&self, id: &str) -> Result<Preparation> {
        let row: PreparationRow = self.first(LOOKUP, &[text(id)]).await?;
        let p = row.restore()?;
        if p.id() != id {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(p)
    }
    /// Trusted destination mapping only; no HTTP creation route. The same
    /// selection resumes the persisted ID even if a different isolate won.
    pub async fn reserve_preparation(
        &self,
        session_hash: &str,
        disclosure: Digest,
        task_repository: &str,
        task_namespace: &str,
        snapshot_namespace: &str,
    ) -> Result<Preparation> {
        let owner = self.owner(session_hash).await?;
        let d = self.disclosure(disclosure).await?;
        if d.owner_id() != owner.owner_id() {
            return Err(Denied::OwnerMismatch.into());
        }
        let lookup = "SELECT body,state,revision,evidence,cleanup_receipt FROM work_preparation WHERE disclosure_digest=?1";
        let existing = self
            .statement(lookup, &[text(&disclosure.to_hex())])?
            .first::<PreparationRow>(None)
            .await?;
        let id = if let Some(row) = &existing {
            row.restore()?.id().to_owned()
        } else {
            opaque()?
        };
        let planned = Preparation::from_registered_disclosure(
            &d,
            &id,
            task_repository,
            task_namespace,
            snapshot_namespace,
        )?;
        let body = planned.authority_record()?;
        if let Some(row) = existing {
            if row.body != body {
                return Err(Denied::Conflict.into());
            }
            return row.restore(); // resume evidence only; dispatch repeats current guards
        }
        let result = self
            .atomic(
                vec![
                    self.statement(
                        include_str!("../../sql/work/reserve-preparation-window.sql"),
                        &[text(owner.owner_id())],
                    )?,
                    self.statement(
                        include_str!("../../sql/work/save-preparation.sql"),
                        &[text(&body), text(session_hash)],
                    )?,
                ],
                owner_audit(
                    owner.owner_id(),
                    "preparation",
                    &id,
                    "preparation.reserve",
                    1,
                ),
                vec![],
            )
            .await;
        let row: Option<PreparationRow> = self
            .statement(lookup, &[text(&disclosure.to_hex())])?
            .first(None)
            .await?;
        if let Some(row) = row {
            let current = row.restore()?;
            let expected = Preparation::from_registered_disclosure(
                &d,
                current.id(),
                task_repository,
                task_namespace,
                snapshot_namespace,
            )?;
            if row.body != expected.authority_record()? {
                return Err(Denied::Conflict.into());
            }
            return Ok(current);
        }
        if self
            .statement(
                "SELECT operation_id FROM work_preparation WHERE task_repository=?1",
                &[text(task_repository)],
            )?
            .first::<String>(Some("operation_id"))
            .await?
            .is_some()
        {
            return Err(Denied::Conflict.into());
        }
        result?;
        Err(Denied::StaleAuthority.into())
    }
    pub async fn dispatch_preparation(&self, id: &str) -> Result<PreparationDispatch> {
        let row: PreparationRow = self.first(LOOKUP, &[text(id)]).await?;
        let mut p = row.restore()?;
        if p.state() != PreparationState::Reserved {
            return Ok(PreparationDispatch::Existing(p));
        }
        self.require_copy_consent(id, None).await?;
        let account = self.account(p.owner_id()).await?;
        p.dispatch(&account.environment())?;
        let result = self
            .transition_preparation(&row, &p, None, None, "preparation.dispatch")
            .await;
        match result {
            Ok(()) => Ok(PreparationDispatch::Started(p)),
            Err(error) => {
                let current = self.preparation(id).await?;
                if current.state() != PreparationState::Reserved {
                    Ok(PreparationDispatch::Existing(current))
                } else {
                    Err(error)
                }
            }
        }
    }
    /// Called by a trusted readback/credential adapter, never an owner DTO. D1
    /// repeats all source/epoch/policy guards after the adapter's remote I/O.
    /// Verified is unreleased preparation evidence, not a grant/run or token.
    pub async fn verify_preparation(
        &self,
        id: &str,
        evidence: &VerifiedPreparation,
    ) -> Result<Preparation> {
        let row: PreparationRow = self.first(LOOKUP, &[text(id)]).await?;
        let mut p = row.restore()?;
        p.verify(evidence)?;
        // Historical migration fixtures alone may precede custody installation.
        // The product never treats a missing journal schema as an exemption.
        #[cfg(feature = "work-qualification")]
        let journal_installed = self
            .statement("SELECT name FROM sqlite_master WHERE type='table' AND name='work_credential_attempt'", &[])?
            .first::<String>(Some("name"))
            .await?
            .is_some();
        #[cfg(not(feature = "work-qualification"))]
        let journal_installed = true;
        if journal_installed && self
            .statement(
                "SELECT attempt_id FROM work_credential_attempt WHERE preparation_id=?1 LIMIT 1",
                &[text(id)],
            )?
            .first::<String>(Some("attempt_id"))
            .await?
            .is_some()
            && self.credential_custody_receipt(id).await? != evidence.credential_receipt()
        {
            return Err(Denied::BindingMismatch.into());
        }
        let body = evidence.authority_record()?;
        if row.state == PreparationState::Verified {
            if row.evidence.as_deref() == Some(&body) {
                return Ok(p);
            }
            return Err(Denied::Conflict.into());
        }
        let result = self
            .transition_preparation(&row, &p, Some(&body), None, "preparation.verify")
            .await;
        self.recover_preparation_transition(id, p.state(), Some(&body), None, result)
            .await
    }
    /// OP executor safety capability: source/owner loss or exhausted creation
    /// policy must not prevent cancellation, cleanup obligations or outcomes.
    pub async fn require_preparation_cleanup(&self, id: &str) -> Result<Preparation> {
        let row: PreparationRow = self.first(LOOKUP, &[text(id)]).await?;
        let mut p = row.restore()?;
        p.require_cleanup();
        if row.state == p.state() {
            return Ok(p);
        }
        let result = self
            .transition_preparation(
                &row,
                &p,
                row.evidence.as_deref(),
                None,
                "preparation.cleanup",
            )
            .await;
        self.recover_preparation_transition(id, p.state(), row.evidence.as_deref(), None, result)
            .await
    }
    /// Receipt is the digest of independently verified concrete cleanup. A
    /// remote error/timeout never releases capacity or removes this identity.
    pub async fn confirm_preparation_cleaned(
        &self,
        id: &str,
        receipt: Digest,
    ) -> Result<Preparation> {
        if self.preparation_has_candidates(id).await? {
            // Candidate-bearing cleanup must use actual private R2 readback.
            return Err(Denied::BindingMismatch.into());
        }
        self.commit_preparation_cleaned(id, receipt).await
    }
    pub(super) async fn commit_preparation_cleaned(
        &self,
        id: &str,
        receipt: Digest,
    ) -> Result<Preparation> {
        let row: PreparationRow = self.first(LOOKUP, &[text(id)]).await?;
        let mut p = row.restore()?;
        p.confirm_cleaned()?;
        let receipt = receipt.to_hex();
        if row.state == p.state() {
            if row.cleanup_receipt.as_deref() == Some(&receipt) {
                return Ok(p);
            }
            return Err(Denied::Conflict.into());
        }
        let result = self
            .transition_preparation(
                &row,
                &p,
                row.evidence.as_deref(),
                Some(&receipt),
                "preparation.cleaned",
            )
            .await;
        self.recover_preparation_transition(
            id,
            p.state(),
            row.evidence.as_deref(),
            Some(&receipt),
            result,
        )
        .await
    }
    async fn transition_preparation(
        &self,
        row: &PreparationRow,
        p: &Preparation,
        evidence: Option<&str>,
        receipt: Option<&str>,
        action: &str,
    ) -> Result<()> {
        self.atomic(
            vec![self.statement(
                include_str!("../../sql/work/transition-preparation.sql"),
                &[
                    text(p.id()),
                    number(row.revision)?,
                    text(&row.body),
                    text(p.state().name()),
                    nullable(evidence),
                    nullable(receipt),
                ],
            )?],
            Audit {
                before: Some(row.state.name()),
                after: Some(p.state().name()),
                receipt,
                actor: "op-work-preparer",
                ..owner_audit(
                    p.owner_id(),
                    "preparation",
                    p.id(),
                    action,
                    row.revision + 1,
                )
            },
            vec![],
        )
        .await
    }
    async fn recover_preparation_transition(
        &self,
        id: &str,
        state: PreparationState,
        evidence: Option<&str>,
        receipt: Option<&str>,
        result: Result<()>,
    ) -> Result<Preparation> {
        let row: PreparationRow = self.first(LOOKUP, &[text(id)]).await?;
        if row.state == state
            && row.evidence.as_deref() == evidence
            && row.cleanup_receipt.as_deref() == receipt
        {
            return row.restore();
        }
        result?;
        Err(Denied::Conflict.into())
    }
}
