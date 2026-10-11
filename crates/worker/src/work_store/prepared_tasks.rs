use super::*;

impl WorkStore {
    /// Trusted OP capability, after remote verification. No browser upload or
    /// token release. Never retrofit a pre-existing weak task row into authority.
    pub async fn materialize_prepared_task(&self, id: &str) -> Result<TaskRepository> {
        let p = self.preparation(id).await?;
        if p.state() != PreparationState::Verified {
            return Err(Denied::InvalidTransition.into());
        }
        self.confirm_disclosure_sources(p.disclosure_digest())
            .await?;
        self.task_from_preparation(&p, 1, true).await?;
        let existing: Option<String> = self
            .statement(
                "SELECT repository_id FROM work_prepared_task WHERE preparation_id=?1",
                &[text(id)],
            )?
            .first(Some("repository_id"))
            .await?;
        if let Some(repository) = existing {
            return self.task(&repository).await;
        }
        if self
            .statement(
                "SELECT repository_id FROM work_task_repository WHERE repository_id=?1",
                &[text(p.task_repository())],
            )?
            .first::<String>(Some("repository_id"))
            .await?
            .is_some()
        {
            // Another isolate may have committed both rows since our first read.
            let bound: Option<String> = self
                .statement(
                    "SELECT repository_id FROM work_prepared_task WHERE preparation_id=?1",
                    &[text(id)],
                )?
                .first(Some("repository_id"))
                .await?;
            if let Some(repository) = bound {
                return self.task(&repository).await;
            }
            return Err(Denied::Conflict.into());
        }
        let result = self
            .atomic(
                vec![
                    self.statement(
                        include_str!("../../sql/work/materialize-task.sql"),
                        &[text(id)],
                    )?,
                    self.statement(
                        include_str!("../../sql/work/materialize-prepared-task.sql"),
                        &[text(id)],
                    )?,
                ],
                Audit {
                    actor: "op-work-preparer",
                    ..owner_audit(
                        p.owner_id(),
                        "preparation",
                        id,
                        "preparation.materialize",
                        1,
                    )
                },
                vec![],
            )
            .await;
        let existing: Option<String> = self
            .statement(
                "SELECT repository_id FROM work_prepared_task WHERE preparation_id=?1",
                &[text(id)],
            )?
            .first(Some("repository_id"))
            .await?;
        if let Some(repository) = existing {
            return self.task(&repository).await;
        }
        result?;
        Err(Denied::StaleAuthority.into())
    }

    pub(super) async fn prepared_request_id(&self, request: &WorkRequest) -> Result<String> {
        let id: String = self
            .first(
                "SELECT p.preparation_id AS id FROM work_prepared_task p WHERE p.repository_id=?1",
                &[text(&request.input().task_repository)],
            )
            .await
            .map(|row: PreparedId| row.id)?;
        self.task(&request.input().task_repository)
            .await?
            .check_request(request)?;
        Ok(id)
    }

    /// Repeat the immutable association before an exact put retry too. An old
    /// matching grant/run body must not bypass a missing preparation binding.
    pub(super) async fn require_request_preparation(&self, request: &WorkRequest) -> Result<()> {
        #[derive(Deserialize)]
        struct BindingRow {
            prepared: u64,
            bound: u64,
        }
        let row: BindingRow = self.first(
            "SELECT EXISTS(SELECT 1 FROM work_prepared_task WHERE repository_id=?1) AS prepared, \
             EXISTS(SELECT 1 FROM work_request_preparation WHERE request_digest=?2 AND repository_id=?1) AS bound",
            &[text(&request.input().task_repository), text(&request.digest().to_hex())],
        ).await?;
        if row.bound == 1 && row.prepared == 1 {
            return Ok(());
        }
        #[cfg(feature = "work-qualification")]
        if row.prepared == 0 {
            return Ok(());
        } // weak pre-0052 fixture only
        Err(Denied::BindingMismatch.into())
    }
}

#[derive(Deserialize)]
struct PreparedId {
    id: String,
}
