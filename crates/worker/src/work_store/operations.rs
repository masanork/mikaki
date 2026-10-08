use super::*;

/// Only Started permits a first external call. Existing requires reconciliation
/// by the stable operation ID; even Dispatched must never be blindly resent.
pub enum DispatchResult {
    Started(ExternalOperation),
    Existing(ExternalOperation),
}

/// Trusted adapter outcomes, after authenticating the exact effect and receipt.
/// This is not an HTTP request DTO or an owner authorization decision.
pub enum Outcome<'a> {
    Unknown,
    Applied(&'a str),
    Rejected(&'a str),
}

#[derive(Deserialize)]
struct OperationRow {
    body: String,
    state: OperationState,
    revision: u64,
    receipt: Option<String>,
    approval_id: String,
    owner_id: String,
}
impl OperationRow {
    fn restore(&self, id: &str) -> Result<ExternalOperation> {
        let op = ExternalOperation::restore_authority_record(
            &self.body,
            self.state,
            self.receipt.as_deref(),
        )?;
        if op.id() != id {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(op)
    }
}
const LOOKUP: &str = "SELECT body,state,revision,receipt,approval_id,owner_id FROM work_code_operation WHERE operation_id=?1";
fn state_name(state: OperationState) -> &'static str {
    match state {
        OperationState::Prepared => "prepared",
        OperationState::Dispatched => "dispatched",
        OperationState::OutcomeUnknown => "outcome_unknown",
        OperationState::Applied => "applied",
        OperationState::Rejected => "rejected",
        OperationState::Cancelled => "cancelled",
    }
}

impl WorkStore {
    pub async fn operation(&self, id: &str) -> Result<ExternalOperation> {
        let row: OperationRow = self.first(LOOKUP, &[text(id)]).await?;
        row.restore(id)
    }

    pub async fn prepare_operation(
        &self,
        approval_id: &str,
        id: &str,
    ) -> Result<ExternalOperation> {
        if let Some(row) = self
            .statement(LOOKUP, &[text(id)])?
            .first::<OperationRow>(None)
            .await?
        {
            if row.approval_id != approval_id {
                return Err(Denied::Conflict.into());
            }
            return row.restore(id);
        }
        let approval = self.approval(approval_id).await?;
        let context = self.candidate_context(approval.candidate_digest()).await?;
        let environment = context.account.environment();
        let op = approval.prepare_operation(ADOPT_CODE, id, &context.adoption(&environment))?;
        let body = op.authority_record()?;
        let result = self
            .atomic(
                vec![self.statement(
                    include_str!("../../sql/work/prepare-operation.sql"),
                    &[text(&body)],
                )?],
                Audit {
                    after: Some("prepared"),
                    ..owner_audit(&context.account.id, "operation", id, "operation.prepare", 1)
                },
                vec![],
            )
            .await;
        if let Err(error) = result {
            if let Some(row) = self
                .statement(LOOKUP, &[text(id)])?
                .first::<OperationRow>(None)
                .await?
            {
                if row.body == body {
                    return row.restore(id);
                }
                return Err(Denied::Conflict.into());
            }
            if self
                .statement(
                    "SELECT body FROM work_code_operation WHERE approval_id=?1",
                    &[text(approval_id)],
                )?
                .first::<ImmutableRow>(None)
                .await?
                .is_some()
            {
                return Err(Denied::Conflict.into());
            }
            return Err(error);
        }
        self.operation(id).await
    }

    /// Reserve this exact target and repeat live guards atomically with the
    /// dispatch audit. A caller must act ONLY on Started, once.
    pub async fn dispatch(&self, id: &str) -> Result<DispatchResult> {
        let row: OperationRow = self.first(LOOKUP, &[text(id)]).await?;
        let mut op = row.restore(id)?;
        if op.state() != OperationState::Prepared {
            return Ok(DispatchResult::Existing(op));
        }
        let approval = self.approval(&row.approval_id).await?;
        let context = self.candidate_context(approval.candidate_digest()).await?;
        let environment = context.account.environment();
        approval.dispatch(&mut op, &context.adoption(&environment))?;
        let bindings = [text(id), number(row.revision)?, text(&row.body)];
        let result = self
            .atomic(
                vec![
                    self.statement(include_str!("../../sql/work/claim-target.sql"), &bindings)?,
                    self.statement(include_str!("../../sql/work/dispatch.sql"), &bindings)?,
                ],
                Audit {
                    before: Some("prepared"),
                    after: Some("dispatched"),
                    actor: "op-work-executor",
                    ..owner_audit(
                        &row.owner_id,
                        "operation",
                        id,
                        "operation.dispatch",
                        row.revision + 1,
                    )
                },
                vec![],
            )
            .await;
        match result {
            Ok(()) => Ok(DispatchResult::Started(op)),
            Err(error) => {
                let current = self.operation(id).await?;
                if current.state() != OperationState::Prepared {
                    Ok(DispatchResult::Existing(current))
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Authenticated executor capability: recording reality remains possible
    /// after producer/owner revocation. Outcomes cannot authorize a new effect.
    pub async fn record_outcome(
        &self,
        id: &str,
        outcome: Outcome<'_>,
    ) -> Result<ExternalOperation> {
        let row: OperationRow = self.first(LOOKUP, &[text(id)]).await?;
        let mut op = row.restore(id)?;
        match outcome {
            Outcome::Unknown => op.mark_outcome_unknown()?,
            Outcome::Applied(receipt) => op.confirm_applied(receipt)?,
            Outcome::Rejected(receipt) => op.confirm_rejected(receipt)?,
        }
        if op.state() == row.state && op.receipt() == row.receipt.as_deref() {
            return Ok(op);
        }
        let bindings = [
            text(id),
            number(row.revision)?,
            text(&row.body),
            text(state_name(op.state())),
            nullable(op.receipt()),
            text(state_name(row.state)),
        ];
        let mut tail = vec![];
        if matches!(
            op.state(),
            OperationState::Applied | OperationState::Rejected
        ) {
            // Fence a stale resolver observation before releasing the target.
            // A fresh authenticated ref read must explicitly re-enable it.
            tail.push(
                self.statement(include_str!("../../sql/work/fence-target.sql"), &[text(id)])?,
            );
            tail.push(self.statement(
                include_str!("../../sql/work/release-target.sql"),
                &[text(id)],
            )?);
            let guard = opaque()?;
            tail.push(self.statement(include_str!("../../sql/work/guard.sql"), &[text(&guard)])?);
            tail.push(self.statement(
                "DELETE FROM work_transition_guard WHERE guard_id=?1",
                &[text(&guard)],
            )?);
        }
        let result = self
            .atomic(
                vec![self.statement(include_str!("../../sql/work/transition.sql"), &bindings)?],
                Audit {
                    before: Some(state_name(row.state)),
                    after: Some(state_name(op.state())),
                    receipt: op.receipt(),
                    actor: "op-work-executor",
                    ..owner_audit(
                        &row.owner_id,
                        "operation",
                        id,
                        "operation.outcome",
                        row.revision + 1,
                    )
                },
                tail,
            )
            .await;
        match result {
            Ok(()) => Ok(op),
            Err(error) => {
                let current = self.operation(id).await?;
                if current.state() == op.state() && current.receipt() == op.receipt() {
                    Ok(current)
                } else {
                    Err(error)
                }
            }
        }
    }

    pub async fn cancel_operation(
        &self,
        session_hash: &str,
        id: &str,
    ) -> Result<ExternalOperation> {
        let owner = self.owner(session_hash).await?;
        let row: OperationRow = self.first(LOOKUP, &[text(id)]).await?;
        if row.owner_id != owner.owner_id() {
            return Err(Denied::OwnerMismatch.into());
        }
        let mut op = row.restore(id)?;
        op.cancel_undispatched()?;
        if row.state == OperationState::Cancelled {
            return Ok(op);
        }
        let result = self
            .atomic(
                vec![self.statement(
                    include_str!("../../sql/work/cancel.sql"),
                    &[
                        text(id),
                        number(row.revision)?,
                        text(&row.body),
                        text(session_hash),
                    ],
                )?],
                Audit {
                    before: Some("prepared"),
                    after: Some("cancelled"),
                    ..owner_audit(
                        &row.owner_id,
                        "operation",
                        id,
                        "operation.cancel",
                        row.revision + 1,
                    )
                },
                vec![],
            )
            .await;
        let current = self.operation(id).await?;
        match result {
            Ok(()) => Ok(current),
            Err(_) if current.state() == OperationState::Cancelled => Ok(current),
            Err(error) => Err(error),
        }
    }
}
