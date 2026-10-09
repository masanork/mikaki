//! Bounded owner projections. Every SELECT joins the live OP session in the same
//! statement as the owned row; an earlier HTTP authentication is insufficient.
use super::*;
use serde::Serialize;
use serde_json::{Value, json};

pub enum OwnerRecordKind {
    Disclosure,
    Preparation,
    Request,
    Grant,
    Run,
    Operation,
}

#[derive(Deserialize, Serialize)]
pub struct OwnerRequestSummary {
    request_id: String,
    digest: String,
    revision: u64,
    expires_at: u64,
}
#[derive(Serialize)]
pub struct OwnerRequestPage {
    pub requests: Vec<OwnerRequestSummary>,
    pub next_after: Option<String>,
}
#[derive(Deserialize)]
struct OwnerRecordRow {
    body: String,
    revision: u64,
    #[serde(default)]
    revoked: u8,
    #[serde(default)]
    is_current: u8,
    state: Option<OperationState>,
    receipt: Option<String>,
}

#[derive(Deserialize)]
struct OwnerPreparationRow {
    body: String,
    state: PreparationState,
    revision: u64,
    evidence: Option<String>,
    current_authority: u8,
    materialized: u8,
}
impl OwnerPreparationRow {
    fn project(self) -> Result<Value> {
        let p = Preparation::restore_authority_record(&self.body, self.state)?;
        let e = self
            .evidence
            .as_deref()
            .map(VerifiedPreparation::restore_authority_record)
            .transpose()?;
        let mut projection = p.review(e.as_ref())?;
        projection["revision"] = json!(self.revision);
        projection["current_authority"] = json!(self.current_authority == 1);
        projection["materialized"] = json!(self.materialized == 1);
        Ok(projection)
    }
}
const OWNER_PREPARATION_FIELDS: &str = "p.body,p.state,p.revision,p.evidence, \
 EXISTS(SELECT 1 FROM work_prepared_task_current c WHERE c.repository_id=p.task_repository) AS current_authority, \
 EXISTS(SELECT 1 FROM work_prepared_task t WHERE t.preparation_id=p.operation_id) AS materialized";

pub(crate) fn owner_id_shape(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

impl WorkStore {
    /// Bounded history, not a list of delegable repositories. Restore each public
    /// projection from its current row; authenticate again after checkpoint I/O.
    pub async fn owner_preparations(
        &self,
        session_hash: &str,
        after: Option<&str>,
    ) -> Result<Value> {
        if after.is_some_and(|id| !owner_id_shape(id)) {
            return Err(Denied::InvalidInput.into());
        }
        self.require_current_authority().await?;
        let sql = format!(
            "SELECT {OWNER_PREPARATION_FIELDS} FROM work_preparation p \
             JOIN authenticated_owner a ON a.account_id=p.owner_id \
             WHERE p.operation_id>?2 ORDER BY p.operation_id LIMIT 21"
        );
        let mut rows = self
            .owner_statement(session_hash, &sql, after.unwrap_or(""))?
            .all()
            .await?
            .results::<OwnerPreparationRow>()?;
        let more = rows.len() > 20;
        rows.truncate(20);
        let preparations = rows
            .into_iter()
            .map(OwnerPreparationRow::project)
            .collect::<Result<Vec<_>>>()?;
        let next = if more {
            preparations.last().and_then(|p| p["id"].as_str())
        } else {
            None
        };
        Ok(json!({"preparations":preparations,"next_after":next}))
    }

    pub(super) fn owner_statement(
        &self,
        session_hash: &str,
        sql: &str,
        key: &str,
    ) -> Result<D1PreparedStatement> {
        // Both fragments are internal constants; all session/resource values bind.
        let sql = format!(
            "WITH authenticated_owner AS ({}) {sql}",
            include_str!("../../sql/work/owner-session.sql")
        );
        self.statement(&sql, &[text(session_hash), text(key)])
    }

    /// Keyset page of current heads, at most 20 summaries (21 rows fetched).
    /// No goals/file payloads or arbitrary limit/owner parameters in the list.
    pub async fn owner_requests(
        &self,
        session_hash: &str,
        after: Option<&str>,
    ) -> Result<OwnerRequestPage> {
        if after.is_some_and(|id| !owner_id_shape(id)) {
            return Err(Denied::InvalidInput.into());
        }
        self.require_current_authority().await?;
        let mut rows = self.owner_statement(session_hash,
            "SELECT h.request_id,h.digest,h.revision,w.expires_at FROM work_request_head h \
             JOIN authenticated_owner a ON a.account_id=h.owner_id JOIN work_request w ON w.digest=h.digest \
             WHERE h.request_id>?2 ORDER BY h.request_id LIMIT 21", after.unwrap_or(""))?
            .all().await?.results::<OwnerRequestSummary>()?;
        let next_after = if rows.len() > 20 {
            rows.truncate(20);
            rows.last().map(|row| row.request_id.clone())
        } else {
            None
        };
        Ok(OwnerRequestPage {
            requests: rows,
            next_after,
        })
    }

    /// Selected public fields only. Mutable state is restored from current D1
    /// columns, never from the immutable body's initial state. No bearer material.
    pub async fn owner_record(
        &self,
        session_hash: &str,
        kind: OwnerRecordKind,
        id: &str,
    ) -> Result<Value> {
        if !owner_id_shape(id) {
            return Err(Denied::InvalidInput.into());
        }
        self.require_current_authority().await?;
        if matches!(kind, OwnerRecordKind::Preparation) {
            let sql = format!(
                "SELECT {OWNER_PREPARATION_FIELDS} FROM work_preparation p JOIN authenticated_owner a ON a.account_id=p.owner_id WHERE p.operation_id=?2"
            );
            let row: OwnerPreparationRow = self
                .owner_statement(session_hash, &sql, id)?
                .first(None)
                .await?
                .ok_or(StoreError::Denied(Denied::BindingMismatch))?;
            let projection = row.project()?;
            if projection["id"].as_str() != Some(id) {
                return Err(Denied::BindingMismatch.into());
            }
            return Ok(json!({"kind":"preparation","preparation":projection}));
        }
        let sql = match kind {
            OwnerRecordKind::Preparation => unreachable!(),
            OwnerRecordKind::Disclosure => {
                "SELECT d.body,1 AS revision,EXISTS(SELECT 1 FROM work_disclosure_source_current c WHERE c.digest=d.digest) AS is_current,NULL AS state,NULL AS receipt FROM work_disclosure d \
                JOIN authenticated_owner a ON a.account_id=d.owner_id WHERE d.digest=?2"
            }
            OwnerRecordKind::Request => {
                "SELECT w.body,w.revision,(w.digest=h.digest) AS is_current,NULL AS state,NULL AS receipt \
                FROM work_request w JOIN authenticated_owner a ON a.account_id=w.owner_id \
                JOIN work_request_head h ON h.owner_id=w.owner_id AND h.request_id=w.request_id WHERE w.digest=?2"
            }
            OwnerRecordKind::Grant => {
                "SELECT g.body,g.revision,g.revoked,NULL AS state,NULL AS receipt FROM work_grant g \
                JOIN work_request w ON w.digest=g.request_digest JOIN authenticated_owner a ON a.account_id=w.owner_id WHERE g.grant_id=?2"
            }
            OwnerRecordKind::Run => {
                "SELECT r.body,r.revision,r.revoked,NULL AS state,NULL AS receipt FROM work_run r \
                JOIN work_request w ON w.digest=r.request_digest JOIN authenticated_owner a ON a.account_id=w.owner_id WHERE r.run_id=?2"
            }
            OwnerRecordKind::Operation => {
                "SELECT o.body,o.revision,o.state,o.receipt FROM work_code_operation o \
                JOIN authenticated_owner a ON a.account_id=o.owner_id WHERE o.operation_id=?2"
            }
        };
        let row = self
            .owner_statement(session_hash, sql, id)?
            .first::<OwnerRecordRow>(None)
            .await?
            .ok_or(StoreError::Denied(Denied::BindingMismatch))?;
        let projection = match kind {
            OwnerRecordKind::Disclosure => {
                let d = ResolvedDisclosure::restore_authority_record(&row.body)?;
                if d.digest().to_hex() != id {
                    return Err(Denied::BindingMismatch.into());
                }
                json!({"kind":"disclosure","digest":d.digest(),"manifest":d.review(),"current_sources":row.is_current==1})
            }
            OwnerRecordKind::Request => {
                let request = WorkRequest::restore_authority_record(&row.body)?;
                if request.digest().to_hex() != id {
                    return Err(Denied::BindingMismatch.into());
                }
                // Repeat SSO in the final metadata SELECT, even when no binding
                // exists. An expired session cannot turn a failed read into null.
                let sql = "SELECT (SELECT json_object('body',p.body,'state',p.state,'revision',p.revision,'evidence',p.evidence, \
                        'current_authority',EXISTS(SELECT 1 FROM work_prepared_task_current c WHERE c.repository_id=p.task_repository), \
                        'materialized',1) FROM work_request_preparation r JOIN work_prepared_task t ON t.repository_id=r.repository_id \
                        JOIN work_preparation p ON p.operation_id=t.preparation_id WHERE r.request_digest=w.digest) AS preparation \
                        FROM authenticated_owner a JOIN work_request w ON w.owner_id=a.account_id WHERE w.digest=?2";
                #[derive(Deserialize)]
                struct Associated {
                    preparation: Option<String>,
                }
                let associated: Associated = self
                    .owner_statement(session_hash, sql, id)?
                    .first(None)
                    .await?
                    .ok_or(StoreError::Denied(Denied::StaleAuthority))?;
                let preparation = associated
                    .preparation
                    .map(|body| {
                        let row: OwnerPreparationRow =
                            serde_json::from_str(&body).map_err(|_| Denied::BindingMismatch)?;
                        row.project()
                    })
                    .transpose()?;
                json!({"kind":"request","digest":request.digest(),"request":request.input(),"is_current":row.is_current==1,"preparation":preparation})
            }
            OwnerRecordKind::Grant => {
                let grant =
                    Grant::restore_authority_record(&row.body, row.revision, row.revoked == 1)?;
                if grant.id() != id {
                    return Err(Denied::BindingMismatch.into());
                }
                json!({"kind":"grant","id":grant.id(),"request_digest":grant.request_digest(),"revision":grant.revision(),"revoked":grant.is_revoked(),"expires_at":grant.expires_at()})
            }
            OwnerRecordKind::Run => {
                let run = Run::restore_authority_record(&row.body, row.revision, row.revoked == 1)?;
                if run.id() != id {
                    return Err(Denied::BindingMismatch.into());
                }
                json!({"kind":"run","id":run.id(),"request_digest":run.request_digest(),"grant_id":run.grant_id(),"revision":run.revision(),"revoked":run.is_revoked(),"expires_at":run.expires_at()})
            }
            OwnerRecordKind::Operation => {
                let state = row.state.ok_or(Denied::InvalidInput)?;
                let operation = ExternalOperation::restore_authority_record(
                    &row.body,
                    state,
                    row.receipt.as_deref(),
                )?;
                if operation.id() != id {
                    return Err(Denied::BindingMismatch.into());
                }
                json!({"kind":"operation","id":operation.id(),"revision":row.revision,"state":operation.state(),"repository":operation.repository(),"reference":operation.reference(),"expected_head":operation.expected_head(),"commit":operation.commit(),"receipt":operation.receipt()})
            }
            OwnerRecordKind::Preparation => unreachable!(),
        };
        Ok(projection)
    }
}
