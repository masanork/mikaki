//! Independent write-ahead floor for managed-work batches. Not an effect broker.
use super::*;
use serde::Serialize;
use worker::{D1Result, Env, Method, RequestInit};

const RELEASE: u64 = 1;

fn storage_category(error: &worker::Error) -> &'static str {
    if let worker::Error::UnknownJsError {
        cause: Some(cause), ..
    } = error
    {
        let nested = storage_category(cause);
        if nested != "unknown" && nested != "d1_unknown" {
            return nested;
        }
    }
    if let worker::Error::D1(error) = error {
        let nested = crate::checkpoint_diagnostics::storage_category(&error.cause());
        if nested != "unknown" {
            return nested;
        }
        // Current D1 errors may carry the useful message on the outer Error,
        // while older wrappers expose it only as cause.message.
        let outer: &js_sys::Error = error.as_ref();
        return crate::checkpoint_diagnostics::storage_category(&String::from(outer.message()));
    }
    crate::checkpoint_diagnostics::storage_category(&error.to_string())
}

fn failure(stage: &'static str, sequence: Option<u64>, category: &'static str) {
    worker::console_error!(
        "{}",
        serde_json::json!({
            "event":"authority_checkpoint_failure",
            "stage":stage,
            "sequence":sequence,
            "category":category,
        })
    );
}

fn observe<T>(result: Result<T>, stage: &'static str, sequence: Option<u64>) -> Result<T> {
    if let Err(error) = &result {
        let category = match error {
            StoreError::Storage(error) => storage_category(error),
            StoreError::Denied(Denied::StaleAuthority) => "stale_authority",
            StoreError::Denied(_) => "protocol_denied",
        };
        failure(stage, sequence, category);
    }
    result
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCheckpoint {
    authority: String,
    epoch: String,
    sequence: u64,
    tip: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Permit {
    operation: String,
    previous: AuthorityCheckpoint,
    next: AuthorityCheckpoint,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointState {
    checkpoint: AuthorityCheckpoint,
    pending: Option<Permit>,
    last: Option<Permit>,
    release_floor: u64,
    frozen: bool,
}
impl AuthorityCheckpoint {
    fn validate(&self) -> Result<()> {
        if !owner_id_shape(&self.authority) || self.sequence > MAX_STORED_INTEGER {
            return Err(Denied::InvalidInput.into());
        }
        Digest::parse_hex(&self.epoch)?;
        Digest::parse_hex(&self.tip)?;
        Ok(())
    }
}
impl Permit {
    fn validate(&self) -> Result<()> {
        self.previous.validate()?;
        self.next.validate()?;
        if !owner_id_shape(&self.operation)
            || self.previous.authority != self.next.authority
            || self.previous.epoch != self.next.epoch
            || self.previous.sequence.checked_add(1) != Some(self.next.sequence)
            || self.previous.tip == self.next.tip
        {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(())
    }
}
impl WorkStore {
    pub async fn require_current_authority(&self) -> Result<()> {
        #[cfg(feature = "work-qualification")]
        if self.checkpoint.is_none() && !self.checkpoint_enrolled().await? {
            return Ok(());
        }
        self.current_authority_checkpoint().await?;
        Ok(())
    }
    pub(crate) async fn checkpoint_enrolled(&self) -> Result<bool> {
        if self.statement("SELECT name FROM sqlite_master WHERE type='table' AND name='work_authority_checkpoint'", &[])?.first::<String>(Some("name")).await?.is_none() {
            return Ok(false);
        }
        Ok(self
            .statement(
                "SELECT authority FROM work_authority_checkpoint WHERE id=1",
                &[],
            )?
            .first::<String>(Some("authority"))
            .await?
            .is_some())
    }
    pub fn from_env(env: &Env) -> Result<Self> {
        Ok(Self {
            db: env.d1("DB")?,
            checkpoint: env.service("WORK_AUTHORITY_CHECKPOINT").ok(),
        })
    }
    async fn checkpoint_call<T: serde::de::DeserializeOwned>(
        &self,
        body: serde_json::Value,
    ) -> Result<T> {
        let service = self.checkpoint.as_ref().ok_or(Denied::StaleAuthority)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_body(Some(text(&body.to_string())));
        let mut response = service
            .fetch("https://private.invalid/checkpoint", Some(init))
            .await?;
        if response.status_code() != 200 {
            return Err(Denied::StaleAuthority.into());
        }
        // Trusted fixed response schema; bound the stream before JSON decoding.
        let mut stream = response.stream()?;
        use futures_util::StreamExt;
        let mut bytes = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if bytes.len() + chunk.len() > 4096 {
                return Err(Denied::InvalidInput.into());
            }
            bytes.extend(chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| Denied::InvalidInput.into())
    }
    async fn primary_checkpoint(&self) -> Result<AuthorityCheckpoint> {
        let c: AuthorityCheckpoint = self
            .statement(
                "SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1",
                &[],
            )?
            .first(None)
            .await?
            .ok_or(Denied::StaleAuthority)?;
        c.validate()?;
        Ok(c)
    }
    /// Fresh observation only. A future effect/release broker must enforce its
    /// own outside-OP fence; this result is not a reusable effect permission.
    pub async fn current_authority_checkpoint(&self) -> Result<AuthorityCheckpoint> {
        let c = self.primary_checkpoint().await?;
        let s: CheckpointState = self
            .checkpoint_call(serde_json::json!({"action":"status","release":RELEASE}))
            .await?;
        if s.frozen
            || s.pending.is_some()
            || s.release_floor == 0
            || s.release_floor > RELEASE
            || s.checkpoint != c
        {
            return Err(Denied::StaleAuthority.into());
        }
        if let Some(last) = s.last {
            last.validate()?;
        }
        s.checkpoint.validate()?;
        Ok(c)
    }
    fn checkpoint_step(&self, p: &Permit) -> Result<D1PreparedStatement> {
        self.statement("UPDATE work_authority_checkpoint SET sequence=?1,tip=?2 WHERE id=1 AND authority=?3 AND epoch=?4 AND sequence=?5 AND tip=?6", &[
            number(p.next.sequence)?, text(&p.next.tip), text(&p.previous.authority), text(&p.previous.epoch), number(p.previous.sequence)?, text(&p.previous.tip)])
    }
    /// A pending write has no expiry/replacement. Fence any still-in-flight SQL
    /// with CAS advancement before reconciling; never replay business SQL.
    async fn settle_checkpoint(&self, p: &Permit, definitive_abort: bool) -> Result<()> {
        p.validate()?;
        let mut current = observe(
            self.primary_checkpoint().await,
            "settlement_read",
            Some(p.next.sequence),
        )?;
        if current == p.previous {
            // An old marker after a lost result can also be a restored DB. It
            // must stay quarantined; absence is never proof of non-commit.
            if !definitive_abort {
                failure(
                    "settlement_observation",
                    Some(p.next.sequence),
                    "previous_marker_quarantined",
                );
                return Err(Denied::StaleAuthority.into());
            }
            // This CAS is serialized at D1 primary. A late original batch has
            // the same leading CAS+guard and must abort if this wins first.
            observe(
                self.db
                    .batch(vec![self.checkpoint_step(p)?])
                    .await
                    .map_err(StoreError::from),
                "settlement_fence",
                Some(p.next.sequence),
            )?;
            current = observe(
                self.primary_checkpoint().await,
                "settlement_read",
                Some(p.next.sequence),
            )?;
        }
        if current != p.next {
            failure(
                "settlement_observation",
                Some(p.next.sequence),
                "marker_mismatch",
            );
            return Err(Denied::StaleAuthority.into());
        }
        let committed: AuthorityCheckpoint = observe(self.checkpoint_call(serde_json::json!({"action":"commit","release":RELEASE,"permit":p,"observed":current})).await, "permit_commit", Some(p.next.sequence))?;
        if committed != p.next {
            failure("permit_commit", Some(p.next.sequence), "response_mismatch");
            return Err(Denied::BindingMismatch.into());
        }
        Ok(())
    }
    pub async fn reconcile_authority_checkpoint(&self) -> Result<AuthorityCheckpoint> {
        let s: CheckpointState = self
            .checkpoint_call(serde_json::json!({"action":"status","release":RELEASE}))
            .await?;
        if let Some(p) = s.pending {
            self.settle_checkpoint(&p, false).await?;
        }
        self.current_authority_checkpoint().await
    }
    pub(super) async fn checkpoint_batch(
        &self,
        mut statements: Vec<D1PreparedStatement>,
    ) -> Result<Vec<D1Result>> {
        if self.checkpoint.is_none() {
            // Unenrolled synthetic history is deliberately weak local evidence.
            // Missing binding after enrollment never takes this exemption.
            #[cfg(feature = "work-qualification")]
            if !self.checkpoint_enrolled().await? {
                return Ok(self.db.batch(statements).await?);
            }
            return Err(Denied::StaleAuthority.into());
        }
        let expected = observe(self.primary_checkpoint().await, "primary_read", None)?;
        let operation = opaque()?;
        let p: Permit = observe(self.checkpoint_call(serde_json::json!({"action":"begin","release":RELEASE,"expected":expected,"operation":operation})).await, "permit_begin", Some(expected.sequence))?;
        observe(p.validate(), "permit_validation", Some(expected.sequence))?;
        if p.previous != expected || p.operation != operation {
            failure(
                "permit_validation",
                Some(expected.sequence),
                "response_mismatch",
            );
            return Err(Denied::BindingMismatch.into());
        }
        let framed = observe(
            self.authority_frame_schema().await,
            "batch_prepare",
            Some(p.next.sequence),
        )?;
        let prepared = (|| -> Result<_> {
            if framed {
                statements.insert(
                0,
                self.statement(
                    "INSERT INTO work_authority_frame(id,sequence,tip,closure) VALUES(1,?1,?2,1)",
                    &[number(p.next.sequence)?, text(&p.next.tip)],
                )?,
            );
                statements
                    .push(self.statement("DELETE FROM work_authority_frame WHERE id=1", &[])?);
            }
            let guard = opaque()?;
            statements.insert(
                0,
                self.statement(include_str!("../../sql/work/guard.sql"), &[text(&guard)])?,
            );
            statements.insert(0, self.checkpoint_step(&p)?);
            statements.push(self.statement(
                "DELETE FROM work_transition_guard WHERE guard_id=?1",
                &[text(&guard)],
            )?);
            Ok(statements)
        })();
        let result = self
            .db
            .batch(observe(prepared, "batch_prepare", Some(p.next.sequence))?)
            .await;
        // Preserve the original failure's closed category before settlement can
        // replace it with StaleAuthority. Never log SQL or provider error text.
        if let Err(error) = &result {
            failure("d1_batch", Some(p.next.sequence), storage_category(error));
        }
        // Publication failure must not return a dispatch authorization. A future
        // explicit reconciliation settles only the checkpoint, not business I/O.
        let definitive_abort = result.as_ref().err().is_some_and(|e| {
            let s = e.to_string();
            s.contains("SQLITE_CONSTRAINT")
                || s.contains("work_guard_passed")
                || s.contains("work_resource_exhausted")
                || s.contains("work_source_guard_failed")
                || s.contains("work_preparation_guard_failed")
                || s.contains("work_checkpoint_guard_failed")
        });
        self.settle_checkpoint(&p, definitive_abort).await?;
        match result {
            Ok(mut results) => {
                results.drain(0..2);
                results.pop();
                if framed {
                    results.remove(0);
                    results.pop();
                }
                Ok(results)
            }
            Err(error) => Err(StoreError::Storage(error)),
        }
    }
    async fn authority_frame_schema(&self) -> Result<bool> {
        #[cfg(feature = "work-qualification")]
        return Ok(self
            .statement(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='work_authority_frame'",
                &[],
            )?
            .first::<String>(Some("name"))
            .await?
            .is_some());
        #[cfg(not(feature = "work-qualification"))]
        Ok(true)
    }
    // In-process OP capability only; never expose statement inputs over RPC.
    pub(crate) async fn authority_batch(
        &self,
        statements: Vec<D1PreparedStatement>,
    ) -> Result<Vec<D1Result>> {
        if self.checkpoint.is_some() || self.checkpoint_enrolled().await? {
            self.checkpoint_batch(statements).await
        } else {
            Ok(self.db.batch(statements).await?)
        }
    }
    pub(crate) async fn require_authority_if_enrolled(&self) -> Result<()> {
        if self.checkpoint.is_some() || self.checkpoint_enrolled().await? {
            self.current_authority_checkpoint().await?;
        }
        Ok(())
    }
}
