//! Fixed Native copy sequence. Workflow transports IDs; these primary records,
//! current consent and independent effect journals decide every operation.
use super::*;
use futures_util::StreamExt;
use serde_json::{Value, json};
use worker::{Env, Method, RequestInit};

const TOTAL: u64 = 19;
#[derive(Deserialize)]
struct Job {
    preparation_id: String,
    review_digest: String,
    state: String,
    next_step: u64,
    inflight: u8,
    revision: u64,
    updated_at: u64,
}
const FIELDS: &str = "preparation_id,review_digest,state,next_step,inflight,revision,updated_at";
#[derive(Clone, Copy)]
enum Phase {
    Initial,
    Mint,
    Git,
    Reconcile,
    Close,
    Verify,
}
fn phase(step: u64) -> Result<(CredentialRole, CredentialPurpose, Phase)> {
    use CredentialPurpose::*;
    use CredentialRole::*;
    Ok(match step {
        0 => (Task, Initial, Phase::Initial),
        1 => (Snapshot, Initial, Phase::Initial),
        2..=17 => {
            let n = step - 2;
            let role = if n < 8 { Task } else { Snapshot };
            let purpose = if n % 8 < 4 { Upload } else { Readback };
            (
                role,
                purpose,
                match n % 4 {
                    0 => Phase::Mint,
                    1 => Phase::Git,
                    2 => Phase::Reconcile,
                    _ => Phase::Close,
                },
            )
        }
        18 => (Task, Initial, Phase::Verify),
        _ => return Err(Denied::InvalidInput.into()),
    })
}
impl Job {
    fn project(&self) -> Value {
        json!({"preparation_id":self.preparation_id,"review_digest":self.review_digest,
         "state":self.state,"next_step":self.next_step,"total_steps":TOTAL,
         "inflight":self.inflight==1,"updated_at":self.updated_at})
    }
}
pub(crate) async fn gate(env: &Env, binding: &str, path: &str, input: Value) -> Result<Value> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(text(&input.to_string())));
    let mut response = env
        .service(binding)?
        .fetch(&format!("https://private.invalid{path}"), Some(init))
        .await?;
    if response.status_code() != 200 {
        return Err(Denied::StaleAuthority.into());
    }
    let mut stream = response.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > 4096 {
            return Err(Denied::InvalidInput.into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let body = String::from_utf8(bytes).map_err(|_| Denied::InvalidInput)?;
    mikaki_webauthn::strict_json(&body, 4096, 8).map_err(|_| Denied::InvalidInput)?;
    serde_json::from_str(&body).map_err(|_| Denied::InvalidInput.into())
}
impl WorkStore {
    async fn copy_job(&self, id: &str) -> Result<Job> {
        let row: Job = self
            .first(
                &format!("SELECT {FIELDS} FROM work_copy_job WHERE preparation_id=?1"),
                &[text(id)],
            )
            .await?;
        if row.preparation_id != id || row.next_step > TOTAL || row.inflight > 1 {
            return Err(Denied::BindingMismatch.into());
        }
        Digest::parse_hex(&row.review_digest)?;
        Ok(row)
    }
    pub async fn owner_copy_job(&self, session: &str, id: &str, account: &str) -> Result<Value> {
        let review = self.owner_copy_review(session, id, account).await?;
        let p = self
            .owner_record(session, OwnerRecordKind::Preparation, id)
            .await?;
        let job = self
            .statement(
                &format!("SELECT {FIELDS} FROM work_copy_job WHERE preparation_id=?1"),
                &[text(id)],
            )?
            .first::<Job>(None)
            .await?;
        let approving_session=self.statement("SELECT preparation_id FROM work_copy_consent_current WHERE preparation_id=?1 AND session_hash=?2",&[text(id),text(session)])?.first::<String>(Some("preparation_id")).await?.is_some();
        let cleanup_pending = if job.as_ref().is_some_and(|j| j.state == "blocked") {
            self.credential_attempts(id)
                .await?
                .iter()
                .any(|a| !matches!(a.state.as_str(), "closed" | "reserved"))
        } else {
            false
        };
        Ok(
            json!({"review_digest":review["review_digest"],"can_start":job.is_none() && approving_session && review["current"]==true && p["preparation"]["state"]=="reserved","cleanup_pending":cleanup_pending,
          "preparation_state":p["preparation"]["state"],"job":job.map(|j|j.project())}),
        )
    }
    pub async fn start_copy_job(
        &self,
        env: &Env,
        session: &str,
        id: &str,
        digest: Digest,
    ) -> Result<Value> {
        let account = copy_account(env)?;
        let review = self.owner_copy_review(session, id, &account).await?;
        if review["review_digest"] != digest.to_hex() {
            return Err(Denied::ReviewMismatch.into());
        }
        // An exact retry must still use the approving live SSO and fixed account.
        if self.statement("SELECT preparation_id FROM work_copy_consent_current WHERE preparation_id=?1 AND session_hash=?2 AND review_digest=?3 AND artifacts_account=?4",&[text(id),text(session),text(&digest.to_hex()),text(&account)])?.first::<String>(Some("preparation_id")).await?.is_none(){return Err(Denied::StaleAuthority.into());}
        let existing = self
            .statement(
                "SELECT preparation_id FROM work_copy_job WHERE preparation_id=?1",
                &[text(id)],
            )?
            .first::<String>(Some("preparation_id"))
            .await?;
        if existing.is_none() {
            let p = self.preparation(id).await?;
            if p.state() != PreparationState::Reserved {
                return Err(Denied::InvalidTransition.into());
            }
            // Validate the operator's already active wrapping key and fixed
            // starter before reserving an outbox record. Never activate a key.
            env.service("WORK_COPY_STARTER")?;
            self.active_copy_key(env).await?;
            self.atomic(vec![self.statement("INSERT INTO work_copy_job(preparation_id,review_digest,state,next_step,inflight,revision) VALUES(?1,?2,'queued',0,0,1)",&[text(id),text(&digest.to_hex())])?],owner_audit(p.owner_id(),"copy-job",id,"copy.queue",1),vec![]).await?;
        }
        if self.copy_job(id).await?.state == "queued" {
            // The queued primary outbox survives a lost trigger reply. The fixed
            // Workflow ID is never restarted or replaced. Retry/scheduled drain
            // can only notify that same instance.
            let _ = gate(
                env,
                "WORK_COPY_STARTER",
                "/start",
                json!({"preparation_id":id}),
            )
            .await;
        }
        self.owner_copy_job(session, id, &account).await
    }
    async fn active_copy_key(&self, env: &Env) -> Result<WrappingKey> {
        let version = self
            .statement(
                "SELECT version FROM work_credential_key WHERE state='active'",
                &[],
            )?
            .first::<u64>(Some("version"))
            .await?
            .ok_or(Denied::StaleAuthority)?;
        let key = credential_key(env, version)?;
        self.check_copy_key(&key).await?;
        Ok(key)
    }
    pub async fn pending_copy_jobs(&self) -> Result<Value> {
        self.require_current_authority().await?;
        let ids=self.statement("SELECT j.preparation_id FROM work_copy_job j JOIN work_copy_consent_current c ON c.preparation_id=j.preparation_id AND c.review_digest=j.review_digest WHERE j.state='queued' ORDER BY j.preparation_id LIMIT 20",&[])?.all().await?.results::<serde_json::Value>()?;
        Ok(json!({"preparations":ids}))
    }
    pub async fn advance_copy_job(&self, env: &Env, id: &str, expected: u64) -> Result<Value> {
        let job = self.copy_job(id).await?;
        if expected < job.next_step || matches!(job.state.as_str(), "blocked" | "verified") {
            return Ok(job.project());
        }
        if expected != job.next_step || expected >= TOTAL {
            return Err(Denied::InvalidInput.into());
        }
        if job.inflight == 1 {
            // A restored/duplicate Workflow cannot know whether the admitted
            // physical effect completed. Retain a stop and known-ID cleanup;
            // never replay that step or leave it looking ready to advance.
            let _ = self.cleanup_copy_job(env, id).await;
            return Ok(json!({"preparation_id":id,"state":"blocked","next_step":job.next_step}));
        }
        self.require_current_authority().await?;
        self.require_copy_consent(id, Some(&copy_account(env)?))
            .await?;
        let p = self.preparation(id).await?;
        self.atomic(vec![self.statement("UPDATE work_copy_job SET state='running',inflight=1,revision=revision+1,updated_at=unixepoch() WHERE preparation_id=?1 AND revision=?2 AND next_step=?3 AND inflight=0 AND state IN('queued','running')",&[text(id),number(job.revision)?,number(expected)?])?],owner_audit(p.owner_id(),"copy-job",id,"copy.step.admit",job.revision+1),vec![]).await?;
        // Only the successful primary claimant reaches a physical gate. A lost
        // or duplicate admission never replays it. All gates retain their own
        // independent permanent admission across primary/Workflow restore.
        let result = self.execute_copy_phase(env, id, expected).await;
        let claimed = self.copy_job(id).await?;
        if result.is_err() {
            let _ = self.block_copy_job(id).await;
            let _ = self.cleanup_copy_job(env, id).await;
            return Ok(json!({"preparation_id":id,"state":"blocked","next_step":expected}));
        }
        let state = if expected + 1 == TOTAL {
            "verified"
        } else {
            "running"
        };
        self.atomic(vec![self.statement("UPDATE work_copy_job SET state=?1,next_step=next_step+1,inflight=0,revision=revision+1,updated_at=unixepoch() WHERE preparation_id=?2 AND revision=?3 AND inflight=1 AND next_step=?4 AND state='running'",&[text(state),text(id),number(claimed.revision)?,number(expected)?])?],owner_audit(p.owner_id(),"copy-job",id,"copy.step.finish",claimed.revision+1),vec![]).await?;
        Ok(self.copy_job(id).await?.project())
    }
    async fn execute_copy_phase(&self, env: &Env, id: &str, step: u64) -> Result<()> {
        let (role, purpose, phase) = phase(step)?;
        if matches!(phase, Phase::Verify) {
            let reply = gate(
                env,
                "WORK_COPY_VERIFIER",
                "/verify-preparation",
                json!({"preparation_id":id}),
            )
            .await?;
            if reply["id"] != id
                || reply["state"] != "verified"
                || self.preparation(id).await?.state() != PreparationState::Verified
            {
                return Err(Denied::BindingMismatch.into());
            }
            return Ok(());
        }
        if step == 0 {
            self.dispatch_preparation(id).await?;
        }
        let a = if matches!(phase, Phase::Initial | Phase::Mint) {
            let key = self.active_copy_key(env).await?;
            self.reserve_credential(id, role, purpose, &key).await?
        } else {
            self.copy_slot(id, role, purpose).await?
        };
        let (binding, path) = match phase {
            Phase::Initial => ("WORK_COPY_INITIAL", "/initial"),
            Phase::Mint => ("WORK_COPY_MINT", "/mint"),
            Phase::Git => ("WORK_COPY_GIT", "/git"),
            Phase::Reconcile => ("WORK_COPY_RECONCILER", "/reconcile-mint"),
            Phase::Close => ("WORK_COPY_CLOSER", "/close-mint"),
            Phase::Verify => unreachable!(),
        };
        let reply = gate(env, binding, path, json!({"attempt_id":a.id})).await?;
        if reply["attempt_id"] != a.id {
            return Err(Denied::BindingMismatch.into());
        }
        let current = self.credential_status(&a.id).await?;
        let okay = match phase {
            Phase::Initial | Phase::Close => {
                reply["state"] == "closed"
                    && reply["op_synchronized"] == true
                    && current.state == "closed"
            }
            Phase::Mint => {
                reply["state"] == "custodied"
                    && reply["op_synchronized"] == true
                    && current.state == "captured"
            }
            Phase::Git => reply["state"] == "completed",
            Phase::Reconcile => {
                reply["op_synchronized"] == true && current.state == "revocation_pending"
            }
            Phase::Verify => false,
        };
        if !okay {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(())
    }
    pub async fn block_copy_job(&self, id: &str) -> Result<()> {
        let job = self.copy_job(id).await?;
        if matches!(job.state.as_str(), "blocked" | "verified") {
            return Ok(());
        }
        let p = self.preparation(id).await?;
        self.atomic(vec![self.statement("UPDATE work_copy_job SET state='blocked',revision=revision+1,updated_at=unixepoch() WHERE preparation_id=?1 AND revision=?2 AND state IN('queued','running')",&[text(id),number(job.revision)?])?],owner_audit(p.owner_id(),"copy-job",id,"copy.block",job.revision+1),vec![]).await
    }
    pub async fn cleanup_copy_job(&self, env: &Env, id: &str) -> Result<Value> {
        self.copy_job(id).await?; // Only retained jobs; safety grants no new work.
        let _ = self.block_copy_job(id).await;
        let p = self.preparation(id).await?;
        let attempts = self.credential_attempts(id).await?;
        for a in attempts {
            if a.state == "closed" || a.state == "reserved" {
                continue;
            }
            let planned = self.credential_plan(&a.id).await?;
            if planned.purpose() == CredentialPurpose::Initial {
                let _ = gate(
                    env,
                    "WORK_COPY_INITIAL_RECONCILER",
                    "/reconcile",
                    json!({"attempt_id":a.id}),
                )
                .await;
            } else {
                let _ = self.require_credential_revocation(&a.id).await;
                let _ = gate(
                    env,
                    "WORK_COPY_RECONCILER",
                    "/cancel-mint",
                    json!({"attempt_id":a.id}),
                )
                .await;
                let _ = gate(
                    env,
                    "WORK_COPY_CLOSER",
                    "/close-mint",
                    json!({"attempt_id":a.id}),
                )
                .await;
            }
        }
        let pending = self
            .credential_attempts(id)
            .await?
            .iter()
            .any(|a| !matches!(a.state.as_str(), "closed" | "reserved"));
        Ok(json!({"preparation_id":p.id(),"cleanup_pending":pending}))
    }
}
