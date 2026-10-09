//! Explicit consent to a fixed private copy; never a workload grant or launcher proof.
use super::*;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

#[derive(Deserialize)]
struct ReviewRow {
    body: String,
    state: PreparationState,
    revision: u64,
    sources_current: u8,
    review_digest: Option<String>,
    artifacts_account: Option<String>,
    active: Option<u8>,
    consent_current: u8,
}
pub fn copy_account(env: &worker::Env) -> Result<String> {
    let account = env.var("WORK_ARTIFACTS_ACCOUNT")?.to_string();
    if account.len() != 32
        || !account
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Denied::InvalidInput.into());
    }
    Ok(account)
}
impl WorkStore {
    /// Same live owner SELECT after independent checkpoint I/O. The immutable
    /// preparation digest binds disclosure, recipient, workload and destinations.
    pub async fn owner_copy_review(&self, session: &str, id: &str, account: &str) -> Result<Value> {
        if !owner_id_shape(id) {
            return Err(Denied::InvalidInput.into());
        }
        self.require_current_authority().await?;
        let row: ReviewRow = self.owner_statement(session,
            "SELECT p.body,p.state,p.revision,EXISTS(SELECT 1 FROM work_disclosure_source_current d WHERE d.digest=p.disclosure_digest) AS sources_current,c.review_digest,c.artifacts_account,c.active,EXISTS(SELECT 1 FROM work_copy_consent_current v WHERE v.preparation_id=p.operation_id) AS consent_current \
             FROM work_preparation p JOIN authenticated_owner a ON a.account_id=p.owner_id \
             LEFT JOIN work_copy_consent c ON c.preparation_id=p.operation_id WHERE p.operation_id=?2", id)?
            .first(None).await?.ok_or(Denied::BindingMismatch)?;
        let p = Preparation::restore_authority_record(&row.body, row.state)?;
        // The review describes the original reserved revision. A recorded
        // consent can be inspected later, but cannot authorize another copy.
        let subject = json!({"format_version":1,"purpose":"private-preparation-copy",
            "preparation_id":p.id(),"preparation_digest":p.digest(),"preparation_revision":1,
            "disclosure_digest":p.disclosure_digest(),"operator":"Cloudflare Artifacts",
            "artifacts_account":row.artifacts_account.as_deref().unwrap_or(account),"expires_at":p.expires_at()});
        let bytes = serde_json::to_vec(&subject).map_err(|_| Denied::InvalidInput)?;
        let mut h = Sha256::new();
        h.update(b"mikaki.work-copy-consent.v1\0");
        h.update(bytes);
        let digest = Digest::from_bytes(h.finalize().into()).to_hex();
        if row.review_digest.as_ref().is_some_and(|d| d != &digest) {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(json!({"review_digest":digest,"subject":subject,
            "status":match row.active { Some(1)=>"approved",Some(0)=>"withdrawn",_=>"unconfirmed" },
            "current":row.consent_current==1 && row.artifacts_account.as_deref()==Some(account),
            "can_approve":row.active.is_none() && row.sources_current==1 && row.state==PreparationState::Reserved && row.revision==1 && p.expires_at()>now()}))
    }
    pub async fn confirm_copy(
        &self,
        session: &str,
        id: &str,
        account: &str,
        digest: Digest,
    ) -> Result<Value> {
        let review = self.owner_copy_review(session, id, account).await?;
        if review["review_digest"] != digest.to_hex() {
            return Err(Denied::StaleAuthority.into());
        }
        if review["status"] == "approved" {
            // Exact retry of the same owner session only. Historical consent is
            // never adopted by a new login or a different destination account.
            if self.statement("SELECT preparation_id FROM work_copy_consent_current WHERE preparation_id=?1 AND session_hash=?2 AND review_digest=?3 AND artifacts_account=?4",
                &[text(id),text(session),text(&digest.to_hex()),text(account)])?.first::<String>(Some("preparation_id")).await?.is_none() { return Err(Denied::StaleAuthority.into()); }
            return Ok(review);
        }
        if review["can_approve"] != true {
            return Err(Denied::StaleAuthority.into());
        }
        let owner = self.owner(session).await?;
        let p = self.preparation(id).await?;
        let sql = format!(
            "WITH authenticated_owner AS ({}) INSERT INTO work_copy_consent(preparation_id,review_digest,preparation_digest,owner_id,session_hash,artifacts_account,expires_at,active,revision) \
            SELECT p.operation_id,?3,p.digest,p.owner_id,?1,?4,p.expires_at,1,1 FROM work_preparation p JOIN authenticated_owner a ON a.account_id=p.owner_id \
            WHERE p.operation_id=?2 AND p.digest=?5 AND p.state='reserved' AND p.revision=1",
            include_str!("../../sql/work/owner-session.sql")
        );
        self.atomic(
            vec![self.statement(
                &sql,
                &[
                    text(session),
                    text(id),
                    text(&digest.to_hex()),
                    text(account),
                    text(&p.digest().to_hex()),
                ],
            )?],
            Audit {
                owner: owner.owner_id(),
                kind: "copy-consent",
                entity: id,
                action: "copy.approve",
                actor: owner.owner_id(),
                revision: 1,
                before: None,
                after: Some("approved"),
                receipt: Some(&digest.to_hex()),
            },
            vec![],
        )
        .await?;
        self.owner_copy_review(session, id, account).await
    }
    pub async fn withdraw_copy(
        &self,
        session: &str,
        id: &str,
        account: &str,
        digest: Digest,
    ) -> Result<Value> {
        let review = self.owner_copy_review(session, id, account).await?;
        if review["review_digest"] != digest.to_hex() || review["status"] == "unconfirmed" {
            return Err(Denied::StaleAuthority.into());
        }
        if review["status"] == "withdrawn" {
            return Ok(review);
        }
        let owner = self.owner(session).await?;
        let sql = format!(
            "WITH authenticated_owner AS ({}) UPDATE work_copy_consent SET active=0,revision=revision+1 \
            WHERE preparation_id=?2 AND review_digest=?3 AND active=1 AND owner_id IN(SELECT account_id FROM authenticated_owner)",
            include_str!("../../sql/work/owner-session.sql")
        );
        self.atomic(
            vec![self.statement(&sql, &[text(session), text(id), text(&digest.to_hex())])?],
            Audit {
                owner: owner.owner_id(),
                kind: "copy-consent",
                entity: id,
                action: "copy.withdraw",
                actor: owner.owner_id(),
                revision: 2,
                before: Some("approved"),
                after: Some("withdrawn"),
                receipt: Some(&digest.to_hex()),
            },
            vec![],
        )
        .await?;
        self.owner_copy_review(session, id, account).await
    }
    pub(super) async fn require_copy_consent(&self, id: &str, account: Option<&str>) -> Result<()> {
        // Older schema qualification remains explicitly historical. Product
        // builds always require 0013; a missing table cannot authorize effects.
        #[cfg(feature = "work-qualification")]
        if self
            .statement(
                "SELECT name FROM sqlite_master WHERE name='work_copy_consent' AND type='table'",
                &[],
            )?
            .first::<String>(Some("name"))
            .await?
            .is_none()
        {
            return Ok(());
        }
        if self.statement("SELECT preparation_id FROM work_copy_consent_current WHERE preparation_id=?1 AND (?2 IS NULL OR artifacts_account=?2)",&[text(id),nullable(account)])?.first::<String>(Some("preparation_id")).await?.is_none() {return Err(Denied::StaleAuthority.into());}
        Ok(())
    }
}
