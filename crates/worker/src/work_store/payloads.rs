//! Private candidate retention. No owner upload/download, Git execution or URLs.
use super::*;
use worker::{Bucket, Conditional};

#[derive(Deserialize)]
struct PayloadRow {
    body: String,
    state: String,
}
#[derive(Deserialize)]
struct PayloadBinding {
    preparation_id: String,
    task_repo_id: String,
}
#[derive(Deserialize)]
struct CandidateId {
    digest: String,
}
impl WorkStore {
    async fn payload_binding(&self, candidate: &Candidate) -> Result<PayloadBinding> {
        self.first("SELECT t.preparation_id,t.task_repo_id FROM work_request_preparation r JOIN work_prepared_task t ON t.repository_id=r.repository_id WHERE r.request_digest=?1", &[text(&candidate.request_digest().to_hex())]).await
    }
    async fn restore_payload(&self, digest: Digest, body: &str) -> Result<CandidatePayload> {
        let c = self.candidate(digest).await?;
        let r = self.request(c.request_digest()).await?;
        let binding = self.payload_binding(&c).await?;
        let p = self.preparation(&binding.preparation_id).await?;
        Ok(CandidatePayload::restore_authority_record(
            body,
            &c,
            &r,
            &p,
            &binding.task_repo_id,
        )?)
    }
    async fn payload_row(&self, digest: Digest) -> Result<PayloadRow> {
        self.first(
            "SELECT body,state FROM work_candidate_payload WHERE candidate_digest=?1",
            &[text(&digest.to_hex())],
        )
        .await
    }
    /// Safety preservation of an already accepted candidate; no new production
    /// permission. Capacity is reserved before the first private R2 write.
    pub async fn reserve_candidate_payload(
        &self,
        digest: Digest,
        facts: CandidateGitFacts,
    ) -> Result<CandidatePayload> {
        let c = self.candidate(digest).await?;
        let r = self.request(c.request_digest()).await?;
        let binding = self.payload_binding(&c).await?;
        let p = self.preparation(&binding.preparation_id).await?;
        let payload =
            CandidatePayload::from_verified_git(&c, &r, &p, &binding.task_repo_id, facts)?;
        let body = payload.authority_record()?;
        let entity = digest.to_hex();
        self.put(
            "SELECT body FROM work_candidate_payload WHERE candidate_digest=?1",
            &digest.to_hex(),
            &body,
            vec![self.statement(
                include_str!("../../sql/work/reserve-candidate-payload.sql"),
                &[
                    text(&digest.to_hex()),
                    text(p.id()),
                    text(p.owner_id()),
                    text(&payload.digest().to_hex()),
                    text(&payload.object_key()),
                    number(payload.bundle_bytes())?,
                    text(&body),
                ],
            )?],
            payload_audit(
                &payload,
                &entity,
                "candidate.payload.reserve",
                1,
                None,
                Some("reserved"),
            ),
        )
        .await?;
        Ok(payload)
    }
    async fn read_payload_object(
        &self,
        bucket: &Bucket,
        payload: &CandidatePayload,
    ) -> Result<Vec<u8>> {
        let object = bucket
            .get(payload.object_key())
            .execute()
            .await?
            .ok_or(Denied::StaleAuthority)?;
        // The R2 object's own size is checked before buffering this bounded
        // opaque pack. Whole Git parsing belongs to the independent adapter.
        if object.size() != payload.bundle_bytes() || object.size() > MAX_CANDIDATE_BUNDLE_BYTES {
            return Err(Denied::BindingMismatch.into());
        }
        let bytes = object.body().ok_or(Denied::StaleAuthority)?.bytes().await?;
        payload.verify_bundle_bytes(&bytes)?;
        Ok(bytes)
    }
    /// Conditional write-once + actual digest readback before the audited D1
    /// marker. A lost reply/audit failure leaves one charged recoverable object.
    pub async fn retain_candidate_payload(
        &self,
        bucket: &Bucket,
        digest: Digest,
        bytes: Vec<u8>,
    ) -> Result<CandidatePayload> {
        let row = self.payload_row(digest).await?;
        let payload = self.restore_payload(digest, &row.body).await?;
        let entity = digest.to_hex();
        payload.verify_bundle_bytes(&bytes)?;
        bucket
            .put(payload.object_key(), bytes)
            .only_if(Conditional {
                etag_does_not_match: Some("*".into()),
                ..Conditional::default()
            })
            .execute()
            .await?;
        self.read_payload_object(bucket, &payload).await?;
        if row.state == "retained" {
            return Ok(payload);
        }
        let result = self
            .atomic(
                vec![self.statement(
                    include_str!("../../sql/work/retain-candidate-payload.sql"),
                    &[text(&digest.to_hex()), text(&row.body)],
                )?],
                payload_audit(
                    &payload,
                    &entity,
                    "candidate.payload.retain",
                    2,
                    Some("reserved"),
                    Some("retained"),
                ),
                vec![],
            )
            .await;
        let current = self.payload_row(digest).await?;
        if current.body == row.body && current.state == "retained" {
            return Ok(payload);
        }
        result?;
        Err(Denied::Conflict.into())
    }
    /// Trusted maintenance/adoption adapter only. Historical payload remains
    /// usable without reactivating the producer; owner download is not mounted.
    pub async fn candidate_payload_bytes(
        &self,
        bucket: &Bucket,
        digest: Digest,
    ) -> Result<Vec<u8>> {
        let row = self.payload_row(digest).await?;
        if row.state != "retained" {
            return Err(Denied::StaleAuthority.into());
        }
        let payload = self.restore_payload(digest, &row.body).await?;
        self.read_payload_object(bucket, &payload).await
    }
    pub(super) async fn preparation_has_candidates(&self, id: &str) -> Result<bool> {
        // Only historical pre-0054 fixtures omit this schema; no product fallback.
        #[cfg(feature="work-qualification")]
        if self.statement("SELECT name FROM sqlite_master WHERE type='table' AND name='work_candidate_payload'",&[])?.first::<String>(Some("name")).await?.is_none() { return Ok(false); }
        Ok(self.statement("SELECT c.digest FROM work_candidate c JOIN work_request_preparation r ON r.request_digest=c.request_digest JOIN work_prepared_task t ON t.repository_id=r.repository_id WHERE t.preparation_id=?1 LIMIT 1",&[text(id)])?.first::<String>(Some("digest")).await?.is_some())
    }
    /// Call before remote repo deletion, and again before reporting completion.
    /// Cleanup already fences new candidates; immutable associations fix this set.
    pub async fn cleanup_candidate_payloads(
        &self,
        bucket: &Bucket,
        id: &str,
    ) -> Result<Vec<CandidatePayload>> {
        let p = self.preparation(id).await?;
        if !matches!(
            p.state(),
            PreparationState::CleanupPending | PreparationState::Cleaned
        ) {
            return Err(Denied::InvalidTransition.into());
        }
        let candidates=self.statement("SELECT c.digest FROM work_candidate c JOIN work_request_preparation r ON r.request_digest=c.request_digest JOIN work_prepared_task t ON t.repository_id=r.repository_id WHERE t.preparation_id=?1 ORDER BY c.digest LIMIT 17",&[text(id)])?.all().await?.results::<CandidateId>()?;
        if candidates.len() > 16 {
            return Err(Denied::CapacityExceeded.into());
        }
        let mut retained = Vec::new();
        for c in candidates {
            let digest = Digest::parse_hex(&c.digest)?;
            let row = self.payload_row(digest).await?;
            if row.state != "retained" {
                return Err(Denied::StaleAuthority.into());
            }
            let payload = self.restore_payload(digest, &row.body).await?;
            self.read_payload_object(bucket, &payload).await?;
            retained.push(payload);
        }
        Ok(retained)
    }
    pub async fn confirm_preparation_cleaned_with_payloads(
        &self,
        bucket: &Bucket,
        id: &str,
        receipt: Digest,
    ) -> Result<Preparation> {
        self.cleanup_candidate_payloads(bucket, id).await?;
        self.commit_preparation_cleaned(id, receipt).await
    }
}
fn payload_audit<'a>(
    p: &'a CandidatePayload,
    entity: &'a str,
    action: &'a str,
    revision: u64,
    from: Option<&'a str>,
    to: Option<&'a str>,
) -> Audit<'a> {
    Audit {
        owner: p.owner_id(),
        kind: "candidate_payload",
        entity,
        actor: "op-work-payloads",
        action,
        revision,
        before: from,
        after: to,
        receipt: None,
    }
}
