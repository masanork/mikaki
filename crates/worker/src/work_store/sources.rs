use super::*;
use serde_json::{Value, json};

#[derive(Deserialize)]
pub(super) struct SourceRow {
    body: String,
    access_revision: u64,
    generation: u64,
    projection_revision: String,
    account_id: String,
    epoch: u64,
}
pub struct OwnerSource {
    source: RegisteredSource,
    access_revision: u64,
    generation: u64,
    projection: String,
    body: String,
    owner_id: String,
    owner_epoch: u64,
}
impl OwnerSource {
    pub(super) fn registered(&self) -> &RegisteredSource {
        &self.source
    }
    pub(super) fn access_revision(&self) -> u64 {
        self.access_revision
    }
    pub(super) fn disclosure_fact(&self) -> (&RegisteredSource, u64) {
        (&self.source, self.access_revision)
    }
    pub fn service_request(&self, i: &SourceReadInput) -> Result<String> {
        if i.access_revision != self.access_revision || i.source_revision != self.source.revision()
        {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(self.source.service_request(i)?)
    }
    pub fn verify_reply(&self, i: &SourceReadInput, body: &str) -> Result<Value> {
        Ok(self.source.verify_reply(i, body)?)
    }
}
const JOIN: &str = "FROM work_source_access x JOIN authenticated_owner a ON a.account_id=x.owner_id AND a.epoch=x.owner_epoch \
 JOIN work_source_head h ON h.source_id=x.source_id AND h.active=1 \
 JOIN work_source_version v ON v.source_id=h.source_id AND v.source_revision=h.source_revision \
 JOIN runtime_policy_active p ON p.id=1 WHERE x.active=1";

impl WorkStore {
    /// 10 sources/page; each native receipt is <=32 KiB. No caller owns a repo
    /// because it supplied its name. The epoch/access/head predicates join live SSO.
    pub async fn owner_sources(&self, session_hash: &str, after: Option<&str>) -> Result<Value> {
        if after.is_some_and(|s| !owner_id_shape(s)) {
            return Err(Denied::InvalidInput.into());
        }
        self.require_current_authority().await?;
        let sql = format!(
            "SELECT v.body,x.access_revision,p.generation,p.projection_revision,a.account_id,a.epoch {JOIN} AND x.source_id>?2 ORDER BY x.source_id LIMIT 11"
        );
        let mut rows = self
            .owner_statement(session_hash, &sql, after.unwrap_or(""))?
            .all()
            .await?
            .results::<SourceRow>()?;
        let has_more = rows.len() > 10;
        rows.truncate(10);
        let mut sources = Vec::new();
        for row in rows {
            let source = RegisteredSource::restore_authority_record(&row.body)?;
            let mut metadata = source.metadata();
            metadata["access_revision"] = json!(row.access_revision);
            sources.push(metadata);
        }
        let after = if has_more {
            sources.last().and_then(|s| s.get("source_id")).cloned()
        } else {
            None
        };
        Ok(json!({"sources":sources,"next_after":after}))
    }
    pub async fn owner_source(&self, session_hash: &str, id: &str) -> Result<OwnerSource> {
        if !owner_id_shape(id) {
            return Err(Denied::InvalidInput.into());
        }
        let sql = format!(
            "SELECT v.body,x.access_revision,p.generation,p.projection_revision,a.account_id,a.epoch {JOIN} AND x.source_id=?2"
        );
        let row = self
            .owner_statement(session_hash, &sql, id)?
            .first::<SourceRow>(None)
            .await?
            .ok_or(StoreError::Denied(Denied::BindingMismatch))?;
        let source = RegisteredSource::restore_authority_record(&row.body)?;
        if source.id() != id {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(OwnerSource {
            source,
            access_revision: row.access_revision,
            generation: row.generation,
            projection: row.projection_revision,
            body: row.body,
            owner_id: row.account_id,
            owner_epoch: row.epoch,
        })
    }
    /// Permission may change while the service reads a blob. A primary SELECT
    /// repeats all live facts before owner plaintext can leave the OP.
    pub async fn confirm_source_read(
        &self,
        session_hash: &str,
        id: &str,
        expected: &OwnerSource,
    ) -> Result<()> {
        let current = self.owner_source(session_hash, id).await?;
        if current.body != expected.body
            || current.access_revision != expected.access_revision
            || current.generation != expected.generation
            || current.projection != expected.projection
            || current.owner_id != expected.owner_id
            || current.owner_epoch != expected.owner_epoch
        {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(())
    }
}
