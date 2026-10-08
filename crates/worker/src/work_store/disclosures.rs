use super::*;

impl WorkStore {
    /// No HTTP upload: Git bytes/history were independently verified by the
    /// trusted adapter; logical repository IDs now resolve only through OP ACLs.
    pub async fn bind_disclosure_sources(
        &self,
        session_hash: &str,
        disclosure: ResolvedDisclosure,
    ) -> Result<ResolvedDisclosure> {
        let owner = self.owner(session_hash).await?;
        if owner.owner_id() != disclosure.owner_id() {
            return Err(Denied::OwnerMismatch.into());
        }
        let mut sources = Vec::new();
        for id in disclosure.source_ids() {
            sources.push(self.owner_source(session_hash, id).await?);
        }
        let facts: Vec<_> = sources.iter().map(OwnerSource::disclosure_fact).collect();
        Ok(disclosure.bind_registered_sources(&facts, Digest::parse_hex(&owner.projection)?)?)
    }
    /// Qualified Git adapter input only; no owner HTTP endpoint accepts a
    /// manifest/upload as proof of source authorization or object verification.
    pub async fn save_disclosure(
        &self,
        session_hash: &str,
        disclosure: &ResolvedDisclosure,
    ) -> Result<ResolvedDisclosure> {
        disclosure.require_registered_sources()?;
        let owner = self.owner(session_hash).await?;
        // Reuse the request association checks without trusting body owner facts.
        if owner.owner_id() != disclosure.owner_id() {
            return Err(Denied::OwnerMismatch.into());
        }
        let body = disclosure.authority_record()?;
        let digest = disclosure.digest().to_hex();
        self.put(
            "SELECT body FROM work_disclosure WHERE digest=?1",
            &digest,
            &body,
            vec![
                self.statement(
                    include_str!("../../sql/work/reserve-disclosure-window.sql"),
                    &[text(owner.owner_id())],
                )?,
                self.statement(
                    include_str!("../../sql/work/save-disclosure.sql"),
                    &[text(&body), text(&owner.projection), text(session_hash)],
                )?,
            ],
            owner_audit(
                owner.owner_id(),
                "disclosure",
                &digest,
                "disclosure.reserve",
                1,
            ),
        )
        .await?;
        self.disclosure(disclosure.digest()).await
    }

    pub async fn disclosure(&self, digest: Digest) -> Result<ResolvedDisclosure> {
        let row: ImmutableRow = self
            .first(
                "SELECT body FROM work_disclosure WHERE digest=?1",
                &[text(&digest.to_hex())],
            )
            .await?;
        let disclosure = ResolvedDisclosure::restore_authority_record(&row.body)?;
        if disclosure.digest() != digest {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(disclosure)
    }

    /// The only product request creation capability. D1 binding predicates repeat
    /// the exact owner/epoch/policy/code/recipient/workload/deadline association.
    pub async fn save_resolved_request(
        &self,
        session_hash: &str,
        request: &WorkRequest,
    ) -> Result<WorkRequest> {
        let disclosure = self
            .disclosure(Digest::parse_hex(&request.input().disclosure_digest)?)
            .await?;
        disclosure.require_registered_sources()?;
        self.confirm_disclosure_sources(disclosure.digest()).await?;
        let preparation_id = self.prepared_request_id(request).await?;
        self.save_request_with_binding(
            session_hash,
            request,
            Some(&disclosure),
            Some(&preparation_id),
        )
        .await
    }

    /// Older disclosure-only cases deliberately exercise pre-0052 fixtures.
    /// This capability is absent from the production build.
    #[cfg(feature = "work-qualification")]
    pub async fn save_qualified_disclosure_request(
        &self,
        session_hash: &str,
        request: &WorkRequest,
    ) -> Result<WorkRequest> {
        let disclosure = self
            .disclosure(Digest::parse_hex(&request.input().disclosure_digest)?)
            .await?;
        disclosure.require_registered_sources()?;
        self.confirm_disclosure_sources(disclosure.digest()).await?;
        self.save_request_with_binding(session_hash, request, Some(&disclosure), None)
            .await
    }

    pub(super) async fn confirm_disclosure_sources(&self, digest: Digest) -> Result<()> {
        let found: Option<String> = self
            .statement(
                "SELECT digest FROM work_disclosure_source_current WHERE digest=?1",
                &[text(&digest.to_hex())],
            )?
            .first(Some("digest"))
            .await?;
        if found.is_none() {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(())
    }

    /// Existing legacy evidence is readable, but cannot issue new product grant
    /// or run authority. Only deliberately unbound local qualification rows are
    /// exempt; a bound v1 record never gets that exemption.
    pub(super) async fn registered_request_disclosure(
        &self,
        request: &WorkRequest,
    ) -> Result<Option<String>> {
        let digest: Option<String> = self.statement(
            "SELECT disclosure_digest FROM work_request_disclosure WHERE request_digest=?1 AND owner_id=?2",
            &[text(&request.digest().to_hex()), text(request.owner_id())],
        )?.first(Some("disclosure_digest")).await?;
        let Some(digest) = digest else {
            #[cfg(feature = "work-qualification")]
            return Ok(None);
            #[cfg(not(feature = "work-qualification"))]
            return Err(Denied::BindingMismatch.into());
        };
        if digest != request.input().disclosure_digest {
            return Err(Denied::BindingMismatch.into());
        }
        let disclosure = self.disclosure(Digest::parse_hex(&digest)?).await?;
        disclosure.require_registered_sources()?;
        self.confirm_disclosure_sources(disclosure.digest()).await?;
        Ok(Some(digest))
    }

    /// Only expired, unbound metadata is collectible. No Git repo/blob is erased
    /// here, and referenced producer/operation/manifest records are never deleted.
    pub async fn collect_disclosures(&self) -> Result<u64> {
        let statements=vec![
            self.db.prepare("DELETE FROM work_disclosure WHERE digest IN(SELECT d.digest FROM work_disclosure d JOIN work_resource_policy p ON p.id=1 \
             WHERE d.expires_at<=unixepoch()-p.orphan_retention_seconds AND NOT EXISTS(SELECT 1 FROM work_request_disclosure WHERE disclosure_digest=d.digest) \
             AND NOT EXISTS(SELECT 1 FROM work_preparation WHERE disclosure_digest=d.digest) ORDER BY d.expires_at,d.digest LIMIT 100)"),
            self.db.prepare("DELETE FROM work_disclosure_window WHERE (owner_id,window_start) IN(SELECT owner_id,window_start FROM work_disclosure_window \
             WHERE window_start<unixepoch()-86400 ORDER BY window_start,owner_id LIMIT 100)"),
            self.db.prepare("DELETE FROM work_preparation_window WHERE (owner_id,window_start) IN(SELECT owner_id,window_start FROM work_preparation_window \
             WHERE window_start<unixepoch()-86400 ORDER BY window_start,owner_id LIMIT 100)")];
        let results = if self.checkpoint.is_some() || self.checkpoint_enrolled().await? {
            self.checkpoint_batch(statements).await?
        } else {
            self.db.batch(statements).await?
        };
        Ok(results
            .iter()
            .filter_map(|r| r.meta().ok().flatten())
            .map(|m| m.changes.unwrap_or_default() as u64)
            .sum())
    }
}
