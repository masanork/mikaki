//! Owner selection is a request for metadata preparation, never Git proof or
//! external copy authority. Destination and recipient mappings are operator-owned.
use super::*;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationCodeSelection {
    source_id: String,
    source_revision: u64,
    access_revision: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationComposeInput {
    format_version: u8,
    code: PreparationCodeSelection,
    contexts: Vec<SourceReadInput>,
    expires_at: u64,
}
impl WorkStore {
    pub async fn compose_preparation(
        &self,
        env: &worker::Env,
        session: &str,
        i: PreparationComposeInput,
    ) -> Result<Value> {
        if i.format_version != 1
            || i.contexts.len() > 4
            || i.contexts.iter().map(|c| c.paths.len()).sum::<usize>() > 32
            || !i
                .contexts
                .windows(2)
                .all(|w| w[0].source_id < w[1].source_id)
            || !owner_id_shape(&i.code.source_id)
        {
            return Err(Denied::InvalidInput.into());
        }
        // Validate fixed mapping before private source I/O or any reservation.
        let namespace = env.var("WORK_ARTIFACTS_NAMESPACE")?.to_string();
        let recipient = env.var("WORK_COPY_RECIPIENT")?.to_string();
        let workload = env.var("WORK_COPY_WORKLOAD")?.to_string();
        if namespace.is_empty()
            || namespace.len() > 64
            || !namespace.as_bytes()[0].is_ascii_alphanumeric()
            || !namespace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
            || !owner_id_shape(&recipient)
            || !owner_id_shape(&workload)
        {
            return Err(Denied::InvalidInput.into());
        }
        copy_account(env)?;
        self.require_current_authority().await?;
        let owner = self.owner(session).await?;
        let code = self.owner_source(session, &i.code.source_id).await?;
        if code.registered().role() != "code"
            || i.expires_at <= now()
            || i.expires_at > now() + MAX_WORK_SECONDS
            || i.expires_at > owner.session().expires_at()
        {
            return Err(Denied::InvalidInput.into());
        }
        if code.registered().revision() != i.code.source_revision
            || code.access_revision() != i.code.access_revision
        {
            return Err(Denied::StaleAuthority.into());
        }
        let mut selected = Vec::new();
        for input in &i.contexts {
            selected.push(crate::work_sources::read_registered(self, env, session, input).await?);
        }
        self.confirm_source_read(session, &i.code.source_id, &code)
            .await?;
        for ((source, _), input) in selected.iter().zip(&i.contexts) {
            self.confirm_source_read(session, &input.source_id, source)
                .await?;
        }
        self.require_current_authority().await?;
        let verified = selected
            .iter()
            .zip(&i.contexts)
            .map(|((s, body), input)| s.registered().verify_selection(input, body))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        // Canonical closed selection + current owner/policy fixes this logical
        // snapshot ID. Exact lost replies cannot allocate another preparation.
        let mut h = Sha256::new();
        h.update(b"mikaki.work-owner-selection.v1\0");
        h.update(owner.owner_id().as_bytes());
        h.update(b"\0");
        h.update(owner.projection.as_bytes());
        let input = serde_json::to_vec(&i).map_err(|_| Denied::InvalidInput)?;
        h.update(&input);
        let mut request_digest = Sha256::new();
        request_digest.update(b"mikaki.work-owner-compose-input.v1\0");
        request_digest.update(&input);
        let request_digest = Digest::from_bytes(request_digest.finalize().into());
        let snapshot = format!(
            "snapshot-{}",
            Digest::from_bytes(h.finalize().into()).to_hex()
        );
        let d = ResolvedDisclosure::from_registered_selection(
            RegisteredDisclosureInput {
                code: code.registered(),
                code_access_revision: code.access_revision(),
                contexts: &verified,
                snapshot_repository: &snapshot,
                recipient: &recipient,
                workload: &workload,
                expires_at: i.expires_at,
                policy_projection: Digest::parse_hex(&owner.projection)?,
            },
            owner.session(),
            &owner.environment(),
        )?;
        // An unused expired reservation must not permanently hold the owner's
        // single-copy byte budget. Recheck session/state/obligations at commit.
        self.retire_owner_expired_reservations(session).await?;
        // Existing framed writes repeat all source/session/policy/budget guards.
        // A saved disclosure is safe retained metadata if reservation later fails.
        let d = self.save_disclosure(session, &d).await?;
        let task = format!("task-{}", d.digest().to_hex());
        let p = self
            .reserve_preparation(session, d.digest(), &task, &namespace, &namespace)
            .await?;
        // Reread with the live owner after the two durable commits before returning
        // an acknowledgement. This endpoint never approves or dispatches the copy.
        self.owner_record(session, OwnerRecordKind::Preparation, p.id())
            .await?;
        Ok(
            json!({"request_digest":request_digest,"preparation_id":p.id(),"preparation_digest":p.digest(),
            "disclosure_digest":d.digest(),"expires_at":p.expires_at()}),
        )
    }
}
