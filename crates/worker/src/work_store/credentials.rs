//! Named private service journal. No public owner/actor/broker endpoint.
use super::*;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// Operator-provisioned secret bindings and an external key-version floor.
/// Missing/changed material fails closed; the wrapping key never comes from DTOs.
pub fn credential_key(env: &worker::Env, version: u64) -> Result<WrappingKey> {
    let floor = env
        .var("WORK_CREDENTIAL_KEY_FLOOR")
        .map_err(|_| Denied::StaleAuthority)?
        .to_string()
        .parse::<u64>()
        .map_err(|_| Denied::InvalidInput)?;
    if floor == 0 || version < floor || version > MAX_STORED_INTEGER {
        return Err(Denied::StaleAuthority.into());
    }
    let secret = Zeroizing::new(
        env.secret(&format!("WORK_CREDENTIAL_KEY_V{version}"))
            .map_err(|_| Denied::StaleAuthority)?
            .to_string(),
    );
    Ok(WrappingKey::from_service_secret(version, &secret)?)
}
#[derive(Deserialize, serde::Serialize)]
pub struct CredentialKeyStatus {
    version: u64,
    fingerprint: String,
    state: String,
}
#[derive(Deserialize)]
struct CredentialRow {
    body: String,
    state: String,
    revision: u64,
    dispatched: u8,
    observation: Option<String>,
    key_version: Option<u64>,
    envelope: Option<String>,
    confirmation: Option<String>,
    receipt: Option<String>,
}
const FIELDS: &str =
    "body,state,revision,dispatched,observation,key_version,envelope,confirmation,receipt";
pub enum CredentialDispatch {
    Started(CredentialAttempt),
    Existing(CredentialStatus),
}
#[derive(serde::Serialize)]
pub struct CredentialStatus {
    pub id: String,
    pub state: String,
    pub revision: u64,
}
/// Closed Native facts for the private preparation verifier. No envelope/key
/// material is exposed, and historical evidence needs no decryption capability.
pub(crate) struct ClosedCredential {
    pub attempt: CredentialAttempt,
    pub observation: CredentialObservation,
    pub receipt: Digest,
    pub key_version: Option<u64>,
    pub key_fingerprint: Option<Digest>,
}
impl CredentialRow {
    fn status(&self, a: &CredentialAttempt) -> CredentialStatus {
        CredentialStatus {
            id: a.id().into(),
            state: self.state.clone(),
            revision: self.revision,
        }
    }
}
impl WorkStore {
    pub async fn credential_key_status(&self, version: u64) -> Result<Option<CredentialKeyStatus>> {
        self.current_authority_checkpoint().await?;
        let status = self
            .statement(
                "SELECT version,fingerprint,state FROM work_credential_key WHERE version=?1",
                &[number(version)?],
            )?
            .first::<CredentialKeyStatus>(None)
            .await?;
        self.current_authority_checkpoint().await?;
        Ok(status)
    }

    /// Initial operator activation only. An existing key is never rotated or
    /// retired by this capability; an exact retry reads the original result.
    pub async fn initialize_credential_key(&self, key: &WrappingKey) -> Result<()> {
        self.current_authority_checkpoint().await?;
        if self.check_key(key, true).await.is_ok() {
            return Ok(());
        }
        let guard = opaque()?;
        let result = self
            .checkpoint_batch(vec![
                self.statement(
                    "INSERT INTO work_credential_key(version,fingerprint,state) SELECT ?1,?2,'active' WHERE NOT EXISTS(SELECT 1 FROM work_credential_key)",
                    &[number(key.version())?, text(&key.fingerprint().to_hex())],
                )?,
                self.statement(include_str!("../../sql/work/guard.sql"), &[text(&guard)])?,
                self.statement(
                    "INSERT INTO work_credential_key_audit VALUES(?1,?2,'active',unixepoch())",
                    &[text(&opaque()?), number(key.version())?],
                )?,
                self.statement("DELETE FROM work_transition_guard WHERE guard_id=?1", &[text(&guard)])?,
            ])
            .await;
        if self.check_key(key, true).await.is_ok() {
            self.current_authority_checkpoint().await?;
            return Ok(());
        }
        result?;
        Err(Denied::Conflict.into())
    }

    pub(super) async fn check_copy_key(&self, key: &WrappingKey) -> Result<()> {
        self.check_key(key, true).await
    }
    pub(super) async fn copy_slot(
        &self,
        preparation: &str,
        role: CredentialRole,
        purpose: CredentialPurpose,
    ) -> Result<CredentialStatus> {
        let row: CredentialRow = self.first(&format!("SELECT {FIELDS} FROM work_credential_attempt WHERE preparation_id=?1 AND role=?2 AND purpose=?3"), &[text(preparation), text(role.name()), text(purpose.name())]).await?;
        let attempt = self.credential_attempt(&row).await?;
        Ok(row.status(&attempt))
    }
    pub(crate) async fn closed_preparation_credentials(
        &self,
        preparation_id: &str,
    ) -> Result<Vec<ClosedCredential>> {
        let p = self.preparation(preparation_id).await?;
        let rows = self.statement(&format!("SELECT {FIELDS} FROM work_credential_attempt WHERE preparation_id=?1 ORDER BY role,purpose LIMIT 7"), &[text(preparation_id)])?.all().await?.results::<CredentialRow>()?;
        if rows.len() != 6 {
            return Err(Denied::StaleAuthority.into());
        }
        let mut facts = Vec::with_capacity(6);
        for row in rows {
            if row.state != "closed"
                || row.confirmation.as_deref() != Some("refused")
                || row.envelope.is_some()
                || row.dispatched != 1
            {
                return Err(Denied::StaleAuthority.into());
            }
            let a = CredentialAttempt::restore_authority_record(&row.body, &p)?;
            let observation = CredentialObservation::restore_authority_record(
                row.observation.as_deref().ok_or(Denied::BindingMismatch)?,
                &a,
            )?;
            let key_fingerprint = if a.purpose() == CredentialPurpose::Initial {
                None
            } else {
                let version = row.key_version.ok_or(Denied::BindingMismatch)?;
                let key: CredentialKeyStatus = self.first(
                    "SELECT version,fingerprint,state FROM work_credential_key WHERE version=?1",
                    &[number(version)?],
                ).await?;
                Some(Digest::parse_hex(&key.fingerprint)?)
            };
            facts.push(ClosedCredential {
                attempt: a,
                observation,
                receipt: Digest::parse_hex(row.receipt.as_deref().ok_or(Denied::BindingMismatch)?)?,
                key_version: row.key_version,
                key_fingerprint,
            });
        }
        Ok(facts)
    }
    /// Safety-only capture/closure. Even idempotent acknowledgements bind all
    /// observed metadata; no productive secret is accepted or decrypted.
    pub async fn capture_initial_effect_closed(
        &self,
        id: &str,
        observation: &CredentialObservation,
        receipt: Digest,
    ) -> Result<CredentialStatus> {
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        if a.purpose() != CredentialPurpose::Initial || a.expected_repo_id().is_some() {
            return Err(Denied::BindingMismatch.into());
        }
        if row.state == "closed" {
            if row.observation.as_deref() != Some(&observation.authority_record()?) {
                return Err(Denied::BindingMismatch.into());
            }
        } else {
            self.capture_credential(id, observation, None, None).await?;
        }
        self.confirm_credential_closed(id, "refused", receipt).await
    }
    /// Fixed initial-create adapter. Storage dispatch is not an external permit:
    /// the separately owned effect ledger must admit this exact checkpoint.
    pub async fn initial_effect_plan(
        &self,
        env: &worker::Env,
        id: &str,
    ) -> Result<serde_json::Value> {
        self.current_authority_checkpoint().await?;
        let a = self.credential_plan(id).await?;
        if a.purpose() != CredentialPurpose::Initial || a.expected_repo_id().is_some() {
            return Err(Denied::BindingMismatch.into());
        }
        self.require_copy_consent(a.preparation_id(), Some(&copy_account(env)?))
            .await?;
        let version = self
            .statement(
                "SELECT version FROM work_credential_key WHERE state='active'",
                &[],
            )?
            .first::<u64>(Some("version"))
            .await?
            .ok_or(Denied::StaleAuthority)?;
        let key = credential_key(env, version)?;
        self.check_key(&key, true).await?;
        self.dispatch_credential(id, &key).await?;
        let row = self.credential_row(id).await?;
        if row.state != "dispatched" || row.dispatched != 1 {
            return Err(Denied::InvalidTransition.into());
        }
        let checkpoint = self.current_authority_checkpoint().await?;
        self.check_key(&key, true).await?;
        let p = self.preparation(a.preparation_id()).await?;
        if self
            .statement(
                include_str!("../../sql/work/credential-capture-current.sql"),
                &[text(p.id())],
            )?
            .first::<String>(Some("operation_id"))
            .await?
            .is_none()
        {
            return Err(Denied::StaleAuthority.into());
        }
        let (namespace, name) = p.credential_destination(a.role());
        self.require_copy_consent(p.id(), Some(&copy_account(env)?))
            .await?;
        if checkpoint != self.current_authority_checkpoint().await? {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(
            serde_json::json!({"format_version":1,"effect":"repo.create","attempt_id":a.id(),
            "digest":a.digest().to_hex(),"namespace":namespace,"name":name,"role":a.role().name(),
            "deadline":a.deadline(),"checkpoint":checkpoint,"artifacts_account":copy_account(env)?}),
        )
    }
    /// Private OP adapter metadata for the same unknown/captured attempt. This
    /// read never returns a dispatch permit or a credential.
    pub async fn credential_plan(&self, id: &str) -> Result<CredentialAttempt> {
        self.credential_attempt(&self.credential_row(id).await?)
            .await
    }
    /// Fixed mint plan. Only a closed initial credential can establish the
    /// destination; the independent ledger separately checks its own closure.
    pub async fn mint_effect_plan(&self, env: &worker::Env, id: &str) -> Result<serde_json::Value> {
        self.current_authority_checkpoint().await?;
        let a = self.credential_plan(id).await?;
        if a.purpose() == CredentialPurpose::Initial || a.expected_repo_id().is_none() {
            return Err(Denied::BindingMismatch.into());
        }
        self.require_copy_consent(a.preparation_id(), Some(&copy_account(env)?))
            .await?;
        let initial_id = self.statement(
            "SELECT attempt_id FROM work_credential_attempt WHERE preparation_id=?1 AND role=?2 AND purpose='initial' AND state='closed' AND confirmation='refused' AND json_extract(observation,'$.data.repo_id')=?3",
            &[text(a.preparation_id()), text(a.role().name()), text(a.expected_repo_id().unwrap_or_default())],
        )?.first::<String>(Some("attempt_id")).await?.ok_or(Denied::BindingMismatch)?;
        let version = self
            .statement(
                "SELECT version FROM work_credential_key WHERE state='active'",
                &[],
            )?
            .first::<u64>(Some("version"))
            .await?
            .ok_or(Denied::StaleAuthority)?;
        let key = credential_key(env, version)?;
        self.check_key(&key, true).await?;
        self.dispatch_credential(id, &key).await?;
        let row = self.credential_row(id).await?;
        if row.state != "dispatched" || row.dispatched != 1 {
            return Err(Denied::InvalidTransition.into());
        }
        let checkpoint = self.current_authority_checkpoint().await?;
        self.check_key(&key, true).await?;
        let p = self.preparation(a.preparation_id()).await?;
        if self
            .statement(
                include_str!("../../sql/work/credential-capture-current.sql"),
                &[text(p.id())],
            )?
            .first::<String>(Some("operation_id"))
            .await?
            .is_none()
        {
            return Err(Denied::StaleAuthority.into());
        }
        let (namespace, name) = p.credential_destination(a.role());
        self.require_copy_consent(p.id(), Some(&copy_account(env)?))
            .await?;
        if checkpoint != self.current_authority_checkpoint().await? {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(
            serde_json::json!({"format_version":1,"effect":"token.mint","attempt_id":a.id(),
            "digest":a.digest().to_hex(),"namespace":namespace,"name":name,"role":a.role().name(),
            "purpose":a.purpose().name(),"scope":if a.purpose()==CredentialPurpose::Readback {"read"} else {"write"},
            "repo_id":a.expected_repo_id(),"initial_attempt_id":initial_id,"deadline":a.deadline(),
            "expires_at":a.deadline().min((js_sys::Date::now() / 1000.0) as u64 + 300),
            "key_version":version,"key_fingerprint":key.fingerprint().to_hex(),"checkpoint":checkpoint,"artifacts_account":copy_account(env)?}),
        )
    }
    pub async fn capture_mint_effect_closed(
        &self,
        id: &str,
        observation: &CredentialObservation,
        receipt: Digest,
    ) -> Result<CredentialStatus> {
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        if a.purpose() == CredentialPurpose::Initial {
            return Err(Denied::BindingMismatch.into());
        }
        if row.state == "closed" {
            if row.observation.as_deref() != Some(&observation.authority_record()?) {
                return Err(Denied::BindingMismatch.into());
            }
        } else {
            // Preserve the same known metadata if an earlier encrypted capture succeeded.
            self.capture_credential(id, observation, None, None).await?;
            self.require_credential_revocation(id).await?;
        }
        self.confirm_credential_closed(id, "refused", receipt).await
    }
    async fn credential_row(&self, id: &str) -> Result<CredentialRow> {
        if !owner_id_shape(id) {
            return Err(Denied::InvalidInput.into());
        }
        self.first(
            &format!("SELECT {FIELDS} FROM work_credential_attempt WHERE attempt_id=?1"),
            &[text(id)],
        )
        .await
    }
    async fn credential_attempt(&self, row: &CredentialRow) -> Result<CredentialAttempt> {
        #[derive(Deserialize)]
        struct Binding {
            preparation_id: String,
        }
        // The immutable primary row supplies the preparation ID, not JSON caller claims.
        let id: Binding = self
            .first(
                "SELECT preparation_id FROM work_credential_attempt WHERE body=?1",
                &[text(&row.body)],
            )
            .await?;
        Ok(CredentialAttempt::restore_authority_record(
            &row.body,
            &self.preparation(&id.preparation_id).await?,
        )?)
    }
    pub async fn credential_status(&self, id: &str) -> Result<CredentialStatus> {
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        Ok(row.status(&a))
    }
    /// Fixed private Git plan, derived from a current registered disclosure.
    /// No caller-selected ref, destination, plaintext or transport request.
    pub async fn git_effect_plan(&self, env: &worker::Env, id: &str) -> Result<serde_json::Value> {
        let checkpoint = self.current_authority_checkpoint().await?;
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        let p = self.preparation(a.preparation_id()).await?;
        if a.purpose() == CredentialPurpose::Initial
            || row.state != "captured"
            || row.envelope.is_none()
        {
            return Err(Denied::StaleAuthority.into());
        }
        self.require_copy_consent(p.id(), Some(&copy_account(env)?))
            .await?;
        let version = row.key_version.ok_or(Denied::BindingMismatch)?;
        let key = credential_key(env, version)?;
        self.check_key(&key, true).await?;
        let o = CredentialObservation::restore_authority_record(
            row.observation.as_deref().ok_or(Denied::BindingMismatch)?,
            &a,
        )?;
        if o.scope() != a.purpose().scope()
            || o.expires_at()
                .is_none_or(|expiry| expiry <= js_sys::Date::now() as u64 / 1000 + 5)
        {
            return Err(Denied::Expired.into());
        }
        if self
            .statement(
                include_str!("../../sql/work/credential-capture-current.sql"),
                &[text(p.id())],
            )?
            .first::<String>(Some("operation_id"))
            .await?
            .is_none()
        {
            return Err(Denied::StaleAuthority.into());
        }
        let initial_id = self.statement(
            "SELECT attempt_id FROM work_credential_attempt WHERE preparation_id=?1 AND role=?2 AND purpose='initial' AND state='closed' AND confirmation='refused' AND json_extract(observation,'$.data.repo_id')=?3",
            &[text(p.id()),text(a.role().name()),text(o.repo_id())],
        )?.first::<String>(Some("attempt_id")).await?.ok_or(Denied::BindingMismatch)?;
        let d = self.disclosure(p.disclosure_digest()).await?;
        let data = serde_json::to_value(d.review()).map_err(|_| Denied::InvalidInput)?;
        let role = if a.role().name() == "task" {
            "code"
        } else {
            "snapshot"
        };
        let commit = data[role]["commit"]
            .as_str()
            .ok_or(Denied::BindingMismatch)?;
        let tree = data[role]["tree"].as_str().ok_or(Denied::BindingMismatch)?;
        if commit.len() != 40 || tree.len() != 40 {
            return Err(Denied::InvalidInput.into());
        }
        let (namespace, name) = p.credential_destination(a.role());
        self.require_copy_consent(p.id(), Some(&copy_account(env)?))
            .await?;
        if checkpoint != self.current_authority_checkpoint().await? {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(
            serde_json::json!({"format_version":1,"effect":if a.purpose()==CredentialPurpose::Upload {"git.upload"} else {"git.readback"},
          "attempt_id":a.id(),"digest":a.digest().to_hex(),"namespace":namespace,"name":name,"role":a.role().name(),
          "purpose":a.purpose().name(),"scope":if a.purpose()==CredentialPurpose::Upload {"write"} else {"read"},
          "repo_id":o.repo_id(),"initial_attempt_id":initial_id,"deadline":a.deadline(),"key_version":version,
          "key_fingerprint":key.fingerprint().to_hex(),"checkpoint":checkpoint,"preparation_digest":p.digest().to_hex(),
          "disclosure_digest":p.disclosure_digest().to_hex(),"commit":commit,"tree":tree,"artifacts_account":copy_account(env)?,
          "branch":if a.role().name()=="task" {"work"} else {"snapshot"},
          "observation":{"repo_id":o.repo_id(),"token_id":o.token_id(),"scope":o.scope(),"expires_at":o.expires_at()}}),
        )
    }
    /// Productive decryption is private to the one-shot Git executor. It repeats
    /// live owner/source/policy/key and captured-row checks around decryption.
    pub async fn credential_for_git(
        &self,
        env: &worker::Env,
        id: &str,
        plan: &serde_json::Value,
    ) -> Result<CredentialSecret> {
        if self.git_effect_plan(env, id).await? != *plan {
            return Err(Denied::StaleAuthority.into());
        }
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        let key = credential_key(env, row.key_version.ok_or(Denied::BindingMismatch)?)?;
        let secret = self.decrypt_row(&row, &a, &key).await?;
        if self.git_effect_plan(env, id).await? != *plan {
            return Err(Denied::StaleAuthority.into());
        }
        let current = self.credential_row(id).await?;
        if current.revision != row.revision || current.envelope != row.envelope {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(secret)
    }
    /// Metadata-only acknowledgement, not decryption or productive release.
    pub async fn mint_custody_status(
        &self,
        id: &str,
        observation: &CredentialObservation,
        key_version: u64,
    ) -> Result<CredentialStatus> {
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        if a.purpose() == CredentialPurpose::Initial
            || row.observation.as_deref() != Some(&observation.authority_record()?)
            || row.key_version != Some(key_version)
            || (row.state == "captured" && row.envelope.is_none())
        {
            return Err(Denied::BindingMismatch.into());
        }
        Ok(row.status(&a))
    }
    /// Bounded restart discovery, including lost reservation replies. No key or
    /// owner login is needed to find the six retained maintenance obligations.
    pub async fn credential_attempts(&self, preparation_id: &str) -> Result<Vec<CredentialStatus>> {
        let p = self.preparation(preparation_id).await?;
        let rows = self.statement(&format!("SELECT {FIELDS} FROM work_credential_attempt WHERE preparation_id=?1 ORDER BY role,purpose LIMIT 7"), &[text(preparation_id)])?.all().await?.results::<CredentialRow>()?;
        if rows.len() > 6 {
            return Err(Denied::BindingMismatch.into());
        }
        rows.into_iter()
            .map(|row| {
                let a = CredentialAttempt::restore_authority_record(&row.body, &p)?;
                Ok(row.status(&a))
            })
            .collect()
    }
    /// Private maintenance handles remain available when a key is missing.
    /// These observations are not owner DTOs, fresh issuance or proof of refusal.
    pub async fn credential_cleanup_observation(
        &self,
        id: &str,
    ) -> Result<Option<CredentialObservation>> {
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        if !matches!(row.state.as_str(), "revocation_pending" | "closed") {
            return Err(Denied::InvalidTransition.into());
        }
        row.observation
            .as_deref()
            .map(|body| {
                CredentialObservation::restore_authority_record(body, &a).map_err(StoreError::from)
            })
            .transpose()
    }
    async fn check_key(&self, key: &WrappingKey, active: bool) -> Result<()> {
        let row: CredentialKeyStatus = self
            .first(
                "SELECT version,fingerprint,state FROM work_credential_key WHERE version=?1",
                &[number(key.version())?],
            )
            .await?;
        if row.fingerprint != key.fingerprint().to_hex()
            || row.state == "retired"
            || (active && row.state != "active")
        {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(())
    }
    pub async fn activate_credential_key(&self, key: &WrappingKey) -> Result<()> {
        let existing = self
            .statement(
                "SELECT version,fingerprint,state FROM work_credential_key WHERE version=?1",
                &[number(key.version())?],
            )?
            .first::<CredentialKeyStatus>(None)
            .await?;
        if let Some(row) = existing {
            if row.fingerprint == key.fingerprint().to_hex() && row.state == "active" {
                return Ok(());
            }
            return Err(Denied::Conflict.into());
        }
        let current = self
            .statement(
                "SELECT version,fingerprint,state FROM work_credential_key WHERE state='active'",
                &[],
            )?
            .first::<CredentialKeyStatus>(None)
            .await?;
        let old = current.as_ref().map_or(0, |row| row.version);
        let guard = opaque()?;
        let mut steps=vec![self.statement("UPDATE work_credential_key SET state='decrypt_only' WHERE version=?1 AND state='active'",&[number(old)?])?];
        if old != 0 {
            steps.push(self.statement(
                "INSERT INTO work_credential_key_audit VALUES(?1,?2,'decrypt_only',unixepoch())",
                &[text(&opaque()?), number(old)?],
            )?);
        }
        steps.extend([
            self.statement("INSERT INTO work_credential_key(version,fingerprint,state) SELECT ?1,?2,'active' WHERE NOT EXISTS(SELECT 1 FROM work_credential_key WHERE state='active')",&[number(key.version())?,text(&key.fingerprint().to_hex())])?,
            self.statement(include_str!("../../sql/work/guard.sql"),&[text(&guard)])?,
            self.statement("INSERT INTO work_credential_key_audit VALUES(?1,?2,'active',unixepoch())",&[text(&opaque()?),number(key.version())?])?,
            self.statement("DELETE FROM work_transition_guard WHERE guard_id=?1",&[text(&guard)])?,
        ]);
        let result = self.checkpoint_batch(steps).await;
        if self.check_key(key, true).await.is_ok() {
            return Ok(());
        }
        result?;
        Err(Denied::Conflict.into())
    }
    pub async fn retire_credential_key(&self, key: &WrappingKey) -> Result<()> {
        let row: CredentialKeyStatus = self
            .first(
                "SELECT version,fingerprint,state FROM work_credential_key WHERE version=?1",
                &[number(key.version())?],
            )
            .await?;
        if row.fingerprint != key.fingerprint().to_hex() {
            return Err(Denied::BindingMismatch.into());
        }
        if row.state == "retired" {
            return Ok(());
        }
        let guard = opaque()?;
        self.checkpoint_batch(vec![
            self.statement("UPDATE work_credential_key SET state='retired' WHERE version=?1 AND state='decrypt_only'",&[number(key.version())?])?,
            self.statement(include_str!("../../sql/work/guard.sql"),&[text(&guard)])?,
            self.statement("INSERT INTO work_credential_key_audit VALUES(?1,?2,'retired',unixepoch())",&[text(&opaque()?),number(key.version())?])?,
            self.statement("DELETE FROM work_transition_guard WHERE guard_id=?1",&[text(&guard)])?,
        ]).await?;
        Ok(())
    }
    /// Six fixed slots per preparation. Closed/unknown slots are never replaced.
    pub async fn reserve_credential(
        &self,
        preparation_id: &str,
        role: CredentialRole,
        purpose: CredentialPurpose,
        key: &WrappingKey,
    ) -> Result<CredentialStatus> {
        let lookup = format!(
            "SELECT {FIELDS} FROM work_credential_attempt WHERE preparation_id=?1 AND role=?2 AND purpose=?3"
        );
        let values = [
            text(preparation_id),
            text(role.name()),
            text(purpose.name()),
        ];
        if let Some(row) = self
            .statement(&lookup, &values)?
            .first::<CredentialRow>(None)
            .await?
        {
            let a = self.credential_attempt(&row).await?;
            return Ok(row.status(&a));
        }
        self.check_key(key, true).await?;
        let p = self.preparation(preparation_id).await?;
        self.require_copy_consent(p.id(), None).await?;
        let repo = if purpose == CredentialPurpose::Initial {
            None
        } else {
            Some(self.statement("SELECT repo_id FROM work_preparation_repository WHERE preparation_id=?1 AND role=?2",&[text(preparation_id),text(role.name())])?.first::<String>(Some("repo_id")).await?.ok_or(Denied::BindingMismatch)?)
        };
        let a =
            CredentialAttempt::from_preparation(&p, &opaque()?, role, purpose, repo.as_deref())?;
        let body = a.authority_record()?;
        let result = self
            .atomic(
                vec![self.statement(
                    include_str!("../../sql/work/credential-reserve.sql"),
                    &[
                        text(a.id()),
                        text(&a.digest().to_hex()),
                        text(p.id()),
                        text(p.owner_id()),
                        text(role.name()),
                        text(purpose.name()),
                        text(&body),
                        number(key.version())?,
                        text(&key.fingerprint().to_hex()),
                    ],
                )?],
                custody_audit(
                    &p,
                    &a,
                    "credential.reserve",
                    1,
                    None,
                    Some("reserved"),
                    None,
                ),
                vec![],
            )
            .await;
        if let Some(row) = self
            .statement(&lookup, &values)?
            .first::<CredentialRow>(None)
            .await?
        {
            let actual = self.credential_attempt(&row).await?;
            return Ok(row.status(&actual));
        }
        result?;
        Err(Denied::Conflict.into())
    }
    pub async fn dispatch_credential(
        &self,
        id: &str,
        key: &WrappingKey,
    ) -> Result<CredentialDispatch> {
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        if row.state != "reserved" {
            return Ok(CredentialDispatch::Existing(row.status(&a)));
        }
        self.check_key(key, true).await?;
        let p = self.preparation(a.preparation_id()).await?;
        self.require_copy_consent(p.id(), None).await?;
        let result = self
            .atomic(
                vec![self.statement(
                    include_str!("../../sql/work/credential-dispatch.sql"),
                    &[
                        text(id),
                        number(row.revision)?,
                        number(key.version())?,
                        text(&key.fingerprint().to_hex()),
                    ],
                )?],
                custody_audit(
                    &p,
                    &a,
                    "credential.dispatch",
                    row.revision + 1,
                    Some("reserved"),
                    Some("dispatched"),
                    None,
                ),
                vec![],
            )
            .await;
        if result.is_ok() {
            return Ok(CredentialDispatch::Started(a));
        }
        let current = self.credential_row(id).await?;
        if current.state != "reserved" {
            return Ok(CredentialDispatch::Existing(current.status(&a)));
        }
        result?;
        Err(Denied::Conflict.into())
    }
    /// Capture a returned credential, or a recovered handle without plaintext.
    /// Outcome recording is allowed after owner/source loss; never new issuance.
    pub async fn capture_credential(
        &self,
        id: &str,
        o: &CredentialObservation,
        secret: Option<&CredentialSecret>,
        key: Option<&WrappingKey>,
    ) -> Result<CredentialStatus> {
        let result = self.capture_credential_once(id, o, secret, key).await;
        if matches!(result, Err(StoreError::Denied(Denied::StaleAuthority))) {
            // A cleanup/source fence may have changed during sealing. Preserve
            // the same returned result in the safety state; never repeat mint.
            return self.capture_credential_once(id, o, secret, key).await;
        }
        result
    }
    async fn capture_credential_once(
        &self,
        id: &str,
        o: &CredentialObservation,
        secret: Option<&CredentialSecret>,
        key: Option<&WrappingKey>,
    ) -> Result<CredentialStatus> {
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        let observed = CredentialObservation::restore_authority_record(&o.authority_record()?, &a)?;
        let observation = observed.authority_record()?;
        if row.state == "closed" || row.dispatched != 1 {
            return Err(Denied::InvalidTransition.into());
        }
        if let Some(existing) = &row.observation {
            if existing != &observation {
                return Err(Denied::Conflict.into());
            }
            if let Some(secret) = secret {
                let stored = self
                    .decrypt_row(&row, &a, key.ok_or(Denied::InvalidInput)?)
                    .await?;
                if !stored.matches(secret) {
                    return Err(Denied::Conflict.into());
                }
            }
            return Ok(row.status(&a));
        }
        let p = self.preparation(a.preparation_id()).await?;
        let envelope = if let Some(secret) = secret {
            let key = key.ok_or(Denied::InvalidInput)?;
            self.check_key(key, true).await?;
            let mut nonce = [0; 12];
            let crypto = js_sys::Reflect::get(&js_sys::global(), &text("crypto"))
                .map_err(worker::Error::from)?
                .dyn_into::<web_sys::Crypto>()
                .map_err(worker::Error::from)?;
            crypto
                .get_random_values_with_u8_array(&mut nonce)
                .map_err(worker::Error::from)?;
            Some(key.seal(&a, &observed, secret, nonce)?)
        } else {
            None
        };
        let key_version = if envelope.is_some() {
            number(key.ok_or(Denied::InvalidInput)?.version())?
        } else {
            JsValue::NULL
        };
        let state = if secret.is_some()
            && observed.scope() == a.purpose().scope()
            && row.state == "dispatched"
            && self
                .statement(
                    include_str!("../../sql/work/credential-capture-current.sql"),
                    &[text(p.id())],
                )?
                .first::<String>(Some("operation_id"))
                .await?
                .is_some()
        {
            "captured"
        } else {
            "revocation_pending"
        };
        let (namespace, name) = p.credential_destination(a.role());
        let repo=self.statement("SELECT repo_id FROM work_preparation_repository WHERE preparation_id=?1 AND role=?2",&[text(p.id()),text(a.role().name())])?.first::<String>(Some("repo_id")).await?;
        let mut mutations = vec![];
        if let Some(repo) = repo {
            if repo != observed.repo_id() {
                return Err(Denied::Conflict.into());
            }
        } else {
            mutations.push(self.statement(
                "INSERT INTO work_preparation_repository VALUES(?1,?2,?3,?4,?5)",
                &[
                    text(p.id()),
                    text(a.role().name()),
                    text(namespace),
                    text(name),
                    text(observed.repo_id()),
                ],
            )?);
        }
        mutations.push(self.statement(
            include_str!("../../sql/work/credential-capture.sql"),
            &[
                text(id),
                number(row.revision)?,
                text(state),
                text(&observation),
                key_version,
                nullable(envelope.as_deref()),
            ],
        )?);
        let result = self
            .atomic(
                mutations,
                custody_audit(
                    &p,
                    &a,
                    "credential.capture",
                    row.revision + 1,
                    Some(&row.state),
                    Some(state),
                    None,
                ),
                vec![],
            )
            .await;
        let current = self.credential_row(id).await?;
        if current.observation.as_deref() == Some(&observation) {
            if let Some(secret) = secret {
                let stored = self
                    .decrypt_row(&current, &a, key.ok_or(Denied::InvalidInput)?)
                    .await?;
                if !stored.matches(secret) {
                    return Err(Denied::Conflict.into());
                }
            }
            return Ok(current.status(&a));
        }
        result?;
        Err(Denied::Conflict.into())
    }
    async fn decrypt_row(
        &self,
        row: &CredentialRow,
        a: &CredentialAttempt,
        key: &WrappingKey,
    ) -> Result<CredentialSecret> {
        self.check_key(key, false).await?;
        if row.key_version != Some(key.version()) || row.state == "closed" {
            return Err(Denied::StaleAuthority.into());
        }
        let o = CredentialObservation::restore_authority_record(
            row.observation.as_deref().ok_or(Denied::BindingMismatch)?,
            a,
        )?;
        Ok(key.open(
            a,
            &o,
            row.envelope.as_deref().ok_or(Denied::BindingMismatch)?,
        )?)
    }
    /// Only cleanup recovery is exposed. A productive broker needs its own
    /// operation/dispatch guard; this is not a generic workload token getter.
    pub async fn credential_for_cleanup(
        &self,
        id: &str,
        key: &WrappingKey,
    ) -> Result<CredentialSecret> {
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        if row.state != "revocation_pending" {
            return Err(Denied::StaleAuthority.into());
        }
        let secret = self.decrypt_row(&row, &a, key).await?;
        // Decryption's key read is asynchronous. A closure during that interval
        // must not return a stale recovery result; this SELECT is the final
        // primary observation, not a promise to erase already in-flight bytes.
        let current = self.credential_row(id).await?;
        if current.state != "revocation_pending"
            || current.revision != row.revision
            || current.envelope != row.envelope
        {
            return Err(Denied::StaleAuthority.into());
        }
        Ok(secret)
    }
    pub async fn require_credential_revocation(&self, id: &str) -> Result<CredentialStatus> {
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        if matches!(row.state.as_str(), "revocation_pending" | "closed") {
            return Ok(row.status(&a));
        }
        let p = self.preparation(a.preparation_id()).await?;
        let result = self
            .atomic(
                vec![self.statement(
                    include_str!("../../sql/work/credential-revoke.sql"),
                    &[text(id), number(row.revision)?],
                )?],
                custody_audit(
                    &p,
                    &a,
                    "credential.revoke",
                    row.revision + 1,
                    Some(&row.state),
                    Some("revocation_pending"),
                    None,
                ),
                vec![],
            )
            .await;
        let current = self.credential_row(id).await?;
        if matches!(current.state.as_str(), "revocation_pending" | "closed") {
            return Ok(current.status(&a));
        }
        result?;
        Err(Denied::Conflict.into())
    }
    /// Only an independently observed refusal/expiry/non-issuance receipt can
    /// close an obligation. A timeout/clock/empty partial inventory cannot.
    pub async fn confirm_credential_closed(
        &self,
        id: &str,
        confirmation: &str,
        receipt: Digest,
    ) -> Result<CredentialStatus> {
        let row = self.credential_row(id).await?;
        let a = self.credential_attempt(&row).await?;
        if !matches!(confirmation, "refused" | "expired" | "not_issued")
            || (confirmation == "not_issued") != row.observation.is_none()
        {
            return Err(Denied::BindingMismatch.into());
        }
        let receipt = receipt.to_hex();
        if row.state == "closed" {
            if row.receipt.as_deref() == Some(&receipt)
                && row.confirmation.as_deref() == Some(confirmation)
            {
                return Ok(row.status(&a));
            }
            return Err(Denied::Conflict.into());
        }
        if row.state != "revocation_pending" {
            return Err(Denied::InvalidTransition.into());
        }
        let p = self.preparation(a.preparation_id()).await?;
        let result = self
            .atomic(
                vec![self.statement(
                    include_str!("../../sql/work/credential-close.sql"),
                    &[
                        text(id),
                        number(row.revision)?,
                        text(confirmation),
                        text(&receipt),
                    ],
                )?],
                custody_audit(
                    &p,
                    &a,
                    "credential.closed",
                    row.revision + 1,
                    Some("revocation_pending"),
                    Some("closed"),
                    Some(&receipt),
                ),
                vec![],
            )
            .await;
        let current = self.credential_row(id).await?;
        if current.state == "closed"
            && current.receipt.as_deref() == Some(&receipt)
            && current.confirmation.as_deref() == Some(confirmation)
        {
            return Ok(current.status(&a));
        }
        result?;
        Err(Denied::Conflict.into())
    }
    pub async fn credential_custody_receipt(&self, preparation_id: &str) -> Result<Digest> {
        #[derive(Deserialize)]
        struct Closed {
            body: String,
            observation: String,
            confirmation: String,
            receipt: String,
        }
        let rows = self
            .statement(
                include_str!("../../sql/work/credential-receipt.sql"),
                &[text(preparation_id)],
            )?
            .all()
            .await?
            .results::<Closed>()?;
        if rows.len() != 6 {
            return Err(Denied::StaleAuthority.into());
        }
        let p = self.preparation(preparation_id).await?;
        let mut hash = Sha256::new();
        let mut field = |v: &[u8]| {
            hash.update((v.len() as u64).to_be_bytes());
            hash.update(v);
        };
        field(b"mikaki.work-credential-receipt.v1");
        for row in rows {
            let a = CredentialAttempt::restore_authority_record(&row.body, &p)?;
            CredentialObservation::restore_authority_record(&row.observation, &a)?;
            Digest::parse_hex(&row.receipt)?;
            for v in [&row.body, &row.observation, &row.confirmation, &row.receipt] {
                field(v.as_bytes());
            }
        }
        Ok(Digest::from_bytes(hash.finalize().into()))
    }
}
fn custody_audit<'a>(
    p: &'a Preparation,
    a: &'a CredentialAttempt,
    action: &'a str,
    revision: u64,
    before: Option<&'a str>,
    after: Option<&'a str>,
    receipt: Option<&'a str>,
) -> Audit<'a> {
    Audit {
        owner: p.owner_id(),
        kind: "credential",
        entity: a.id(),
        action,
        actor: "op-work-custody",
        revision,
        before,
        after,
        receipt,
    }
}
