//! OP-owned D1 managed-work authority. No HTTP, OAuth issuer or external effects.
//! Only trusted OP callers receive this capability; actor facts must be verified
//! by the selected launcher/requester/DPoP adapter before calling these methods.
mod checkpoint;
mod copy_consent;
mod credentials;
mod disclosures;
mod operations;
mod owner;
mod payloads;
mod preparations;
mod prepared_tasks;
mod read;
mod sources;
mod write;

use mikaki_auth::work::*;
use serde::Deserialize;
use wasm_bindgen::{JsCast, JsValue};
use worker::{D1Database, D1PreparedStatement};

pub use checkpoint::AuthorityCheckpoint;
pub use copy_consent::copy_account;
pub(crate) use credentials::ClosedCredential;
pub use credentials::{CredentialDispatch, CredentialStatus, credential_key};
pub use operations::{DispatchResult, Outcome};
pub(crate) use owner::owner_id_shape;
pub use owner::{OwnerRecordKind, OwnerRequestPage};
pub use preparations::PreparationDispatch;
pub use read::{OwnerContext, ProducerContext};
pub use sources::OwnerSource;

#[derive(Debug)]
pub enum StoreError {
    Denied(Denied),
    Storage(worker::Error),
}
pub type Result<T> = std::result::Result<T, StoreError>;
impl From<Denied> for StoreError {
    fn from(value: Denied) -> Self {
        Self::Denied(value)
    }
}
impl From<worker::Error> for StoreError {
    fn from(value: worker::Error) -> Self {
        Self::Storage(value)
    }
}
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(reason) => write!(f, "work_denied:{reason}"),
            Self::Storage(_) => f.write_str("work_storage_unavailable"),
        }
    }
}
impl std::error::Error for StoreError {}

/// Request-scoped capability. Direct D1Database queries use the primary (no
/// Sessions/read-replica opt-in); conditional batches repeat all live guards.
pub struct WorkStore {
    db: D1Database,
    checkpoint: Option<worker::Fetcher>,
}
impl WorkStore {
    pub fn new(db: D1Database) -> Self {
        Self {
            db,
            checkpoint: None,
        }
    }

    fn statement(&self, sql: &str, values: &[JsValue]) -> Result<D1PreparedStatement> {
        Ok(self.db.prepare(sql).bind(values)?)
    }

    async fn first<T: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        values: &[JsValue],
    ) -> Result<T> {
        self.statement(sql, values)?
            .first::<T>(None)
            .await?
            .ok_or(StoreError::Denied(Denied::BindingMismatch))
    }

    async fn atomic(
        &self,
        mutations: Vec<D1PreparedStatement>,
        audit: Audit<'_>,
        tail: Vec<D1PreparedStatement>,
    ) -> Result<()> {
        let mut statements = Vec::new();
        let mut guards = Vec::new();
        for mutation in mutations {
            statements.push(mutation);
            let guard = opaque()?;
            statements
                .push(self.statement(include_str!("../../sql/work/guard.sql"), &[text(&guard)])?);
            guards.push(guard);
        }
        statements.push(self.statement(
            include_str!("../../sql/work/audit.sql"),
            &[
                text(&opaque()?),
                text(audit.owner),
                text(audit.kind),
                text(audit.entity),
                text(audit.action),
                text(audit.actor),
                number(audit.revision)?,
                nullable(audit.before),
                nullable(audit.after),
                nullable(audit.receipt),
            ],
        )?);
        let guard = opaque()?;
        statements.push(self.statement(include_str!("../../sql/work/guard.sql"), &[text(&guard)])?);
        guards.push(guard);
        statements.extend(tail);
        for guard in guards {
            statements.push(self.statement(
                "DELETE FROM work_transition_guard WHERE guard_id=?1",
                &[text(&guard)],
            )?);
        }
        match self.checkpoint_batch(statements).await {
            Ok(_) => Ok(()),
            Err(StoreError::Storage(error))
                if error.to_string().contains("work_resource_exhausted") =>
            {
                Err(StoreError::Denied(Denied::CapacityExceeded))
            }
            Err(StoreError::Storage(error))
                if error.to_string().contains("work_guard_passed")
                    || error.to_string().contains("work_source_guard_failed")
                    || error.to_string().contains("work_preparation_guard_failed") =>
            {
                Err(StoreError::Denied(Denied::StaleAuthority))
            }
            Err(error) => Err(error),
        }
    }
}

struct Audit<'a> {
    owner: &'a str,
    kind: &'a str,
    entity: &'a str,
    action: &'a str,
    actor: &'a str,
    revision: u64,
    before: Option<&'a str>,
    after: Option<&'a str>,
    receipt: Option<&'a str>,
}

#[derive(Deserialize)]
struct ImmutableRow {
    body: String,
}
#[derive(Deserialize)]
struct RevocableRow {
    body: String,
    revision: u64,
    revoked: u8,
}

fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}
fn nullable(value: Option<&str>) -> JsValue {
    value.map_or(JsValue::NULL, text)
}
fn number(value: u64) -> Result<JsValue> {
    if value > MAX_STORED_INTEGER {
        return Err(Denied::InvalidInput.into());
    }
    Ok(JsValue::from_f64(value as f64))
}
fn now() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}

fn opaque() -> Result<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let value =
        js_sys::Reflect::get(&js_sys::global(), &text("crypto")).map_err(worker::Error::from)?;
    let crypto = value
        .dyn_into::<web_sys::Crypto>()
        .map_err(worker::Error::from)?;
    let mut bytes = [0; 32];
    crypto
        .get_random_values_with_u8_array(&mut bytes)
        .map_err(worker::Error::from)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn owner_audit<'a>(
    owner: &'a str,
    kind: &'a str,
    entity: &'a str,
    action: &'a str,
    revision: u64,
) -> Audit<'a> {
    Audit {
        owner,
        kind,
        entity,
        action,
        actor: owner,
        revision,
        before: None,
        after: None,
        receipt: None,
    }
}
