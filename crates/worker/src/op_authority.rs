//! Fixed OP authority changes. Private in-process capability; no public route.
//! Operator transport/provenance must be qualified before binding this capability.
use crate::{
    WorkerRuntimePolicy, read_bounded_body,
    work_store::{StoreError, WorkStore},
};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{D1PreparedStatement, D1Result, Env, Request, Response};

fn storage(error: StoreError) -> worker::Error {
    match error {
        StoreError::Storage(error) => error,
        StoreError::Denied(_) => worker::Error::RustError("authority_unavailable".into()),
    }
}
pub(crate) async fn batch(
    env: &Env,
    statements: Vec<D1PreparedStatement>,
) -> worker::Result<Vec<D1Result>> {
    WorkStore::from_env(env)
        .map_err(storage)?
        .authority_batch(statements)
        .await
        .map_err(storage)
}
pub(crate) async fn require_current(env: &Env) -> worker::Result<()> {
    WorkStore::from_env(env)
        .map_err(storage)?
        .require_authority_if_enrolled()
        .await
        .map_err(storage)
}
#[cfg(feature = "work-qualification")]
pub fn qualification_routes(
    router: worker::Router<'_, ()>,
    event_context: worker::Context,
) -> worker::Router<'_, ()> {
    let event_context = std::rc::Rc::new(event_context);
    router.get_async("/logout", crate::logout::get).post_async(
        "/logout",
        move |request, context| {
            let event_context = std::rc::Rc::clone(&event_context);
            async move { crate::logout::post(request, context, event_context).await }
        },
    )
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum Change {
    RevokeAccount {
        account: String,
        expected_epoch: u64,
        actor: String,
        reason: String,
    },
    RevokeSession {
        session: String,
        account: String,
        expected_epoch: u64,
        actor: String,
        reason: String,
    },
    DisableCredential {
        credential: String,
        account: String,
        actor: String,
        reason: String,
    },
    ActivatePolicy {
        policy: serde_json::Value,
        expected_revision: Option<String>,
        expected_generation: u64,
        actor: String,
        reason: String,
    },
}
fn text(value: &str) -> JsValue {
    JsValue::from_str(value)
}
fn number(value: u64) -> worker::Result<JsValue> {
    if value > mikaki_auth::work::MAX_STORED_INTEGER {
        return Err("invalid_authority_input".into());
    }
    Ok(JsValue::from_f64(value as f64))
}
fn valid(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn revision(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Closed, bounded request adapter for a future separately owned admin binding.
/// Not added to the OP HTTP router. The local qualifier invokes this exact code.
pub async fn administer(mut request: Request, env: &Env) -> worker::Result<Response> {
    if request.method() != worker::Method::Post || request.url()?.path() != "/authority" {
        return Response::empty().map(|r| r.with_status(404));
    }
    let result = change(&mut request, env).await;
    match result {
        Ok(value) => Response::builder()
            .with_header("Cache-Control", "no-store")?
            .from_json(&value),
        Err(_) => Response::builder()
            .with_status(409)
            .with_header("Cache-Control", "no-store")?
            .from_json(&serde_json::json!({"error":"authority_unavailable_or_denied"})),
    }
}

// Only the named JS facade supplies its own OP Env. The default service facade
// overrides this raw glue method to refuse RPC; it is never an HTTP route.
#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn administer_op_authority(
    request: web_sys::Request,
    env: Env,
) -> std::result::Result<web_sys::Response, JsValue> {
    administer(request.into(), &env)
        .await
        .map(Into::into)
        .map_err(Into::into)
}
async fn change(request: &mut Request, env: &Env) -> worker::Result<serde_json::Value> {
    let body = read_bounded_body(request, 8192).await?;
    mikaki_webauthn::strict_json(&body, 8192, 16)
        .map_err(|_| worker::Error::RustError("invalid_authority_input".into()))?;
    let input: Change = serde_json::from_str(&body)
        .map_err(|_| worker::Error::RustError("invalid_authority_input".into()))?;
    // Administrative changes always require enrollment, unlike ordinary legacy login.
    let store = WorkStore::from_env(env).map_err(storage)?;
    store
        .current_authority_checkpoint()
        .await
        .map_err(storage)?;
    let db = env.d1("DB")?;
    let (actor, reason, action, target, mut statements, output, policy_audit) = match input {
        Change::RevokeAccount {
            account,
            expected_epoch,
            actor,
            reason,
        } => {
            if !valid(&account, 128) {
                return Err("invalid_authority_input".into());
            }
            let next = expected_epoch
                .checked_add(1)
                .ok_or("invalid_authority_input")?;
            let mutation=db.prepare("UPDATE account_security SET epoch=?1,active=0 WHERE account_id=?2 AND epoch=?3 AND active=1")
                .bind(&[number(next)?,text(&account),number(expected_epoch)?])?;
            (
                actor,
                reason,
                "revoke-account",
                account,
                vec![mutation],
                serde_json::json!({"epoch":next}),
                None,
            )
        }
        Change::RevokeSession {
            session,
            account,
            expected_epoch,
            actor,
            reason,
        } => {
            if !valid(&session, 128) || !valid(&account, 128) {
                return Err("invalid_authority_input".into());
            }
            let mutation=db.prepare("UPDATE sso_session SET revoked=1 WHERE sso_id=?1 AND account_id=?2 AND epoch=?3 AND revoked=0")
                .bind(&[text(&session),text(&account),number(expected_epoch)?])?;
            (
                actor,
                reason,
                "revoke-session",
                session,
                vec![mutation],
                serde_json::json!({"revoked":true}),
                None,
            )
        }
        Change::DisableCredential {
            credential,
            account,
            actor,
            reason,
        } => {
            if !valid(&credential, 512) || !valid(&account, 128) {
                return Err("invalid_authority_input".into());
            }
            let mutation=db.prepare("UPDATE credential SET active=0 WHERE credential_id=?1 AND account_id=?2 AND active=1")
                .bind(&[text(&credential),text(&account)])?;
            (
                actor,
                reason,
                "disable-credential",
                credential,
                vec![mutation],
                serde_json::json!({"disabled":true}),
                None,
            )
        }
        Change::ActivatePolicy {
            policy,
            expected_revision,
            expected_generation,
            actor,
            reason,
        } => {
            let json = serde_json::to_string(&policy)?;
            let policy = WorkerRuntimePolicy::from_compiled_json(&json)?;
            if expected_revision.as_deref().is_some_and(|r| !revision(r))
                || (expected_revision.is_none() != (expected_generation == 0))
            {
                return Err("invalid_authority_input".into());
            }
            let generation = expected_generation
                .checked_add(1)
                .ok_or("invalid_authority_input")?;
            let activation = if let Some(previous) = &expected_revision {
                db.prepare("UPDATE runtime_policy_active SET projection_revision=?1,generation=?2 WHERE id=1 AND projection_revision=?3 AND generation=?4")
                    .bind(&[text(&policy.projection_revision),number(generation)?,text(previous),number(expected_generation)?])?
            } else {
                db.prepare("INSERT INTO runtime_policy_active(id,projection_revision,generation) SELECT 1,?1,1 WHERE NOT EXISTS(SELECT 1 FROM runtime_policy_active WHERE id=1)").bind(&[text(&policy.projection_revision)])?
            };
            let prior = expected_revision.as_deref().map_or(JsValue::NULL, text);
            let statements=vec![
                db.prepare("INSERT INTO runtime_policy_version(projection_revision,policy_revision,projection_json,created_at) VALUES(?1,?2,?3,unixepoch()) ON CONFLICT(projection_revision) DO NOTHING")
                    .bind(&[text(&policy.projection_revision),text(&policy.policy_revision),text(&json)])?,
                activation,
            ];
            let audit=db.prepare("INSERT INTO runtime_policy_audit(generation,previous_revision,projection_revision,changed_at,actor,reason) VALUES(?1,?2,?3,unixepoch(),?4,?5)")
                .bind(&[number(generation)?,prior,text(&policy.projection_revision),text(&actor),text(&reason)])?;
            // Policy audit is appended AFTER the activation changes() guard below.
            let output = serde_json::json!({"generation":generation,"projectionRevision":policy.projection_revision});
            (
                actor,
                reason,
                "activate-policy",
                policy.projection_revision,
                statements,
                output,
                Some(audit),
            )
        }
    };
    if !valid(&actor, 128) || !valid(&reason, 512) {
        return Err("invalid_authority_input".into());
    }
    let mut random = crate::WorkersCryptoRandom;
    let operation = crate::passkey_login::random_secret(&mut random)?;
    statements.push(db.prepare("INSERT INTO atomic_guard(operation_id,passed) VALUES(?1,CASE WHEN changes()=1 THEN 1 ELSE 0 END)").bind(&[text(&operation)])?);
    if let Some(audit) = policy_audit {
        statements.push(audit);
    }
    statements.push(db.prepare("INSERT INTO op_authority_audit(operation_id,action,target,actor,reason,occurred_at) VALUES(?1,?2,?3,?4,?5,unixepoch())")
        .bind(&[text(&operation),text(action),text(&target),text(&actor),text(&reason)])?);
    statements.push(
        db.prepare("DELETE FROM atomic_guard WHERE operation_id=?1")
            .bind(&[text(&operation)])?,
    );
    batch(env, statements).await?;
    Ok(output)
}
