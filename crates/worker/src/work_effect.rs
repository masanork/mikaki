//! Fixed private external-effect adapter. Returned mint secrets enter custody only.
use crate::{
    read_bounded_body,
    work_store::{WorkStore, credential_key},
};
use mikaki_auth::work::{
    CredentialObservation, CredentialPurpose, CredentialScope, CredentialSecret, Digest,
};
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::{Env, Request, Response};
use zeroize::Zeroizing;
mod refusal;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum Input {
    InitialPlan {
        attempt_id: String,
    },
    MintPlan {
        attempt_id: String,
    },
    MintStatus {
        attempt_id: String,
        digest: String,
        repo_id: String,
        token_id: String,
        scope: CredentialScope,
        expires_at: u64,
        key_version: u64,
    },
    CaptureMint {
        attempt_id: String,
        digest: String,
        repo_id: String,
        token_id: String,
        scope: CredentialScope,
        expires_at: u64,
        key_version: u64,
        key_fingerprint: String,
        plaintext: String,
    },
    MintCleanup {
        attempt_id: String,
        digest: String,
        repo_id: String,
        token_id: String,
        scope: CredentialScope,
        expires_at: u64,
    },
    CaptureMintClosed {
        attempt_id: String,
        digest: String,
        repo_id: String,
        token_id: String,
        scope: CredentialScope,
        expires_at: u64,
        receipt: String,
    },
    MintRefusal {
        attempt_id: String,
        digest: String,
        repo_id: String,
        token_id: String,
        scope: CredentialScope,
        expires_at: u64,
        key_version: u64,
    },
    MintClose {
        attempt_id: String,
        digest: String,
        repo_id: String,
        token_id: String,
        scope: CredentialScope,
        expires_at: u64,
        key_version: u64,
        receipt: String,
    },
    CaptureClosed {
        attempt_id: String,
        repo_id: String,
        token_id: String,
        expires_at: Option<u64>,
        receipt: String,
    },
    CaptureRevocation {
        attempt_id: String,
        digest: String,
        repo_id: String,
        token_id: String,
        expires_at: u64,
    },
}
pub async fn handle(mut request: Request, env: &Env) -> worker::Result<Response> {
    if request.url()?.path() == "/git-effect" {
        return crate::work_git::handle(request, env).await;
    }
    let mint = request.url()?.path() == "/mint-effect";
    if request.method() != worker::Method::Post || (!mint && request.url()?.path() != "/effect") {
        return Response::empty().map(|r| r.with_status(404));
    }
    let result = execute(&mut request, env, mint).await;
    match result {
        Ok(value) => Response::builder()
            .with_header("Cache-Control", "no-store")?
            .from_json(&value),
        Err(_) => Response::builder()
            .with_status(409)
            .with_header("Cache-Control", "no-store")?
            .from_json(&serde_json::json!({"error":"effect_unavailable_or_denied"})),
    }
}
async fn execute(
    request: &mut Request,
    env: &Env,
    mint: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let enabled = if mint {
        "WORK_MINT_STORE_ENABLED"
    } else {
        "WORK_EFFECT_STORE_ENABLED"
    };
    if env.var(enabled)?.to_string() != "true" {
        return Err("effect_disabled".into());
    }
    let body = Zeroizing::new(read_bounded_body(request, 8192).await?);
    mikaki_webauthn::strict_json(&body, 8192, 8).map_err(|_| "invalid_effect_input")?;
    let input: Input = serde_json::from_str(&body)?;
    let mint_input = matches!(
        &input,
        Input::MintPlan { .. }
            | Input::MintStatus { .. }
            | Input::CaptureMint { .. }
            | Input::MintCleanup { .. }
            | Input::CaptureMintClosed { .. }
            | Input::MintRefusal { .. }
            | Input::MintClose { .. }
    );
    if mint != mint_input {
        return Err("invalid_effect_input".into());
    }
    let store = WorkStore::from_env(env)?;
    // These fixed result-recording actions confer no dispatch or release.
    // Native batches still require checkpoint framing; frozen/unavailable OP
    // remains unchanged while the independent mint ledger records cleanup.
    let input = match input {
        Input::MintRefusal {
            attempt_id,
            digest,
            repo_id,
            token_id,
            scope,
            expires_at,
            key_version,
        } => {
            return refusal::probe(
                &store,
                env,
                &attempt_id,
                &digest,
                &repo_id,
                &token_id,
                scope,
                expires_at,
                key_version,
            )
            .await;
        }
        Input::MintClose {
            attempt_id,
            digest,
            repo_id,
            token_id,
            scope,
            expires_at,
            key_version,
            receipt,
        } => {
            return refusal::close(
                &store,
                &attempt_id,
                &digest,
                &repo_id,
                &token_id,
                scope,
                expires_at,
                key_version,
                &receipt,
            )
            .await;
        }
        Input::CaptureMint {
            attempt_id,
            digest,
            repo_id,
            token_id,
            scope,
            expires_at,
            key_version,
            key_fingerprint,
            plaintext,
        } => {
            let plaintext = Zeroizing::new(plaintext);
            let a = store.credential_plan(&attempt_id).await?;
            if a.purpose() == CredentialPurpose::Initial
                || a.digest() != Digest::parse_hex(&digest)?
                || scope != a.purpose().scope()
                || expires_at > a.deadline()
                || expires_at <= (js_sys::Date::now() / 1000.0) as u64
                || expires_at > (js_sys::Date::now() / 1000.0) as u64 + 300
            {
                return Err("invalid_effect_input".into());
            }
            let o = CredentialObservation::from_observed(
                &a,
                &repo_id,
                &token_id,
                scope,
                Some(expires_at),
            )?;
            let key = credential_key(env, key_version)?;
            if key.fingerprint() != Digest::parse_hex(&key_fingerprint)? {
                return Err("invalid_effect_key".into());
            }
            let secret = CredentialSecret::from_service_bytes(plaintext.as_bytes())?;
            store.current_authority_checkpoint().await?;
            return Ok(serde_json::to_value(
                store
                    .capture_credential(&attempt_id, &o, Some(&secret), Some(&key))
                    .await?,
            )?);
        }
        Input::MintCleanup {
            attempt_id,
            digest,
            repo_id,
            token_id,
            scope,
            expires_at,
        } => {
            let a = store.credential_plan(&attempt_id).await?;
            if a.purpose() == CredentialPurpose::Initial
                || a.digest() != Digest::parse_hex(&digest)?
            {
                return Err("invalid_effect_input".into());
            }
            let o = CredentialObservation::from_observed(
                &a,
                &repo_id,
                &token_id,
                scope,
                Some(expires_at),
            )?;
            store
                .capture_credential(&attempt_id, &o, None, None)
                .await?;
            return Ok(serde_json::to_value(
                store.require_credential_revocation(&attempt_id).await?,
            )?);
        }
        input => input,
    };
    store.current_authority_checkpoint().await?;
    match input {
        Input::InitialPlan { attempt_id } => {
            Ok(store.initial_effect_plan(env, &attempt_id).await?)
        }
        Input::MintPlan { attempt_id } => Ok(store.mint_effect_plan(env, &attempt_id).await?),
        Input::MintStatus {
            attempt_id,
            digest,
            repo_id,
            token_id,
            scope,
            expires_at,
            key_version,
        } => {
            let a = store.credential_plan(&attempt_id).await?;
            if a.digest() != Digest::parse_hex(&digest)? {
                return Err("invalid_effect_input".into());
            }
            let o = CredentialObservation::from_observed(
                &a,
                &repo_id,
                &token_id,
                scope,
                Some(expires_at),
            )?;
            Ok(serde_json::to_value(
                store
                    .mint_custody_status(&attempt_id, &o, key_version)
                    .await?,
            )?)
        }
        Input::CaptureMintClosed {
            attempt_id,
            digest,
            repo_id,
            token_id,
            scope,
            expires_at,
            receipt,
        } => {
            let a = store.credential_plan(&attempt_id).await?;
            if a.purpose() == CredentialPurpose::Initial
                || a.digest() != Digest::parse_hex(&digest)?
            {
                return Err("invalid_effect_input".into());
            }
            let observation = CredentialObservation::from_observed(
                &a,
                &repo_id,
                &token_id,
                scope,
                Some(expires_at),
            )?;
            Ok(serde_json::to_value(
                store
                    .capture_mint_effect_closed(
                        &attempt_id,
                        &observation,
                        Digest::parse_hex(&receipt)?,
                    )
                    .await?,
            )?)
        }
        Input::CaptureMint { .. }
        | Input::MintCleanup { .. }
        | Input::MintRefusal { .. }
        | Input::MintClose { .. } => unreachable!(),
        Input::CaptureClosed {
            attempt_id,
            repo_id,
            token_id,
            expires_at,
            receipt,
        } => {
            let a = store.credential_plan(&attempt_id).await?;
            if a.purpose() != CredentialPurpose::Initial || a.expected_repo_id().is_some() {
                return Err("invalid_effect_input".into());
            }
            let observation = CredentialObservation::from_observed(
                &a,
                &repo_id,
                &token_id,
                CredentialScope::Write,
                expires_at,
            )?;
            let receipt = Digest::parse_hex(&receipt)?;
            Ok(serde_json::to_value(
                store
                    .capture_initial_effect_closed(&attempt_id, &observation, receipt)
                    .await?,
            )?)
        }
        Input::CaptureRevocation {
            attempt_id,
            digest,
            repo_id,
            token_id,
            expires_at,
        } => {
            let a = store.credential_plan(&attempt_id).await?;
            if a.purpose() != CredentialPurpose::Initial
                || a.expected_repo_id().is_some()
                || a.digest() != Digest::parse_hex(&digest)?
            {
                return Err("invalid_effect_input".into());
            }
            let observation = CredentialObservation::from_observed(
                &a,
                &repo_id,
                &token_id,
                CredentialScope::Write,
                Some(expires_at),
            )?;
            // No plaintext and no closed/refused confirmation: liability stays charged.
            Ok(serde_json::to_value(
                store
                    .capture_credential(&attempt_id, &observation, None, None)
                    .await?,
            )?)
        }
    }
}
// Only the named JS facade supplies its own Env. All other facades refuse raw RPC.
#[wasm_bindgen::prelude::wasm_bindgen]
pub async fn administer_work_effect(
    request: web_sys::Request,
    env: Env,
) -> Result<web_sys::Response, JsValue> {
    handle(request.into(), &env)
        .await
        .map(Into::into)
        .map_err(Into::into)
}
