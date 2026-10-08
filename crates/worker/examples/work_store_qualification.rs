//! LOCAL qualification only. Synthetic managed-verifier facts; never deploy.
//! Exercises the actual Rust WorkStore through Wasm/workerd, with no Git effects.
#![cfg(target_arch = "wasm32")]
use mikaki_auth::work::*;
use mikaki_worker::work_store::{
    CredentialDispatch, DispatchResult, Outcome, OwnerRecordKind, PreparationDispatch, StoreError,
    WorkStore, credential_key,
};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    action: String,
    #[serde(default)]
    session: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    approval: String,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    grant: String,
    #[serde(default)]
    run: String,
    request: Option<RequestInput>,
    disclosure: Option<GitDisclosureInput>,
    issued_at: Option<u64>,
    source: Option<SourceInput>,
    #[serde(default)]
    task_repository: String,
    #[serde(default)]
    task_namespace: String,
    #[serde(default)]
    snapshot_namespace: String,
    preparation_evidence: Option<FixturePreparationEvidence>,
    candidate: Option<FixtureCandidate>,
    #[serde(default)]
    receipt: String,
    #[serde(default)]
    outcome: String,
    #[serde(default = "default_key")]
    key: String,
    #[serde(default = "default_issuer")]
    issuer: String,
    #[serde(default = "default_client")]
    client: String,
    #[serde(default = "default_workload")]
    workload: String,
    #[serde(default = "default_revision")]
    issuer_revision: u64,
    expires_at: Option<u64>,
    credential: Option<FixtureCredential>,
    #[serde(default = "default_revision")]
    key_version: u64,
    payload: Option<CandidateGitFacts>,
    payload_bytes: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCredential {
    preparation_id: Option<String>,
    role: Option<CredentialRole>,
    purpose: Option<CredentialPurpose>,
    repo_id: Option<String>,
    token_id: Option<String>,
    scope: Option<CredentialScope>,
    expires_at: Option<u64>,
    plaintext: Option<String>,
    confirmation: Option<String>,
}
#[derive(Deserialize)]
struct FixtureCandidate {
    commit: String,
    tree: String,
    evidence: Digest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixturePreparationEvidence {
    for_operation: String,
    task_repo_id: String,
    snapshot_repo_id: String,
    payload_receipt: Digest,
    credential_receipt: Digest,
}
fn default_key() -> String {
    "4".repeat(64)
}
fn default_issuer() -> String {
    "launcher-1".into()
}
fn default_client() -> String {
    "launcher-client".into()
}
fn default_workload() -> String {
    "managed-agent".into()
}
fn default_revision() -> u64 {
    1
}
fn now() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
impl Input {
    fn actor(&self) -> std::result::Result<ManagedActor, Denied> {
        ManagedActor::from_verified_request(ManagedActorFacts {
            issuer: &self.issuer,
            issuer_revision: self.issuer_revision,
            client: &self.client,
            workload: &self.workload,
            run: &self.run,
            grant: &self.grant,
            proof_key: Digest::parse_hex(&self.key)?,
            expires_at: self.expires_at.unwrap_or_else(|| now() + 120),
        })
    }
}
fn operation(op: &ExternalOperation) -> Value {
    json!({"id":op.id(),"state":op.state(),"receipt":op.receipt(),"body":op.authority_record().unwrap()})
}
fn preparation(p: &Preparation) -> Value {
    json!({"id":p.id(),"digest":p.digest(),"state":p.state(),"body":p.authority_record().unwrap()})
}
async fn execute(store: WorkStore, i: Input, env: &Env) -> std::result::Result<Value, StoreError> {
    match i.action.as_str() {
        "checkpoint-current" => Ok(serde_json::to_value(
            store.current_authority_checkpoint().await?,
        )
        .map_err(|_| Denied::InvalidInput)?),
        "checkpoint-reconcile" => Ok(serde_json::to_value(
            store.reconcile_authority_checkpoint().await?,
        )
        .map_err(|_| Denied::InvalidInput)?),
        "reserve-candidate-payload" => {
            let payload = store
                .reserve_candidate_payload(
                    Digest::parse_hex(&i.digest)?,
                    i.payload.ok_or(Denied::InvalidInput)?,
                )
                .await?;
            Ok(json!({"digest":payload.digest(),"body":payload.authority_record()?}))
        }
        "retain-candidate-payload" => {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let bytes = i.payload_bytes.ok_or(Denied::InvalidInput)?;
            if bytes.len() > 12 * 1024 * 1024 {
                return Err(Denied::InvalidInput.into());
            }
            let bytes = STANDARD.decode(bytes).map_err(|_| Denied::InvalidInput)?;
            let p = store
                .retain_candidate_payload(
                    &env.bucket("WORK_GIT_PAYLOADS")?,
                    Digest::parse_hex(&i.digest)?,
                    bytes,
                )
                .await?;
            Ok(json!({"body":p.authority_record()?}))
        }
        "read-candidate-payload" => {
            use base64::{Engine as _, engine::general_purpose::STANDARD};
            let bytes = store
                .candidate_payload_bytes(
                    &env.bucket("WORK_GIT_PAYLOADS")?,
                    Digest::parse_hex(&i.digest)?,
                )
                .await?;
            Ok(json!({"bytes":STANDARD.encode(bytes)}))
        }
        "cleanup-candidate-payloads" => Ok(
            json!({"payloads":store.cleanup_candidate_payloads(&env.bucket("WORK_GIT_PAYLOADS")?,&i.id).await?}),
        ),
        "cleaned-preparation-with-payloads" => Ok(preparation(
            &store
                .confirm_preparation_cleaned_with_payloads(
                    &env.bucket("WORK_GIT_PAYLOADS")?,
                    &i.id,
                    Digest::parse_hex(&i.receipt)?,
                )
                .await?,
        )),
        "activate-credential-key" => {
            store
                .activate_credential_key(&credential_key(env, i.key_version)?)
                .await?;
            Ok(json!({"ok":true}))
        }
        "retire-credential-key" => {
            store
                .retire_credential_key(&credential_key(env, i.key_version)?)
                .await?;
            Ok(json!({"ok":true}))
        }
        "reserve-credential" => {
            let c = i.credential.ok_or(Denied::InvalidInput)?;
            Ok(json!(
                store
                    .reserve_credential(
                        c.preparation_id.as_deref().ok_or(Denied::InvalidInput)?,
                        c.role.ok_or(Denied::InvalidInput)?,
                        c.purpose.ok_or(Denied::InvalidInput)?,
                        &credential_key(env, i.key_version)?
                    )
                    .await?
            ))
        }
        "dispatch-credential" => match store
            .dispatch_credential(&i.id, &credential_key(env, i.key_version)?)
            .await?
        {
            CredentialDispatch::Started(a) => {
                Ok(json!({"started":true,"id":a.id(),"body":a.authority_record()?}))
            }
            CredentialDispatch::Existing(status) => Ok(json!({"started":false,"status":status})),
        },
        "capture-credential" => {
            let c = i.credential.ok_or(Denied::InvalidInput)?;
            let record = store.credential_plan(&i.id).await?;
            let o = CredentialObservation::from_observed(
                &record,
                c.repo_id.as_deref().ok_or(Denied::InvalidInput)?,
                c.token_id.as_deref().ok_or(Denied::InvalidInput)?,
                c.scope.ok_or(Denied::InvalidInput)?,
                c.expires_at,
            )?;
            let plaintext = c.plaintext.map(zeroize::Zeroizing::new);
            let secret = plaintext
                .as_ref()
                .map(|value| CredentialSecret::from_service_bytes(value.as_bytes()))
                .transpose()?;
            let key = if secret.is_some() {
                Some(credential_key(env, i.key_version)?)
            } else {
                None
            };
            Ok(json!(
                store
                    .capture_credential(&i.id, &o, secret.as_ref(), key.as_ref())
                    .await?
            ))
        }
        "credential-status" => Ok(json!(store.credential_status(&i.id).await?)),
        "credential-attempts" => Ok(json!({"attempts":store.credential_attempts(&i.id).await?})),
        "credential-cleanup-target" => {
            Ok(match store.credential_cleanup_observation(&i.id).await? {
                Some(o) => json!({"repo_id":o.repo_id(),"token_id":o.token_id()}),
                None => json!({"unknown":true}),
            })
        }
        "credential-revoke" => Ok(json!(store.require_credential_revocation(&i.id).await?)),
        "credential-close" => {
            let c = i.credential.ok_or(Denied::InvalidInput)?;
            Ok(json!(
                store
                    .confirm_credential_closed(
                        &i.id,
                        c.confirmation.as_deref().ok_or(Denied::InvalidInput)?,
                        Digest::parse_hex(&i.receipt)?
                    )
                    .await?
            ))
        }
        "credential-cleanup-recovery" => {
            use sha2::{Digest as _, Sha256};
            let secret = store
                .credential_for_cleanup(&i.id, &credential_key(env, i.key_version)?)
                .await?;
            // Synthetic test witness only. Never return the plaintext.
            Ok(json!({"digest":Digest::from_bytes(Sha256::digest(secret.service_bytes()).into())}))
        }
        "credential-custody-receipt" => {
            Ok(json!({"digest":store.credential_custody_receipt(&i.id).await?}))
        }
        "source-body" => {
            let source =
                RegisteredSource::from_verified_git(i.source.ok_or(Denied::InvalidInput)?)?;
            Ok(json!({"body":source.authority_record()?}))
        }
        "request" | "resolved-request" | "prepared-request" | "request-body" => {
            let owner = store.owner(&i.session).await?;
            let mut environment = owner.environment();
            if let Some(issued_at) = i.issued_at {
                environment.now = issued_at;
            }
            let request = i
                .request
                .ok_or(Denied::InvalidInput)?
                .validate(owner.session(), &environment)?;
            if i.action == "request-body" {
                return Ok(json!({"body":request.authority_record()?}));
            }
            let saved = if i.action == "prepared-request" {
                store.save_resolved_request(&i.session, &request).await?
            } else if i.action == "resolved-request" {
                store
                    .save_qualified_disclosure_request(&i.session, &request)
                    .await?
            } else {
                store.save_request(&i.session, &request).await?
            };
            Ok(json!({"digest":saved.digest().to_hex()}))
        }
        "disclosure" | "disclosure-body" | "legacy-disclosure-body" => {
            let owner = store.owner(&i.session).await?;
            let mut environment = owner.environment();
            if let Some(issued_at) = i.issued_at {
                environment.now = issued_at;
            }
            let d = ResolvedDisclosure::from_verified_git(
                i.disclosure.ok_or(Denied::InvalidInput)?,
                &i.client,
                &i.workload,
                owner.session(),
                &environment,
                i.expires_at.unwrap_or(now() + 600),
            )?;
            let d = if i.action != "legacy-disclosure-body" {
                store.bind_disclosure_sources(&i.session, d).await?
            } else {
                d
            };
            let d = if i.action == "disclosure" {
                store.save_disclosure(&i.session, &d).await?
            } else {
                d
            };
            Ok(json!({"digest":d.digest(),"body":d.authority_record()?}))
        }
        "collect-disclosures" => Ok(json!({"collected":store.collect_disclosures().await?})),
        "materialize-preparation" => {
            store.materialize_prepared_task(&i.id).await?;
            Ok(json!({"id":i.id}))
        }
        "preparation-body" => {
            let d = store.disclosure(Digest::parse_hex(&i.digest)?).await?;
            Ok(preparation(&Preparation::from_registered_disclosure(
                &d,
                &i.id,
                &i.task_repository,
                &i.task_namespace,
                &i.snapshot_namespace,
            )?))
        }
        "reserve-preparation" => Ok(preparation(
            &store
                .reserve_preparation(
                    &i.session,
                    Digest::parse_hex(&i.digest)?,
                    &i.task_repository,
                    &i.task_namespace,
                    &i.snapshot_namespace,
                )
                .await?,
        )),
        "dispatch-preparation" => match store.dispatch_preparation(&i.id).await? {
            PreparationDispatch::Started(p) => {
                Ok(json!({"started":true,"preparation":preparation(&p)}))
            }
            PreparationDispatch::Existing(p) => {
                Ok(json!({"started":false,"preparation":preparation(&p)}))
            }
        },
        "get-preparation" => Ok(preparation(&store.preparation(&i.id).await?)),
        "owner-preparation" => {
            store
                .owner_record(&i.session, OwnerRecordKind::Preparation, &i.id)
                .await
        }
        "verify-preparation" => {
            let e = i.preparation_evidence.ok_or(Denied::InvalidInput)?;
            let p = store.preparation(&e.for_operation).await?;
            // Explicitly synthetic adapter facts: no remote proof is claimed.
            let e = VerifiedPreparation::from_independently_verified(
                &p,
                &e.task_repo_id,
                &e.snapshot_repo_id,
                e.payload_receipt,
                e.credential_receipt,
            )?;
            Ok(preparation(&store.verify_preparation(&i.id, &e).await?))
        }
        "cleanup-preparation" => Ok(preparation(
            &store.require_preparation_cleanup(&i.id).await?,
        )),
        "cleaned-preparation" => Ok(preparation(
            &store
                .confirm_preparation_cleaned(&i.id, Digest::parse_hex(&i.receipt)?)
                .await?,
        )),
        "grant" | "grant-body" => {
            let owner = store.owner(&i.session).await?;
            let request = store.request(Digest::parse_hex(&i.digest)?).await?;
            let task = store.task(&request.input().task_repository).await?;
            let grant = Grant::approve(
                &i.id,
                &request,
                request.digest(),
                owner.session(),
                &task,
                &owner.environment(),
            )?;
            if i.action == "grant-body" {
                return Ok(json!({"body":grant.authority_record()?}));
            }
            let saved = store.save_grant(&i.session, &grant).await?;
            Ok(json!({"id":saved.id(),"revision":saved.revision(),"revoked":saved.is_revoked()}))
        }
        "run" | "run-body" => {
            let owner = store.owner(&i.session).await?;
            let grant = store.grant(&i.grant).await?;
            let request = store.request(grant.request_digest()).await?;
            let task = store.task(&request.input().task_repository).await?;
            let run = Run::register(
                &i.actor()?,
                &grant,
                &request,
                &task,
                now() + 240,
                &owner.environment(),
            )?;
            if i.action == "run-body" {
                return Ok(
                    json!({"body":run.authority_record()?,"actor_expires_at":i.actor()?.expires_at()}),
                );
            }
            let saved = store.save_run(&i.actor()?, &run).await?;
            Ok(json!({"id":saved.id(),"revision":saved.revision(),"revoked":saved.is_revoked()}))
        }
        "candidate" => {
            let actor = i.actor()?;
            let producer = store.producer(&i.run).await?;
            let owner = store.owner(&i.session).await?;
            let environment = owner.environment();
            let fresh = || {
                producer.run.authorize_submission(
                    SUBMIT,
                    &producer.grant,
                    &producer.request,
                    &actor,
                    &producer.task,
                    &environment,
                )
            };
            let raw = i.candidate.ok_or(Denied::InvalidInput)?;
            let candidate = fresh()?
                .prepare_candidate(CandidateInput {
                    commit: raw.commit,
                    tree: raw.tree,
                    evidence: raw.evidence,
                })?
                .confirm(fresh()?)?;
            let saved = store.save_candidate(&actor, &candidate).await?;
            Ok(json!({"digest":saved.digest().to_hex()}))
        }
        "approve" => {
            let candidate = store.candidate(Digest::parse_hex(&i.digest)?).await?;
            let producer = store.producer(candidate.run_id()).await?;
            let target = store
                .target(
                    &producer.request.input().adoption_repository,
                    &producer.request.input().adoption_ref,
                )
                .await?;
            let owner = store.owner(&i.session).await?;
            let environment = owner.environment();
            let context = AdoptionContext {
                candidate: &candidate,
                grant: &producer.grant,
                run: &producer.run,
                target: &target,
                environment: &environment,
            };
            let approval = CodeApproval::approve(
                &i.id,
                candidate.digest(),
                owner.session(),
                &context,
                i.expires_at.unwrap_or_else(|| now() + 120),
            )?;
            let saved = store.save_approval(&i.session, &approval).await?;
            Ok(json!({"id":saved.id()}))
        }
        "prepare" => Ok(operation(
            &store.prepare_operation(&i.approval, &i.id).await?,
        )),
        "dispatch" => match store.dispatch(&i.id).await? {
            DispatchResult::Started(op) => Ok(json!({"started":true,"operation":operation(&op)})),
            DispatchResult::Existing(op) => Ok(json!({"started":false,"operation":operation(&op)})),
        },
        "outcome" => {
            let outcome = match i.outcome.as_str() {
                "unknown" => Outcome::Unknown,
                "applied" => Outcome::Applied(&i.receipt),
                "rejected" => Outcome::Rejected(&i.receipt),
                _ => return Err(Denied::InvalidInput.into()),
            };
            Ok(operation(&store.record_outcome(&i.id, outcome).await?))
        }
        "owner-request-read" => {
            store
                .owner_record(
                    &i.session,
                    mikaki_worker::work_store::OwnerRecordKind::Request,
                    &i.digest,
                )
                .await
        }
        "owner-requests-read" => Ok(json!(store.owner_requests(&i.session, None).await?)),
        "cancel" => Ok(operation(&store.cancel_operation(&i.session, &i.id).await?)),
        "get" => Ok(operation(&store.operation(&i.id).await?)),
        "revoke-grant" => {
            store.revoke_grant(&i.session, &i.id).await?;
            Ok(json!({"ok":true}))
        }
        "revoke-run" => {
            store.revoke_run(&i.session, &i.id).await?;
            Ok(json!({"ok":true}))
        }
        "revoke-approval" => {
            store.revoke_approval(&i.session, &i.id).await?;
            Ok(json!({"ok":true}))
        }
        _ => Err(Denied::UnsupportedAction.into()),
    }
}
#[event(fetch)]
async fn main(mut req: Request, env: Env, ctx: Context) -> worker::Result<Response> {
    if !env
        .var("LOCAL_WORK_QUALIFICATION")
        .is_ok_and(|value| value.to_string() == "true")
    {
        return Response::error("local fixture disabled", 404);
    }
    if req.url()?.path().starts_with("/work/") || req.url()?.path() == "/logout" {
        return mikaki_worker::op_authority::qualification_routes(
            mikaki_worker::work_owner::routes(Router::with_data(())),
            ctx,
        )
        .run(req, env)
        .await;
    }
    if req.method() != Method::Post || req.url()?.path() != "/fixture" {
        return Response::error("local fixture route disabled", 404);
    }
    let input: Input = match serde_json::from_str(&req.text().await?) {
        Ok(input) => input,
        Err(_) => return Response::error("invalid fixture input", 400),
    };
    let store = WorkStore::from_env(&env)
        .map_err(|_| worker::Error::RustError("work_storage_unavailable".into()))?;
    match execute(store, input, &env).await {
        Ok(value) => Response::from_json(&value),
        Err(error) => Response::from_json(&json!({"error":error.to_string()})).map(|r| {
            r.with_status(match error {
                StoreError::Denied(_) => 409,
                StoreError::Storage(_) => 500,
            })
        }),
    }
}
