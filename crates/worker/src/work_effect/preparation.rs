//! Compose retained independent Git evidence with closed primary custody.
//! The caller chooses only a preparation ID, never receipts or Git facts.
use super::*;
use crate::work_store::{AuthorityCheckpoint, ClosedCredential};
use futures_util::StreamExt;
use mikaki_auth::work::{CredentialRole, Preparation, VerifiedPreparation};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    format_version: u8,
    initial: Vec<Initial>,
    mint: Vec<Mint>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Initial {
    plan: Value,
    closure: Closure,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Closure {
    repo_id: String,
    token_id: String,
    expires_at: Option<u64>,
    receipt: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Mint {
    plan: Value,
    observation: Observation,
    refusal: Refusal,
    git: Git,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    repo_id: String,
    token_id: String,
    scope: CredentialScope,
    expires_at: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refusal {
    format_version: u8,
    method: String,
    status: u16,
    repo_id: String,
    token_id: String,
    scope: CredentialScope,
    expires_at: u64,
    key_version: u64,
    receipt: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Git {
    plan: Value,
    result: super::git::GitResult,
}
/// Host v1 receipts use the Native plan's sorted JSON keys and this fixed facts
/// field order. This checks the private commitment, not a provider signature.
#[derive(serde::Serialize)]
struct GitReceiptFacts<'a> {
    method: &'a str,
    commit: &'a str,
    tree: &'a str,
    branch: &'a str,
    commits: u64,
    objects: u64,
    object_bytes: u64,
    inventory_sha256: &'a str,
}
fn git_receipt(g: &Git) -> Result<Digest> {
    let r = &g.result;
    let facts = GitReceiptFacts {
        method: &r.method,
        commit: &r.commit,
        tree: &r.tree,
        branch: &r.branch,
        commits: r.commits,
        objects: r.objects,
        object_bytes: r.object_bytes,
        inventory_sha256: &r.inventory_sha256,
    };
    Ok(Digest::from_bytes(
        Sha256::digest(serde_json::to_vec(&(
            "mikaki-git-result-v1",
            &g.plan,
            facts,
        ))?)
        .into(),
    ))
}
fn fact(
    facts: &[ClosedCredential],
    role: CredentialRole,
    purpose: CredentialPurpose,
) -> Result<&ClosedCredential> {
    let mut matches = facts
        .iter()
        .filter(|f| f.attempt.role() == role && f.attempt.purpose() == purpose);
    let f = matches.next().ok_or("preparation_incomplete")?;
    if matches.next().is_some() {
        return Err("preparation_conflict".into());
    }
    Ok(f)
}
fn checkpoint(plan: &Value, current: &Value) -> Result<Value> {
    let cp = &plan["checkpoint"];
    serde_json::from_value::<AuthorityCheckpoint>(cp.clone())?;
    Digest::parse_hex(cp["epoch"].as_str().ok_or("checkpoint_invalid")?)?;
    Digest::parse_hex(cp["tip"].as_str().ok_or("checkpoint_invalid")?)?;
    if cp["authority"] != current["authority"]
        || cp["epoch"] != current["epoch"]
        || cp["sequence"].as_u64().ok_or("checkpoint_invalid")?
            > current["sequence"].as_u64().ok_or("checkpoint_invalid")?
        || (cp["sequence"] == current["sequence"] && cp["tip"] != current["tip"])
    {
        return Err("checkpoint_mismatch".into());
    }
    Ok(cp.clone())
}
fn base(p: &Preparation, f: &ClosedCredential, cp: Value, effect: &str) -> Value {
    let a = &f.attempt;
    let (namespace, name) = p.credential_destination(a.role());
    json!({"format_version":1,"effect":effect,"attempt_id":a.id(),"digest":a.digest().to_hex(),
        "namespace":namespace,"name":name,"role":a.role().name(),"deadline":a.deadline(),"checkpoint":cp})
}
/// Extend the exact Native reconstruction with the account-bound plan format.
/// Retained older evidence can omit it; that omission never permits a new
/// productive effect (the external gates require an explicit account).
fn account_binding(mut fixed: Value, observed: &Value, account: &str) -> Result<Value> {
    if let Some(actual) = observed.get("artifacts_account") {
        if actual.as_str() != Some(account) {
            return Err("preparation_account_mismatch".into());
        }
        fixed["artifacts_account"] = json!(account);
    }
    Ok(fixed)
}
fn observation(f: &ClosedCredential) -> Value {
    let o = &f.observation;
    json!({"repo_id":o.repo_id(),"token_id":o.token_id(),"scope":o.scope(),"expires_at":o.expires_at()})
}
fn mint_plan(
    p: &Preparation,
    f: &ClosedCredential,
    initial: &ClosedCredential,
    cp: Value,
    expires_at: u64,
) -> Result<Value> {
    if expires_at > f.attempt.deadline()
        || f.observation.expires_at().is_none_or(|e| e > expires_at)
        || f.attempt.expected_repo_id() != Some(initial.observation.repo_id())
        || f.observation.repo_id() != initial.observation.repo_id()
        || f.observation.token_id() == initial.observation.token_id()
        || f.observation.scope() != f.attempt.purpose().scope()
        || f.observation
            .expires_at()
            .is_none_or(|e| e == 0 || e > f.attempt.deadline())
    {
        return Err("preparation_binding_mismatch".into());
    }
    let mut plan = base(p, f, cp, "token.mint");
    let extra = json!({"purpose":f.attempt.purpose().name(),"scope":f.attempt.purpose().scope(),
        "repo_id":f.observation.repo_id(),"initial_attempt_id":initial.attempt.id(),
        "expires_at":expires_at,"key_version":f.key_version.ok_or("missing_key")?,"key_fingerprint":f.key_fingerprint.ok_or("missing_key")?.to_hex()});
    plan.as_object_mut()
        .ok_or("invalid_plan")?
        .extend(extra.as_object().ok_or("invalid_plan")?.clone());
    Ok(plan)
}
fn verify_role(
    p: &Preparation,
    facts: &[ClosedCredential],
    e: &Evidence,
    role: CredentialRole,
    data: &Value,
    current: &Value,
    account: &str,
) -> Result<Value> {
    let initial = fact(facts, role, CredentialPurpose::Initial)?;
    let mut matches = e
        .initial
        .iter()
        .filter(|i| i.plan["attempt_id"] == initial.attempt.id());
    let i = matches.next().ok_or("initial_missing")?;
    if matches.next().is_some()
        || i.plan
            != account_binding(
                base(p, initial, checkpoint(&i.plan, current)?, "repo.create"),
                &i.plan,
                account,
            )?
        || i.closure.repo_id != initial.observation.repo_id()
        || i.closure.token_id != initial.observation.token_id()
        || i.closure.expires_at != initial.observation.expires_at()
        || i.closure.receipt != initial.receipt.to_hex()
        || initial.observation.scope() != CredentialScope::Write
    {
        return Err("initial_mismatch".into());
    }
    let source = &data[if role == CredentialRole::Task {
        "code"
    } else {
        "snapshot"
    }];
    let mut results = Vec::with_capacity(2);
    let mut tokens = vec![initial.observation.token_id()];
    for purpose in [CredentialPurpose::Upload, CredentialPurpose::Readback] {
        let f = fact(facts, role, purpose)?;
        if tokens.contains(&f.observation.token_id()) {
            return Err("token_reused".into());
        }
        tokens.push(f.observation.token_id());
        let mut matches = e
            .mint
            .iter()
            .filter(|m| m.plan["attempt_id"] == f.attempt.id());
        let m = matches.next().ok_or("mint_missing")?;
        let r = &m.refusal;
        if matches.next().is_some()
            || m.plan
                != account_binding(
                    mint_plan(
                        p,
                        f,
                        initial,
                        checkpoint(&m.plan, current)?,
                        m.plan["expires_at"].as_u64().ok_or("missing_expiry")?,
                    )?,
                    &m.plan,
                    account,
                )?
            || serde_json::to_value(&m.observation)? != observation(f)
            || r.format_version != 1
            || r.method != "git_bearer_refused"
            || r.status != 403
            || r.repo_id != f.observation.repo_id()
            || r.token_id != f.observation.token_id()
            || r.scope != f.observation.scope()
            || Some(r.expires_at) != f.observation.expires_at()
            || Some(r.key_version) != f.key_version
            || r.receipt != f.receipt.to_hex()
        {
            return Err("mint_mismatch".into());
        }
        let mut plan = account_binding(
            mint_plan(
                p,
                f,
                initial,
                checkpoint(&m.git.plan, current)?,
                m.plan["expires_at"].as_u64().ok_or("missing_expiry")?,
            )?,
            &m.git.plan,
            account,
        )?;
        plan.as_object_mut()
            .ok_or("invalid_plan")?
            .remove("expires_at");
        plan["effect"] = json!(if purpose == CredentialPurpose::Upload {
            "git.upload"
        } else {
            "git.readback"
        });
        plan.as_object_mut().ok_or("invalid_plan")?.extend(json!({
            "preparation_digest":p.digest().to_hex(),"disclosure_digest":p.disclosure_digest().to_hex(),
            "commit":source["commit"],"tree":source["tree"],"branch":if role == CredentialRole::Task {"work"} else {"snapshot"},
            "observation":observation(f)
        }).as_object().ok_or("invalid_plan")?.clone());
        let g = &m.git.result;
        if m.git.plan != plan
            || g.commit != source["commit"]
            || g.tree != source["tree"]
            || g.branch != plan["branch"]
            || g.method
                != if purpose == CredentialPurpose::Upload {
                    "git_push_accepted"
                } else {
                    "git_readback_verified"
                }
            || g.commits == 0
            || g.commits > 4096
            || g.objects < g.commits
            || g.objects > 65536
            || g.object_bytes > 67108864
            || (role == CredentialRole::Snapshot && g.commits != 1)
            || (role == CredentialRole::Task
                && (json!(g.commits) != source["commits"]
                    || json!(g.objects) != source["objects"]
                    || json!(g.object_bytes) != source["object_bytes"]))
        {
            return Err("git_mismatch".into());
        }
        if Digest::parse_hex(&g.receipt)? != git_receipt(&m.git)? {
            return Err("git_receipt_mismatch".into());
        }
        Digest::parse_hex(&g.inventory_sha256)?;
        results.push(serde_json::to_value(g)?);
    }
    for key in [
        "commit",
        "tree",
        "branch",
        "commits",
        "objects",
        "object_bytes",
        "inventory_sha256",
    ] {
        if results[0][key] != results[1][key] {
            return Err("git_inventory_mismatch".into());
        }
    }
    Ok(json!({"role":role,"repo_id":initial.observation.repo_id(),"results":results}))
}
pub(super) async fn verify(store: &WorkStore, env: &Env, id: &str) -> Result<Value> {
    if env.var("WORK_PREPARATION_VERIFY_ENABLED")?.to_string() != "true" {
        return Err("preparation_disabled".into());
    }
    let cp = store.current_authority_checkpoint().await?;
    let p = store.preparation(id).await?;
    let facts = store.closed_preparation_credentials(id).await?;
    let custody = store.credential_custody_receipt(id).await?;
    let input = json!({"attempts":facts.iter().map(|f| json!({"attempt_id":f.attempt.id(),"purpose":f.attempt.purpose()})).collect::<Vec<_>>()});
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(JsValue::from_str(&serde_json::to_string(&input)?)));
    let mut response = env
        .service("WORK_PREPARATION_EVIDENCE")?
        .fetch_request(Request::new_with_init(
            "https://private.invalid/preparation-evidence",
            &init,
        )?)
        .await?;
    if response.status_code() != 200 {
        return Err("preparation_evidence_unavailable".into());
    }
    let mut stream = response.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > 32768 {
            return Err("preparation_evidence_invalid".into());
        }
        bytes.extend(chunk);
    }
    let body = std::str::from_utf8(&bytes)?;
    mikaki_webauthn::strict_json(body, 32768, 12).map_err(|_| "preparation_evidence_invalid")?;
    let e: Evidence = serde_json::from_str(body)?;
    if e.format_version != 1 || e.initial.len() != 2 || e.mint.len() != 4 {
        return Err("preparation_incomplete".into());
    }
    let d = store.disclosure(p.disclosure_digest()).await?;
    let data = serde_json::to_value(d.review())?;
    let current = serde_json::to_value(&cp)?;
    let account = crate::work_store::copy_account(env)?;
    let task = verify_role(
        &p,
        &facts,
        &e,
        CredentialRole::Task,
        &data,
        &current,
        &account,
    )?;
    let snapshot = verify_role(
        &p,
        &facts,
        &e,
        CredentialRole::Snapshot,
        &data,
        &current,
        &account,
    )?;
    let payload = Digest::from_bytes(
        Sha256::digest(serde_json::to_vec(&json!([
            "mikaki.work-preparation-payload.v1",
            p.digest().to_hex(),
            p.disclosure_digest().to_hex(),
            task,
            snapshot
        ]))?)
        .into(),
    );
    let evidence = VerifiedPreparation::from_independently_verified(
        &p,
        task["repo_id"].as_str().ok_or("repo_missing")?,
        snapshot["repo_id"].as_str().ok_or("repo_missing")?,
        payload,
        custody,
    )?;
    // Closure facts are immutable. Recheck the independent primary checkpoint
    // after the metadata wait; D1 triggers repeat live sources/owner/policy at
    // the framed verify commit. Historical verified retries perform no write.
    if cp != store.current_authority_checkpoint().await? {
        return Err("checkpoint_changed".into());
    }
    let verified = store.verify_preparation(id, &evidence).await?;
    Ok(verified.review(Some(&evidence))?)
}
