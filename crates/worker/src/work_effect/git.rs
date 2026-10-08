//! One-shot productive Git use. Plaintext reaches only a named fixed transport.
use super::*;
use futures_util::StreamExt;

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GitResult {
    pub method: String,
    pub commit: String,
    pub tree: String,
    pub branch: String,
    pub commits: u64,
    pub objects: u64,
    pub object_bytes: u64,
    pub inventory_sha256: String,
    pub receipt: String,
}
async fn bounded(response: &mut Response) -> worker::Result<Vec<u8>> {
    let mut stream = response.stream()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > 8192 {
            return Err(worker::Error::RustError("git_response_invalid".into()));
        }
        bytes.extend(chunk);
    }
    Ok(bytes)
}
pub(super) async fn execute(
    store: &WorkStore,
    env: &Env,
    attempt: &str,
    plan: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if env.var("WORK_GIT_EXECUTION_ENABLED")?.to_string() != "true"
        || store.git_effect_plan(env, attempt).await? != plan
    {
        return Err("git_denied".into());
    }
    // Resolve both capabilities before consuming a permit; no global fetch or
    // caller-supplied Env/URL fallback exists.
    let checkpoint = env.service("WORK_GIT_EXECUTION_CHECKPOINT")?;
    let transport = env.service("WORK_GIT_TRANSPORT")?;
    let secret = store.credential_for_git(env, attempt, &plan).await?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(JsValue::from_str(&serde_json::to_string(&plan)?)));
    let mut response = checkpoint
        .fetch_request(Request::new_with_init(
            "https://private.invalid/git-permit",
            &init,
        )?)
        .await?;
    if response.status_code() != 200
        || serde_json::from_slice::<serde_json::Value>(&bounded(&mut response).await?)?
            != serde_json::json!({"taken":true})
    {
        return Err("git_permit_unconfirmed".into());
    }
    // Current primary facts can change while the independent permit is awaited.
    store.credential_for_git(env, attempt, &plan).await?;
    let headers = worker::Headers::new();
    let authorization = Zeroizing::new(format!(
        "Bearer {}",
        std::str::from_utf8(secret.service_bytes())?
    ));
    headers.set("Authorization", &authorization)?;
    init.with_headers(headers);
    let mut response = transport
        .fetch_request(Request::new_with_init(
            "https://private.invalid/git-execute",
            &init,
        )?)
        .await?;
    if response.status_code() != 200 {
        return Err("git_outcome_unknown".into());
    }
    let result: GitResult = serde_json::from_slice(&bounded(&mut response).await?)?;
    if result.commit != plan["commit"]
        || result.tree != plan["tree"]
        || result.branch != plan["branch"]
        || result.method
            != if plan["purpose"] == "upload" {
                "git_push_accepted"
            } else {
                "git_readback_verified"
            }
        || result.commits == 0
        || result.commits > 4096
        || result.objects < result.commits
        || result.objects > 65536
        || result.object_bytes > 67108864
        || (plan["role"] == "snapshot" && result.commits != 1)
    {
        return Err("git_result_invalid".into());
    }
    Digest::parse_hex(&result.inventory_sha256)?;
    Digest::parse_hex(&result.receipt)?;
    // Loss of authority after an accepted external effect keeps the outcome
    // uncertain. It does not undo bytes already delivered to the fixed repo.
    store.credential_for_git(env, attempt, &plan).await?;
    Ok(serde_json::to_value(result)?)
}
