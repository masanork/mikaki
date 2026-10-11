//! Fixed safety proof; the decrypted bearer is never returned to a caller.
use super::*;
use mikaki_auth::work::CredentialAttempt;
use sha2::{Digest as _, Sha256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Binding<'a> {
    attempt: &'a str,
    digest: &'a str,
    repo: &'a str,
    token: &'a str,
    scope: CredentialScope,
    expires: u64,
    key: u64,
}
impl Binding<'_> {
    async fn validate(
        &self,
        store: &WorkStore,
    ) -> Result<(CredentialAttempt, CredentialObservation)> {
        let a = store.credential_plan(self.attempt).await?;
        if a.purpose() == CredentialPurpose::Initial
            || a.digest() != Digest::parse_hex(self.digest)?
            || a.purpose().scope() != self.scope
            || self.expires == 0
            || self.expires > a.deadline()
        {
            return Err("invalid_refusal_binding".into());
        }
        let o = CredentialObservation::from_observed(
            &a,
            self.repo,
            self.token,
            self.scope,
            Some(self.expires),
        )?;
        let status = store
            .mint_custody_status(self.attempt, &o, self.key)
            .await?;
        if !matches!(status.state.as_str(), "revocation_pending" | "closed") {
            return Err("invalid_refusal_state".into());
        }
        Ok((a, o))
    }
    fn receipt(&self) -> Result<Digest> {
        let bytes = serde_json::to_vec(&serde_json::json!([
            "mikaki-mint-refusal-v1",
            self.digest,
            self.repo,
            self.token,
            self.scope,
            self.expires,
            self.key,
            403
        ]))?;
        let hex: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        Ok(Digest::parse_hex(&hex)?)
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn probe(
    store: &WorkStore,
    env: &Env,
    attempt: &str,
    digest: &str,
    repo: &str,
    token: &str,
    scope: CredentialScope,
    expires: u64,
    key: u64,
) -> Result<serde_json::Value> {
    let b = Binding {
        attempt,
        digest,
        repo,
        token,
        scope,
        expires,
        key,
    };
    let (a, _) = b.validate(store).await?;
    let wrapping = credential_key(env, key)?;
    let secret = store.credential_for_cleanup(attempt, &wrapping).await?;
    let p = store.preparation(a.preparation_id()).await?;
    let (namespace, name) = p.credential_destination(a.role());
    let account = env.var("WORK_ARTIFACTS_ACCOUNT")?.to_string();
    if account.len() != 32
        || !account
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("invalid_refusal_account".into());
    }
    let headers = worker::Headers::new();
    let authorization = Zeroizing::new(format!(
        "Bearer {}",
        std::str::from_utf8(secret.service_bytes())?
    ));
    headers.set("Authorization", &authorization)?;
    headers.set("X-Mikaki-Attempt-ID", attempt)?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get).with_headers(headers);
    let request = Request::new_with_init(
        &format!(
            "https://{account}.artifacts.cloudflare.net/git/{namespace}/{name}.git/info/refs?service=git-upload-pack"
        ),
        &init,
    )?;
    // This named transport checks independent cleanup/identity, suppresses all
    // response content and refuses redirects. Missing binding has no fallback.
    let response = env
        .service("WORK_MINT_REFUSAL_TRANSPORT")?
        .fetch_request(request)
        .await?;
    if response.status_code() != 403 {
        return Err("refusal_unconfirmed".into());
    }
    // A concurrent closure/key retirement must not emit a stale proof.
    store.credential_for_cleanup(attempt, &wrapping).await?;
    b.validate(store).await?;
    Ok(
        serde_json::json!({"format_version":1,"method":"git_bearer_refused","status":403,
        "repo_id":repo,"token_id":token,"scope":scope,"expires_at":expires,"key_version":key,"receipt":b.receipt()?.to_hex()}),
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn close(
    store: &WorkStore,
    attempt: &str,
    digest: &str,
    repo: &str,
    token: &str,
    scope: CredentialScope,
    expires: u64,
    key: u64,
    receipt: &str,
) -> Result<serde_json::Value> {
    let b = Binding {
        attempt,
        digest,
        repo,
        token,
        scope,
        expires,
        key,
    };
    b.validate(store).await?;
    let receipt = Digest::parse_hex(receipt)?;
    if receipt != b.receipt()? {
        return Err("invalid_refusal_receipt".into());
    }
    Ok(serde_json::to_value(
        store
            .confirm_credential_closed(attempt, "refused", receipt)
            .await?,
    )?)
}
