//! First-party OID4VCI flow. Evidence, grant secrets and separate holder keys stay in Rust.
use p256::elliptic_curve::Generate;
mod batch;
mod completion;
mod credential_transport;
pub mod haip;
mod inventory;
pub mod invocation;
pub mod passport;
mod presentation_transport;
pub mod proximity;
use crate::identity_wallet::{self, HolderKey, Receipt};
use getrandom::SysRng;
use mikaki_identity::{
    card::{CardFailure, FailureCode},
    evidence::Evidence,
    issuance::{self, PublicJwk},
    mdoc,
};
use openidconnect::reqwest::{Client, Response};
use rand_core::{Rng, UnwrapErr};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_opener::OpenerExt;
use zeroize::Zeroizing;

use mikaki_identity::wallet_profile::{ISSUER, ROOT};
struct Flow {
    tx: String,
    secret: Zeroizing<String>,
    keys: Vec<HolderKey>,
    batch_claims: Option<String>,
    created: Instant,
    configuration: String,
    passport: Option<passport::PassportFlow>,
}
struct PendingPresentation {
    id: String,
    request: mikaki_identity::presentation::ApprovedRequest,
    credential_hash: String,
    inventory: Option<mikaki_identity::presentation::inventory::InventoryRequest>,
    bindings: Vec<(String, String)>,
    expires_at: u64,
}
#[derive(Default)]
struct Inner {
    evidence: Option<(Evidence, Instant)>,
    passport_review: Option<passport::Pending>,
    passport_generation: u64,
    passport_receipts: Vec<(String, Receipt)>,
    flow: Option<Flow>,
    haip: Option<haip::Pending>,
    haip_state: &'static str,
    receipt: Option<Receipt>,
    receipts: Vec<Receipt>,
    busy: bool,
    generation: u64,
    presentation: Option<PendingPresentation>,
    invocation: Option<(String, invocation::Invocation, Instant)>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    initial_invocation_checked: bool,
    #[cfg(target_os = "android")]
    proximity: Option<proximity::android::Flow>,
    #[cfg(target_os = "android")]
    proximity_id: Option<String>,
    presented_nonces: std::collections::HashSet<String>,
}
impl Inner {
    fn current_receipts(&mut self, app: &AppHandle, at: u64) -> Result<Vec<Receipt>, String> {
        self.restore_receipts(app)?;
        let owner = crate::identity_documents::owner(app).ok();
        passport::retain_receipts(&mut self.passport_receipts, owner.as_deref(), at);
        if self.flow.as_ref().is_some_and(|f| {
            f.created.elapsed() >= Duration::from_secs(600)
                || f.passport
                    .as_ref()
                    .is_some_and(|p| Some(p.owner.as_str()) != owner.as_deref())
        }) {
            self.flow = None;
        }
        let mut receipts = self.receipts.clone();
        receipts.extend(self.passport_receipts.iter().map(|(_, r)| r.clone()));
        Ok(receipts)
    }

    fn restore_receipts(&mut self, app: &AppHandle) -> Result<(), String> {
        if self.receipts.is_empty() {
            self.receipts = identity_wallet::restore_inventory(app, ISSUER, now()?)?;
            if self.receipts.is_empty() {
                if let Some(receipt) = &self.receipt {
                    self.receipts.push(receipt.clone());
                }
            }
        }
        self.receipt = self
            .receipts
            .iter()
            .rev()
            .find(|r| r.expires_at > now().unwrap_or(u64::MAX))
            .cloned();
        Ok(())
    }
    fn install_receipts(&mut self, app: &AppHandle, receipts: Vec<Receipt>) -> Result<(), String> {
        self.restore_receipts(app)?;
        let at = now()?;
        let inventory = batch::install(&self.receipts, receipts, at, |all| {
            identity_wallet::save_inventory(app, all)
        })?;
        for old in self.receipts.iter().filter(|r| r.expires_at <= at) {
            let _ = old.key.destroy();
        }
        self.receipt = inventory.last().cloned();
        self.receipts = inventory;
        self.presentation = None;
        Ok(())
    }
    fn invalidate_presentations(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.presentation = None;
        self.invocation = None;
        // Erasure must not requeue the original launch intent on the first UI poll.
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            self.initial_invocation_checked = true;
        }
    }
    fn retire_age_receipts(
        &mut self,
        app: &AppHandle,
        selected: &[String],
        at: u64,
    ) -> Result<(), String> {
        self.retire_age_receipts_with(
            selected,
            at,
            |remaining, anchor| identity_wallet::save_retired_inventory(app, remaining, anchor),
            |key| key.destroy(),
        )
    }
    fn retire_age_receipts_with(
        &mut self,
        selected: &[String],
        at: u64,
        persist: impl FnOnce(&[Receipt], &Receipt) -> Result<(), String>,
        destroy: impl Fn(&HolderKey) -> Result<(), String>,
    ) -> Result<(), String> {
        let removed =
            identity_wallet::retirement::commit(&mut self.receipts, selected, ISSUER, at, persist)?;
        self.receipt = self
            .receipts
            .iter()
            .rev()
            .find(|r| r.expires_at > at)
            .cloned();
        for key in removed {
            destroy(&key)?;
        }
        Ok(())
    }
    fn consume_review(&mut self, id: &str) -> Result<PendingPresentation, String> {
        if !self.presentation.as_ref().is_some_and(|p| p.id == id) {
            return Err("review_required".into());
        }
        let pending = self.presentation.take().ok_or("review_required")?;
        let nonce_hash = credential_hash(&format!(
            "{}:{}",
            pending.request.client_id(),
            pending.request.nonce()
        ));
        if self.presented_nonces.len() >= 256 || !self.presented_nonces.insert(nonce_hash) {
            return Err("request_consumed".into());
        }
        Ok(pending)
    }
}
/// Logout drops owner-bound passport secrets immediately, including in-flight authority.
pub(crate) fn clear_passport_session(app: &AppHandle) {
    if let Some(state) = app.try_state::<IdentityState>() {
        if let Ok(mut inner) = state.0.lock() {
            passport::clear_owner_session(&mut inner);
        }
    }
}
#[derive(Default)]
pub struct IdentityState(Arc<Mutex<Inner>>);
struct Gate {
    state: Arc<Mutex<Inner>>,
    generation: u64,
}
impl Drop for Gate {
    fn drop(&mut self) {
        if let Ok(mut s) = self.state.lock() {
            s.busy = false;
        }
    }
}
fn gate(state: &IdentityState) -> Result<Gate, String> {
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    if s.busy {
        return Err("identity_busy".into());
    }
    s.busy = true;
    Ok(Gate {
        state: state.0.clone(),
        generation: s.generation,
    })
}
fn random() -> String {
    let mut bytes = [0; 32];
    UnwrapErr(SysRng).fill_bytes(&mut bytes);
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "clock_unavailable".into())
}
fn client() -> Result<Client, String> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| "network_unavailable".into())
}
fn json_request(
    http: &Client,
    url: String,
    value: Value,
) -> Result<openidconnect::reqwest::RequestBuilder, String> {
    let bytes = serde_json::to_vec(&value).map_err(|_| "invalid_request")?;
    Ok(http
        .post(url)
        .header("content-type", "application/json")
        .body(bytes))
}
async fn body(mut response: Response) -> Result<Value, String> {
    let status = response.status();
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| "network_error")? {
        if bytes.len() + chunk.len() > 48 * 1024 {
            return Err("invalid_response".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    let value = mikaki_identity::wallet_profile::strict_json(&bytes)?;
    if !status.is_success() {
        let error = value["error"].as_str().unwrap_or("server_error");
        return Err(match error {
            "document_verification_failed"
            | "issuer_unavailable"
            | "not_found"
            | "access_denied"
            | "transaction_unavailable"
            | "transaction_consumed"
            | "document_revalidation_required"
            | "slow_down" => error.to_string(),
            _ => "issuance_failed".into(),
        });
    }
    Ok(value)
}
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn retain_evidence(
    app: &AppHandle,
    evidence: Evidence,
    cancelled: &std::sync::atomic::AtomicBool,
) -> Result<(), CardFailure> {
    let state = app.state::<IdentityState>();
    let mut s = state
        .0
        .lock()
        .map_err(|_| CardFailure::from(FailureCode::TransportError))?;
    if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(FailureCode::Cancelled.into());
    }
    if s.busy {
        return Err(FailureCode::ReaderBusy.into());
    }
    s.evidence = Some((evidence, Instant::now()));
    Ok(())
}
#[tauri::command]
pub fn clear_identity_evidence(
    app: AppHandle,
    state: State<'_, IdentityState>,
) -> Result<(), String> {
    crate::identity_documents::clear_pending(&app)?;
    let mut inner = state.0.lock().map_err(|_| "identity_unavailable")?;
    inner.evidence = None;
    inner.passport_review = None;
    inner.passport_generation = inner.passport_generation.wrapping_add(1);
    Ok(())
}
#[derive(Serialize)]
pub struct LinkStarted {
    holder_thumbprint: String,
    holder_thumbprints: Vec<String>,
    credential_count: usize,
    expires_in: u64,
    haip: bool,
}
#[tauri::command]
pub async fn start_identity_link(
    app: AppHandle,
    state: State<'_, IdentityState>,
    configuration: Option<String>,
    credential_count: Option<usize>,
) -> Result<LinkStarted, String> {
    if state
        .0
        .lock()
        .map_err(|_| "identity_unavailable")?
        .haip
        .is_some()
    {
        return Err("identity_busy".into());
    }
    let configuration = configuration.unwrap_or_else(|| issuance::CONFIGURATION.into());
    if !matches!(
        configuration.as_str(),
        issuance::CONFIGURATION | mdoc::CONFIGURATION
    ) {
        return Err("unsupported_credential_configuration".into());
    }
    let guard = gate(&state)?;
    let count = credential_count.unwrap_or(1);
    if !(1..=mikaki_identity::age_batch::MAX_SIZE).contains(&count) {
        return Err("invalid_age_batch".into());
    }
    {
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        s.restore_receipts(&app)?;
        if s.receipts
            .iter()
            .filter(|r| r.expires_at > now().unwrap_or(u64::MAX))
            .count()
            + count
            > mikaki_identity::age_batch::MAX_SIZE
        {
            return Err("wallet_inventory_full".into());
        }
    }
    let http = client()?;
    let batch_claims = if count > 1 {
        let metadata = body(
            http.get(format!(
                "{ROOT}/.well-known/openid-credential-issuer/identity/issuer"
            ))
            .send()
            .await
            .map_err(|_| "network_error")?,
        )
        .await?;
        if metadata["credential_issuer"] != ISSUER {
            return Err("invalid_metadata".into());
        }
        Some(batch::metadata_claims(&metadata, &configuration)?)
    } else {
        None
    };
    let (evidence, read_at) = state
        .0
        .lock()
        .map_err(|_| "identity_unavailable")?
        .evidence
        .take()
        .ok_or("read_required")?;
    if read_at.elapsed() > Duration::from_secs(600) {
        return Err("read_required".into());
    }
    let keys = (0..count)
        .map(|_| HolderKey::create(&app))
        .collect::<Result<Vec<_>, _>>()?;
    let holders = keys
        .iter()
        .map(HolderKey::public)
        .collect::<Result<Vec<_>, _>>()?;
    let payload = if count == 1 {
        json!({"evidence":evidence,"holder_jwk":holders[0]})
    } else {
        json!({"evidence":evidence,"holder_jwks":holders,"credential_configuration_id":configuration})
    };
    let response = body(
        json_request(&http, format!("{ROOT}/identity/intake"), payload)?
            .send()
            .await
            .map_err(|_| "network_error")?,
    )
    .await?;
    let tx = response["transaction_id"]
        .as_str()
        .filter(|s| valid_id(s))
        .ok_or("invalid_response")?
        .to_string();
    let secret = Zeroizing::new(
        response["poll_secret"]
            .as_str()
            .filter(|s| valid_id(s))
            .ok_or("invalid_response")?
            .to_string(),
    );
    let url = format!("{ROOT}/identity/approve?tx={tx}");
    let thumbprints = holders
        .iter()
        .map(PublicJwk::thumbprint)
        .collect::<Result<Vec<_>, _>>()
        .map_err(str::to_string)?;
    let thumbprint = thumbprints[0].clone();
    if response["approval_url"] != url
        || response["holder_thumbprint"] != thumbprint
        || response["expires_in"] != 600
        || (count > 1
            && (response["credential_count"] != count
                || response["holder_thumbprints"] != json!(thumbprints)))
    {
        return Err("invalid_response".into());
    }
    {
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        s.flow = Some(Flow {
            tx,
            secret,
            keys,
            batch_claims,
            created: Instant::now(),
            configuration,
            passport: None,
        });
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|_| "browser_unavailable")?;
    Ok(LinkStarted {
        holder_thumbprint: thumbprint,
        holder_thumbprints: thumbprints,
        credential_count: count,
        expires_in: 600,
        haip: false,
    })
}
fn valid_id(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
#[derive(Serialize)]
pub struct ReceiveResult {
    state: &'static str,
    credential_count: Option<usize>,
    expires_at: Option<u64>,
    format: Option<String>,
}
#[tauri::command]
pub async fn receive_identity_credential(
    app: AppHandle,
    state: State<'_, IdentityState>,
) -> Result<ReceiveResult, String> {
    let guard = gate(&state)?;
    let flow = state
        .0
        .lock()
        .map_err(|_| "identity_unavailable")?
        .flow
        .take()
        .ok_or("approval_required")?;
    if flow.created.elapsed() > Duration::from_secs(600) {
        return Err("transaction_unavailable".into());
    }
    passport::check_flow_owner(&app, &flow)?;
    let http = client()?;
    let poll_path = if flow.passport.is_some() {
        "identity/passport/poll"
    } else {
        "identity/poll"
    };
    let response = body(
        json_request(
            &http,
            format!("{ROOT}/{poll_path}"),
            json!({"transaction_id":flow.tx,"poll_secret":&*flow.secret}),
        )?
        .send()
        .await
        .map_err(|_| "network_error")?,
    )
    .await?;
    if response["state"] == "pending" {
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        s.flow = Some(flow);
        return Ok(ReceiveResult {
            state: "pending",
            credential_count: None,
            expires_at: None,
            format: None,
        });
    }
    let offer = &response["credential_offer"];
    if response["state"] != "approved"
        || offer["credential_issuer"] != ISSUER
        || offer["credential_configuration_ids"]
            .as_array()
            .is_none_or(|ids| {
                ids.is_empty()
                    || ids.len() > 3
                    || !ids.contains(&json!(flow.configuration))
                    || ids.iter().any(|id| {
                        id != issuance::CONFIGURATION
                            && id != mdoc::CONFIGURATION
                            && id != mikaki_identity::passport::credential::CONFIGURATION
                    })
            })
    {
        return Err("invalid_response".into());
    }
    let code = Zeroizing::new(
        offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
            ["pre-authorized_code"]
            .as_str()
            .filter(|s| valid_id(s))
            .ok_or("invalid_response")?
            .to_string(),
    );
    // Exact HTTPS issuer and endpoint checks; never follow arbitrary offer URLs or redirects.
    let metadata = body(
        http.get(format!(
            "{ROOT}/.well-known/openid-credential-issuer/identity/issuer"
        ))
        .send()
        .await
        .map_err(|_| "network_error")?,
    )
    .await?;
    let oauth = body(
        http.get(format!(
            "{ROOT}/.well-known/oauth-authorization-server/identity/issuer"
        ))
        .send()
        .await
        .map_err(|_| "network_error")?,
    )
    .await?;
    if metadata["credential_issuer"] != ISSUER
        || metadata["credential_endpoint"] != format!("{ISSUER}/credential")
        || metadata["nonce_endpoint"] != format!("{ISSUER}/nonce")
        || metadata["credential_configurations_supported"]["linked_document"]["format"]
            != "dc+sd-jwt"
        || metadata["credential_configurations_supported"]["linked_document"]["vct"]
            != format!("{ISSUER}/types/linked-document")
        || oauth["issuer"] != ISSUER
        || oauth["token_endpoint"] != format!("{ISSUER}/token")
        || oauth["jwks_uri"] != format!("{ISSUER}/jwks")
    {
        return Err("invalid_metadata".into());
    }
    if flow.configuration == mdoc::CONFIGURATION
        && (metadata["credential_configurations_supported"][mdoc::CONFIGURATION]["format"]
            != "mso_mdoc"
            || metadata["credential_configurations_supported"][mdoc::CONFIGURATION]["doctype"]
                != mdoc::DOCTYPE)
    {
        return Err("invalid_metadata".into());
    }
    if let Some(claims) = &flow.batch_claims {
        if &batch::metadata_claims(&metadata, &flow.configuration)? != claims {
            return Err("invalid_metadata".into());
        }
    }
    if flow.passport.is_some()
        && (metadata["credential_configurations_supported"]
            [mikaki_identity::passport::credential::CONFIGURATION]["format"]
            != "dc+sd-jwt"
            || metadata["credential_configurations_supported"]
                [mikaki_identity::passport::credential::CONFIGURATION]["vct"]
                != mikaki_identity::passport::credential::vct(ISSUER))
    {
        return Err("invalid_metadata".into());
    }
    let jwks = body(
        http.get(format!("{ISSUER}/jwks"))
            .send()
            .await
            .map_err(|_| "network_error")?,
    )
    .await?;
    let keys = jwks["keys"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("invalid_issuer_key")?;
    let kid = keys[0]["kid"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("invalid_issuer_key")?;
    let issuer_key = PublicJwk {
        kty: keys[0]["kty"].as_str().unwrap_or("").into(),
        crv: keys[0]["crv"].as_str().unwrap_or("").into(),
        x: keys[0]["x"].as_str().unwrap_or("").into(),
        y: keys[0]["y"].as_str().unwrap_or("").into(),
    };
    if keys[0]["alg"] != "ES256" || keys[0]["use"] != "sig" || keys[0].get("d").is_some() {
        return Err("invalid_issuer_key".into());
    }
    issuer_key.verifying_key().map_err(str::to_string)?;
    let mut recipient_entropy = Zeroizing::new([0u8; 32]);
    UnwrapErr(SysRng).fill_bytes(&mut *recipient_entropy);
    let encryption = mikaki_identity::issuance_encryption::WalletEncryption::from_metadata(
        &metadata,
        *recipient_entropy,
        &random(),
    )
    .map_err(|_| "invalid_metadata")?;
    if let Some(encryption) = &encryption {
        let request_key = encryption.request_key().map_err(|_| "invalid_metadata")?;
        if request_key == issuer_key
            || flow
                .keys
                .iter()
                .map(HolderKey::public)
                .collect::<Result<Vec<_>, _>>()?
                .contains(&request_key)
        {
            return Err("invalid_metadata".into());
        }
    }
    if state
        .0
        .lock()
        .map_err(|_| "identity_unavailable")?
        .generation
        != guard.generation
    {
        return Err("cancelled".into());
    }
    let token = body(
        http.post(format!("{ISSUER}/token"))
            .form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                ),
                ("pre-authorized_code", &*code),
            ])
            .send()
            .await
            .map_err(|_| "network_error")?,
    )
    .await?;
    let access = Zeroizing::new(
        token["access_token"]
            .as_str()
            .filter(|s| valid_id(s))
            .ok_or("invalid_response")?
            .to_string(),
    );
    if token["token_type"] != "Bearer"
        || (if flow.passport.is_some() {
            token["expires_in"]
                .as_u64()
                .is_none_or(|n| n == 0 || n > 120)
                || token["scope"] != mikaki_identity::passport::credential::CONFIGURATION
        } else {
            token["expires_in"] != 120 || token["scope"] != "linked_document"
        })
    {
        return Err("invalid_response".into());
    }
    let nonce = body(
        http.post(format!("{ISSUER}/nonce"))
            .send()
            .await
            .map_err(|_| "network_error")?,
    )
    .await?;
    let nonce = nonce["c_nonce"]
        .as_str()
        .filter(|s| valid_id(s))
        .ok_or("invalid_response")?;
    let proofs = Zeroizing::new(
        flow.keys
            .iter()
            .map(|key| key.proof(ISSUER, nonce, now()?, &random()))
            .collect::<Result<Vec<_>, _>>()?,
    );
    passport::check_flow_owner(&app, &flow)?;
    let mut payload =
        json!({"credential_configuration_id":flow.configuration,"proofs":{"jwt":&*proofs}});
    if let Some(source) = &flow.passport {
        payload["passport_evidence"] =
            serde_json::to_value(&source.evidence).map_err(|_| "issuance_failed")?;
    }
    let request = if let Some(encryption) = &encryption {
        let mut entropy = Zeroizing::new([0u8; 32]);
        let mut iv = [0u8; 12];
        UnwrapErr(SysRng).fill_bytes(&mut *entropy);
        UnwrapErr(SysRng).fill_bytes(&mut iv);
        let wire = encryption
            .prepare_request(payload, *entropy, iv)
            .map_err(|_| "issuance_failed")?;
        http.post(format!("{ISSUER}/credential"))
            .header("content-type", "application/jwt")
            .body(wire)
    } else {
        json_request(&http, format!("{ISSUER}/credential"), payload)?
    };
    if state
        .0
        .lock()
        .map_err(|_| "identity_unavailable")?
        .generation
        != guard.generation
    {
        return Err("cancelled".into());
    }
    let mut response = request
        .bearer_auth(&*access)
        .send()
        .await
        .map_err(|_| "network_error")?;
    // OID4VCI error responses are always JSON, including encrypted issuance.
    let issued = if !response.status().is_success() {
        body(response).await?
    } else {
        if response.status().as_u16() != 200 {
            return Err("invalid_response".into());
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .ok_or("invalid_response")?
            .to_owned();
        let mut wire = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| "network_error")? {
            if wire.len() + chunk.len() > 96 * 1024 {
                return Err("invalid_response".into());
            }
            wire.extend_from_slice(&chunk);
        }
        credential_transport::decode_success(&content_type, &wire, encryption.as_ref())?
    };
    passport::check_flow_owner(&app, &flow)?;
    let receipts = batch::verify_response(
        issued,
        flow.keys,
        &flow.configuration,
        issuer_key,
        kid.into(),
        flow.batch_claims.as_deref(),
        now()?,
    )?;
    let expires_at = receipts
        .iter()
        .map(|r| r.expires_at)
        .min()
        .ok_or("invalid_response")?;
    let format = receipts[0].format.clone();
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    if s.generation != guard.generation {
        return Err("cancelled".into());
    }
    let credential_count = receipts.len();
    if let Some(source) = flow.passport {
        if receipts.len() != 1 || s.current_receipts(&app, now()?)?.len() >= 8 {
            return Err("wallet_inventory_full".into());
        }
        s.passport_receipts.push((
            source.owner,
            receipts.into_iter().next().ok_or("invalid_response")?,
        ));
    } else {
        s.install_receipts(&app, receipts)?;
    }
    Ok(ReceiveResult {
        state: "received",
        credential_count: Some(credential_count),
        expires_at: Some(expires_at),
        format: Some(format),
    })
}
#[tauri::command]
pub fn clear_identity_credential(
    app: AppHandle,
    state: State<'_, IdentityState>,
) -> Result<(), String> {
    crate::identity_reader::cancel_active_read(&app)?;
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    s.invalidate_presentations();
    s.evidence = None;
    s.flow = None;
    s.haip = None;
    s.haip_state = "cancelled";
    s.receipt = None;
    s.receipts.clear();
    s.passport_receipts.clear();
    s.passport_review = None;
    #[cfg(target_os = "android")]
    {
        s.proximity = None;
        if let Some(id) = s.proximity_id.take() {
            use tauri_plugin_identity_proximity::IdentityProximityExt;
            app.identity_proximity().close(&id);
        }
    }
    identity_wallet::erase(&app)?;
    Ok(())
}
#[derive(Serialize)]
pub struct CredentialStatus {
    state: &'static str,
    expires_at: Option<u64>,
    format: Option<String>,
    credential_count: usize,
}
// Android restores an authenticated receipt against its existing, non-exportable holder key.
#[tauri::command]
pub fn identity_credential_status(
    app: AppHandle,
    state: State<'_, IdentityState>,
) -> Result<CredentialStatus, String> {
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    let receipts = s.current_receipts(&app, now()?)?;
    if let Some(receipt) = receipts.last() {
        let holder = receipt.key.public()?;
        if receipt.credential.is_empty() || holder.verifying_key().is_err() {
            return Err("invalid_credential".into());
        }
        Ok(CredentialStatus {
            state: "received",
            credential_count: receipts
                .iter()
                .filter(|r| r.expires_at > now().unwrap_or(u64::MAX))
                .count(),
            expires_at: Some(receipt.expires_at),
            format: Some(receipt.format.clone()),
        })
    } else {
        Ok(CredentialStatus {
            state: "empty",
            credential_count: 0,
            expires_at: None,
            format: None,
        })
    }
}

/// Verified display metadata only. Credentials, proofs and holder keys stay native.
#[derive(Serialize)]
pub struct WalletCard {
    id: String,
    title: &'static str,
    issuer: &'static str,
    format: String,
    expires_at: u64,
    fields: Value,
}
#[tauri::command]
pub fn identity_wallet_inventory(
    app: AppHandle,
    state: State<'_, IdentityState>,
) -> Result<Vec<WalletCard>, String> {
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    let at = now()?;
    let receipts = s.current_receipts(&app, at)?;
    let mut cards = Vec::new();
    for receipt in &receipts {
        if receipt.expires_at <= at {
            continue;
        }
        let (expires_at, claims) = receipt.verified_values(ISSUER, at)?;
        let mut fields = serde_json::Map::new();
        for field in [
            "name",
            "address",
            "birthdate",
            "gender",
            "document_expiry_date",
            "age_over_18",
            "age_over_20",
        ]
        .into_iter()
        .chain(mikaki_identity::passport::credential::FIELDS)
        {
            if let Some(value) = claims.get(field) {
                fields.insert(field.into(), value.clone());
            }
        }
        cards.push(WalletCard {
            id: credential_hash(&receipt.credential),
            title: if claims["document_type"] == "passport" {
                "旅券MRZ属性証明"
            } else {
                "Mikaki本人確認属性証明"
            },
            issuer: ISSUER,
            format: receipt.format.clone(),
            expires_at,
            fields: Value::Object(fields),
        });
    }
    Ok(cards)
}
/// Fixed product navigation carries no proof, credential or authority.
#[cfg_attr(not(any(target_os = "android", target_os = "ios")), allow(dead_code))]
pub fn receive_product_link(app: &AppHandle, url: &url::Url) -> bool {
    if url.as_str() != "mikaki-wallet:" {
        return false;
    }
    use tauri::Emitter;
    let _ = app.emit("product-wallet-ready", ());
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = crate::web::show_wallet(&handle);
    });
    true
}

#[tauri::command]
pub fn open_identity_management(app: AppHandle) -> Result<(), String> {
    app.opener()
        .open_url(format!("{ROOT}/identity"), None::<&str>)
        .map_err(|_| "browser_unavailable".into())
}

fn credential_hash(s: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(s.as_bytes()))
}
fn verifier_registry() -> Result<Vec<mikaki_identity::presentation::VerifierRegistration>, String> {
    let registry: Vec<mikaki_identity::presentation::VerifierRegistration> =
        serde_json::from_str(option_env!("MIKAKI_OID4VP_VERIFIERS").unwrap_or("[]"))
            .map_err(|_| "verifier_configuration_invalid")?;
    if registry.is_empty() || registry.len() > 32 {
        return Err("verifier_not_configured".into());
    }
    let mut seen = std::collections::HashSet::new();
    for r in &registry {
        let u = url::Url::parse(&r.response_uri).map_err(|_| "verifier_configuration_invalid")?;
        if r.client_id.is_empty()
            || r.client_id.len() > 128
            || r.validate_identifier().is_err()
            || !seen.insert(&r.client_id)
            || u.scheme() != "https"
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
            || u.fragment().is_some()
        {
            return Err("verifier_configuration_invalid".into());
        }
        r.jwk
            .verifying_key()
            .map_err(|_| "verifier_configuration_invalid")?;
        if let Some(policy) = &r.certificate_trust {
            policy
                .validate()
                .map_err(|_| "verifier_configuration_invalid")?;
            if r.profile != mikaki_identity::presentation::Profile::Oid4vpFinalX509Hash
                && policy.dns_name.is_none()
            {
                return Err("verifier_configuration_invalid".into());
            }
        }
        if let Some(encryption) = &r.response_encryption {
            if matches!(
                r.profile,
                mikaki_identity::presentation::Profile::Oid4vpFinalRequestKeys
                    | mikaki_identity::presentation::Profile::Oid4vpFinalX509Hash
            ) {
                return Err("verifier_configuration_invalid".into());
            }
            encryption
                .validate()
                .map_err(|_| "verifier_configuration_invalid")?;
        }
    }
    Ok(registry)
}
#[derive(Serialize)]
pub struct PresentationReview {
    review_id: String,
    verifier_name: String,
    response_uri: String,
    values: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<Value>,
    retained_fields: Vec<String>,
    expires_at: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    credentials: Vec<inventory::CredentialReview>,
}
// Only authenticated provenance, never an undisclosed attribute value, enters consent UI.
fn presentation_source(receipt: &Receipt, at: u64) -> Result<Option<Value>, String> {
    let single_use = receipt.single_use(ISSUER, at)?;
    let (document_type, evidence) = if receipt.format == "mso_mdoc" {
        let validated = mdoc::verify_receipt(
            &receipt.credential,
            &receipt.issuer_key,
            &receipt.key.public()?,
            at,
        )
        .map_err(str::to_string)?;
        let Some(evidence) = validated.evidence else {
            return Ok(None);
        };
        (evidence["document_type"].clone(), evidence)
    } else {
        let validated = issuance::verify_receipt(
            &receipt.credential,
            &receipt.issuer_key,
            &receipt.issuer_kid,
            &receipt.key.public()?,
            ISSUER,
            at,
        )
        .map_err(str::to_string)?;
        (
            validated["document_type"].clone(),
            validated["evidence"].clone(),
        )
    };
    Ok(Some(
        json!({"document_type":document_type,"single_use":single_use,"predicate_source":evidence["predicate_source"],
        "assurance":evidence["assurance"],"verified_at":evidence["verified_at"],
        "live_possession_verified":evidence["live_possession_verified"],"government_credential":evidence["government_credential"]}),
    ))
}
#[tauri::command]
pub fn review_identity_presentation(
    app: AppHandle,
    state: State<'_, IdentityState>,
    request: String,
) -> Result<PresentationReview, String> {
    let guard = gate(&state)?;
    prepare_presentation(&app, &state, &request, &guard, None, None)
}
fn prepare_presentation(
    app: &AppHandle,
    state: &IdentityState,
    request: &str,
    guard: &Gate,
    expected_client: Option<&str>,
    retrieval: Option<&mut mikaki_identity::presentation::retrieval::RequestRetrieval>,
) -> Result<PresentationReview, String> {
    let request = Zeroizing::new(request.to_string());
    let mut wallet_nonce = [0; 32];
    UnwrapErr(SysRng).fill_bytes(&mut wallet_nonce);
    let registry = verifier_registry()?;
    let vct = format!("{ISSUER}/types/linked-document");
    let inventory_request = match retrieval {
        Some(retrieval) => retrieval.verify_inventory(&request, &registry, &vct, now()?),
        None => mikaki_identity::presentation::inventory::verify_request(
            &request,
            &registry,
            &vct,
            now()?,
        ),
    };
    match inventory_request {
        Ok(checked) => inventory::prepare(app, state, guard, expected_client, checked),
        Err("unsupported_inventory_profile") => {
            let checked = mikaki_identity::presentation::verify_request_with_wallet_nonce(
                &request,
                &registry,
                &vct,
                now()?,
                wallet_nonce,
            )
            .map_err(str::to_string)?;
            prepare_checked_presentation(app, state, guard, expected_client, checked)
        }
        Err(error) => Err(error.into()),
    }
}
fn prepare_checked_presentation(
    app: &AppHandle,
    state: &IdentityState,
    guard: &Gate,
    expected_client: Option<&str>,
    checked: mikaki_identity::presentation::ApprovedRequest,
) -> Result<PresentationReview, String> {
    if expected_client.is_some_and(|id| id != checked.client_id()) {
        return Err("untrusted_verifier".into());
    }
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    if s.generation != guard.generation {
        return Err("identity_cancelled".into());
    }
    let receipts = s.current_receipts(app, now()?)?;
    let (receipt, values) = inventory::single_selection(&receipts, &checked, now()?)?;
    let nonce_hash = credential_hash(&format!("{}:{}", checked.client_id(), checked.nonce()));
    if s.presented_nonces.contains(&nonce_hash) || s.presented_nonces.len() >= 256 {
        return Err("request_consumed".into());
    }
    let id = random();
    let review = PresentationReview {
        review_id: id.clone(),
        verifier_name: checked.verifier_name.clone(),
        response_uri: checked.response_uri().to_string(),
        values,
        source: presentation_source(receipt, now()?)?,
        retained_fields: checked.retained_fields.clone(),
        expires_at: checked.expires_at().min(receipt.expires_at),
        credentials: Vec::new(),
    };
    let hash = credential_hash(&receipt.credential);
    s.presentation = Some(PendingPresentation {
        id,
        expires_at: review.expires_at,
        request: checked,
        credential_hash: hash,
        inventory: None,
        bindings: Vec::new(),
    });
    Ok(review)
}
#[derive(Serialize)]
pub struct PresentationResult {
    state: &'static str,
}
#[derive(Serialize)]
pub struct OnlinePresentationResult {
    state: &'static str,
    completion: &'static str,
}
#[tauri::command]
pub async fn confirm_identity_presentation(
    app: AppHandle,
    state: State<'_, IdentityState>,
    review_id: String,
    approve: bool,
) -> Result<OnlinePresentationResult, String> {
    let guard = gate(&state)?;
    let pending = {
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        let pending = s.consume_review(&review_id)?;
        if !approve {
            return Ok(OnlinePresentationResult {
                state: "denied",
                completion: "not_requested",
            });
        }
        pending
    };
    let (token, encrypted) = if pending.inventory.is_some() {
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        (
            inventory::response(&pending, &s.current_receipts(&app, now()?)?, now()?)?,
            true,
        )
    } else {
        let (credential, key, issuer_key) = {
            let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
            if s.generation != guard.generation {
                return Err("cancelled".into());
            }
            let current = s.current_receipts(&app, now()?)?;
            let receipt = current
                .iter()
                .find(|r| credential_hash(&r.credential) == pending.credential_hash)
                .ok_or("credential_changed")?;
            if credential_hash(&receipt.credential) != pending.credential_hash
                || receipt.expires_at <= now()?
            {
                return Err("credential_expired".into());
            }
            receipt.validate(ISSUER, now()?)?;
            pending.request.check_credential_authorities(
                &receipt.credential,
                receipt.credential_trust.as_ref(),
                &receipt.issuer_key,
                now()?,
                receipt.expires_at,
            )?;
            (
                Zeroizing::new(receipt.credential.to_string()),
                receipt.key.clone(),
                receipt.issuer_key.clone(),
            )
        };
        let vp = if pending.request.format() == "mso_mdoc" {
            if now()? >= pending.request.expires_at() {
                return Err("request_expired".into());
            }
            let holder = key.public()?;
            let validated = mdoc::verify_receipt(&credential, &issuer_key, &holder, now()?)
                .map_err(str::to_string)?;
            let transcript = pending.request.mdoc_transcript().map_err(str::to_string)?;
            let authentication =
                mdoc::device_authentication(&transcript).map_err(str::to_string)?;
            let signature =
                key.sign_bytes(&mdoc::signature_input(&authentication).map_err(str::to_string)?)?;
            Zeroizing::new(
                mdoc::device_response(
                    &validated,
                    &pending.request.fields,
                    &transcript,
                    &signature,
                    &holder,
                )
                .map_err(str::to_string)?,
            )
        } else {
            let selected = Zeroizing::new(
                mikaki_identity::presentation::select_disclosures(&credential, &pending.request)
                    .map_err(str::to_string)?
                    .0,
            );
            let kb = key.sign(
                json!({"typ":"kb+jwt","alg":"ES256"}),
                mikaki_identity::presentation::binding_claims(&selected, &pending.request, now()?)
                    .map_err(str::to_string)?,
            )?;
            Zeroizing::new(format!("{}{kb}", *selected))
        };
        let encrypted = pending.request.response_encryption().is_some();
        let token = Zeroizing::new(if encrypted {
            let ephemeral = p256::SecretKey::generate_from_rng(&mut UnwrapErr(SysRng));
            let mut iv = [0; 12];
            UnwrapErr(SysRng).fill_bytes(&mut iv);
            mikaki_identity::presentation::encryption::encrypt_response(
                &vp,
                &pending.request,
                now()?,
                ephemeral,
                iv,
            )
            .map_err(str::to_string)?
        } else {
            serde_json::to_string(&mikaki_identity::presentation::response_body(
                &vp,
                &pending.request,
            ))
            .map_err(|_| "invalid_response")?
        });
        (token, encrypted)
    };
    let parameters = if encrypted {
        vec![("response", token.as_str())]
    } else {
        vec![
            ("vp_token", token.as_str()),
            ("state", pending.request.state().ok_or("invalid_request")?),
        ]
    };
    {
        let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        if pending.inventory.is_some() {
            inventory::validate(&pending, &s.current_receipts(&app, now()?)?, now()?)?;
        }
        if pending.expires_at <= now()? {
            return Err("request_expired".into());
        }
        let selected = if pending.inventory.is_some() {
            pending
                .bindings
                .iter()
                .map(|(_, hash)| hash.clone())
                .collect::<Vec<_>>()
        } else {
            vec![pending.credential_hash.clone()]
        };
        s.retire_age_receipts(&app, &selected, now()?)?;
    }
    // Storage and Keystore calls may take time. Retirement is irreversible,
    // but cancellation or expiry during that work still suppresses dispatch.
    {
        let s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        if pending.expires_at <= now()? {
            return Err("request_expired".into());
        }
    }
    let response =
        presentation_transport::deliver(&client()?, pending.request.response_uri(), &parameters)
            .await
            .map_err(str::to_string)?;
    let completion = completion::finish(&app, &guard, response, pending.request.client_id()).await;
    Ok(OnlinePresentationResult {
        state: "presented",
        completion,
    })
}

#[cfg(test)]
mod presentation_tests {
    use super::*;
    use mikaki_identity::{
        issuance::PublicJwk,
        presentation::{self, VerifierRegistration},
    };
    fn pending() -> PendingPresentation {
        let key = p256::ecdsa::SigningKey::from_slice(&[5; 32]).unwrap();
        let registry = VerifierRegistration {
            client_id: "fixture".into(),
            name: "Fixture".into(),
            response_uri: "https://fixture.example/response".into(),
            kid: "key".into(),
            jwk: PublicJwk::from_key(key.verifying_key()),
            certificate_trust: None,
            response_encryption: None,
            profile: mikaki_identity::presentation::Profile::Oid4vpFinal,
        };
        let request = issuance::sign_jwt(&key, json!({"typ":"oauth-authz-req+jwt","alg":"ES256","kid":"key"}), json!({"iss":"fixture","client_id":"fixture","aud":"https://self-issued.me/v2","response_type":"vp_token","response_mode":"direct_post","response_uri":registry.response_uri,"nonce":"N".repeat(43),"state":"S".repeat(43),"iat":1000,"exp":1120,"dcql_query":{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{"vct_values":["fixture-vct"]},"claims":[{"path":["name"]}]}]}})).unwrap();
        PendingPresentation {
            id: "review".into(),
            request: presentation::verify_request(&request, &[registry], "fixture-vct", 1000)
                .unwrap(),
            credential_hash: "exact-credential".into(),
            inventory: None,
            bindings: Vec::new(),
            expires_at: 1120,
        }
    }
    #[test]
    fn consent_id_is_bound_and_consumption_is_irreversible_even_when_cancelled() {
        let mut state = Inner {
            presentation: Some(pending()),
            ..Inner::default()
        };
        assert!(state.consume_review("other").is_err());
        assert!(state.presentation.is_some());
        assert_eq!(
            state.consume_review("review").unwrap().credential_hash,
            "exact-credential"
        );
        assert!(state.consume_review("review").is_err());
        state.presentation = Some(pending());
        assert!(matches!(state.consume_review("review"),Err(e) if e=="request_consumed"));
        assert!(state.presentation.is_none());
    }
    #[test]
    fn invalidation_removes_unconsumed_consent_without_resetting_replay_history() {
        let mut state = Inner {
            presentation: Some(pending()),
            ..Inner::default()
        };
        state.consume_review("review").unwrap();
        state.presentation = Some(pending());
        state.invalidate_presentations();
        assert!(matches!(state.consume_review("review"),Err(e) if e=="review_required"));
        state.presentation = Some(pending());
        assert!(matches!(state.consume_review("review"),Err(e) if e=="request_consumed"));
    }
    #[test]
    fn age_retirement_clears_the_legacy_cache_before_key_deletion_and_never_requeues() {
        use crate::identity_wallet::credential_trust_tests::receipt_with_profile;
        use std::cell::RefCell;
        const AT: u64 = 1791000000;
        for format in ["dc+sd-jwt", "mso_mdoc"] {
            let receipt = receipt_with_profile(
                format,
                3,
                ISSUER,
                &mikaki_identity::claim_profile::ClaimProfile::age_only(),
            );
            let selected = vec![credential_hash(&receipt.credential)];
            let mut state = Inner {
                receipt: Some(receipt.clone()),
                receipts: vec![receipt],
                ..Inner::default()
            };
            let events = RefCell::new(Vec::new());
            assert!(state
                .retire_age_receipts_with(
                    &selected,
                    AT,
                    |remaining, _| {
                        assert!(remaining.is_empty());
                        events.borrow_mut().push("persist");
                        Ok(())
                    },
                    |_| {
                        events.borrow_mut().push("destroy");
                        Err("wallet_key_unavailable".into())
                    }
                )
                .is_err());
            assert_eq!(*events.borrow(), vec!["persist", "destroy"]);
            assert!(state.receipts.is_empty() && state.receipt.is_none());
            assert!(state
                .retire_age_receipts_with(
                    &selected,
                    AT,
                    |_, _| panic!("cannot recover a consumed receipt"),
                    |_| panic!()
                )
                .is_err());
        }
    }
    #[test]
    fn storage_failure_leaves_unused_receipts_available_and_never_deletes_their_keys() {
        use crate::identity_wallet::credential_trust_tests::receipt_with_profile;
        const AT: u64 = 1791000000;
        let receipt = receipt_with_profile(
            "dc+sd-jwt",
            3,
            ISSUER,
            &mikaki_identity::claim_profile::ClaimProfile::age_only(),
        );
        let selected = vec![credential_hash(&receipt.credential)];
        let mut state = Inner {
            receipt: Some(receipt.clone()),
            receipts: vec![receipt],
            ..Inner::default()
        };
        assert!(state
            .retire_age_receipts_with(
                &selected,
                AT,
                |_, _| Err("wallet_storage_unavailable".into()),
                |_| panic!("storage failed; no dispatch or deletion")
            )
            .is_err());
        assert_eq!(state.receipts.len(), 1);
        assert!(state.receipt.is_some());
        assert!(state
            .retire_age_receipts_with(&selected, AT, |_, _| Ok(()), |_| Ok(()))
            .is_ok());
        assert!(state.receipts.is_empty() && state.receipt.is_none());
    }
    #[test]
    fn concurrent_confirmation_has_one_winner() {
        let state = Arc::new(Mutex::new(Inner {
            presentation: Some(pending()),
            ..Inner::default()
        }));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let state = state.clone();
                std::thread::spawn(move || state.lock().unwrap().consume_review("review").is_ok())
            })
            .collect();
        assert_eq!(
            workers
                .into_iter()
                .filter_map(|t| t.join().ok())
                .filter(|v| *v)
                .count(),
            1
        );
    }
}
