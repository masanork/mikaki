//! First-party OID4VCI flow. Evidence, grant secrets and separate holder keys stay in Rust.
mod completion;
mod credential_transport;
pub mod haip;
mod inventory;
pub mod invocation;
mod presentation_transport;
pub mod proximity;
use crate::identity_wallet::{self, HolderKey, Receipt};
use mikaki_identity::{
    card::{CardFailure, FailureCode},
    evidence::Evidence,
    issuance::{self, PublicJwk},
    mdoc,
};
use openidconnect::reqwest::{Client, Response};
use rand_core::{OsRng, RngCore};
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
    key: HolderKey,
    created: Instant,
    configuration: String,
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
    fn install_receipt(&mut self, app: &AppHandle, receipt: Receipt) -> Result<(), String> {
        self.restore_receipts(app)?;
        let at = now()?;
        let mut inventory: Vec<_> = self
            .receipts
            .iter()
            .filter(|r| r.expires_at > at)
            .cloned()
            .collect();
        if inventory.len() >= 8 {
            return Err("wallet_inventory_full".into());
        }
        if inventory
            .iter()
            .any(|r| credential_hash(&r.credential) == credential_hash(&receipt.credential))
        {
            return Err("credential_already_saved".into());
        }
        inventory.push(receipt.clone());
        identity_wallet::save_inventory(app, &inventory)?;
        for old in self.receipts.iter().filter(|r| r.expires_at <= at) {
            let _ = old.key.destroy();
        }
        self.receipts = inventory;
        self.receipt = Some(receipt);
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
    OsRng.fill_bytes(&mut bytes);
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
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid_response")?;
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
pub fn clear_identity_evidence(state: State<'_, IdentityState>) -> Result<(), String> {
    state.0.lock().map_err(|_| "identity_unavailable")?.evidence = None;
    Ok(())
}
#[derive(Serialize)]
pub struct LinkStarted {
    holder_thumbprint: String,
    expires_in: u64,
}
#[tauri::command]
pub async fn start_identity_link(
    app: AppHandle,
    state: State<'_, IdentityState>,
    configuration: Option<String>,
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
    let key = HolderKey::create(&app)?; // Dedicated holder key, never login DPoP.
    let holder = key.public()?;
    let http = client()?;
    let response = body(
        json_request(
            &http,
            format!("{ROOT}/identity/intake"),
            json!({"evidence":evidence,"holder_jwk":holder}),
        )?
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
    let thumbprint = holder.thumbprint().map_err(str::to_string)?;
    if response["approval_url"] != url
        || response["holder_thumbprint"] != thumbprint
        || response["expires_in"] != 600
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
            key,
            created: Instant::now(),
            configuration,
        });
    }
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|_| "browser_unavailable")?;
    Ok(LinkStarted {
        holder_thumbprint: thumbprint,
        expires_in: 600,
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
    let http = client()?;
    let response = body(
        json_request(
            &http,
            format!("{ROOT}/identity/poll"),
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
                    || ids.len() > 2
                    || !ids.contains(&json!(flow.configuration))
                    || ids
                        .iter()
                        .any(|id| id != issuance::CONFIGURATION && id != mdoc::CONFIGURATION)
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
    OsRng.fill_bytes(&mut *recipient_entropy);
    let encryption = mikaki_identity::issuance_encryption::WalletEncryption::from_metadata(
        &metadata,
        *recipient_entropy,
        &random(),
    )
    .map_err(|_| "invalid_metadata")?;
    if let Some(encryption) = &encryption {
        let request_key = encryption.request_key().map_err(|_| "invalid_metadata")?;
        if request_key == issuer_key || request_key == flow.key.public()? {
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
        || token["expires_in"] != 120
        || token["scope"] != "linked_document"
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
    let proof = Zeroizing::new(flow.key.proof(ISSUER, nonce, now()?, &random())?);
    let payload =
        json!({"credential_configuration_id":flow.configuration,"proofs":{"jwt":[&*proof]}});
    let request = if let Some(encryption) = &encryption {
        let mut entropy = Zeroizing::new([0u8; 32]);
        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut *entropy);
        OsRng.fill_bytes(&mut iv);
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
    let credentials = issued["credentials"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("invalid_response")?;
    let credential = Zeroizing::new(
        credentials[0]["credential"]
            .as_str()
            .ok_or("invalid_response")?
            .to_string(),
    );
    let holder = flow.key.public()?;
    let format = if flow.configuration == mdoc::CONFIGURATION {
        "mso_mdoc"
    } else {
        "dc+sd-jwt"
    };
    let expires_at = if format == "mso_mdoc" {
        mdoc::verify_receipt(&credential, &issuer_key, &holder, now()?)
            .map_err(str::to_string)?
            .expires_at
    } else {
        issuance::verify_receipt(&credential, &issuer_key, kid, &holder, ISSUER, now()?)
            .map_err(str::to_string)?["exp"]
            .as_u64()
            .ok_or("invalid_credential")?
    };
    let mut s = state.0.lock().map_err(|_| "identity_unavailable")?;
    if s.generation != guard.generation {
        return Err("cancelled".into());
    }
    let receipt = Receipt {
        credential,
        format: format.into(),
        key: flow.key,
        expires_at,
        issuer_key,
        issuer_kid: kid.to_string(),
        credential_trust: None,
    };
    s.install_receipt(&app, receipt)?;
    Ok(ReceiveResult {
        state: "received",
        expires_at: Some(expires_at),
        format: Some(format.into()),
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
    s.restore_receipts(&app)?;
    if let Some(receipt) = &s.receipt {
        let holder = receipt.key.public()?;
        if receipt.credential.is_empty() || holder.verifying_key().is_err() {
            return Err("invalid_credential".into());
        }
        Ok(CredentialStatus {
            state: "received",
            credential_count: s
                .receipts
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
    retained_fields: Vec<String>,
    expires_at: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    credentials: Vec<inventory::CredentialReview>,
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
    OsRng.fill_bytes(&mut wallet_nonce);
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
    s.restore_receipts(app)?;
    let (receipt, values) = inventory::single_selection(&s.receipts, &checked, now()?)?;
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
        let s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        (inventory::response(&pending, &s.receipts, now()?)?, true)
    } else {
        let (credential, key, issuer_key) = {
            let s = state.0.lock().map_err(|_| "identity_unavailable")?;
            if s.generation != guard.generation {
                return Err("cancelled".into());
            }
            let receipt = s
                .receipts
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
            Zeroizing::new(format!("{}{kb}", &*selected))
        };
        let encrypted = pending.request.response_encryption().is_some();
        let token = Zeroizing::new(if encrypted {
            let ephemeral = p256::SecretKey::random(&mut OsRng);
            let mut iv = [0; 12];
            OsRng.fill_bytes(&mut iv);
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
        let s = state.0.lock().map_err(|_| "identity_unavailable")?;
        if s.generation != guard.generation {
            return Err("cancelled".into());
        }
        if pending.inventory.is_some() {
            inventory::validate(&pending, &s.receipts, now()?)?;
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
