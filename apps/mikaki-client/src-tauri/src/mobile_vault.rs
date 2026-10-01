//! Mobile Vault preview. Tokens and DPoP key stay in Rust memory and are
//! discarded on logout or process exit; no plaintext decryption is attempted.

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openidconnect::core::{CoreClient, CoreIdToken, CoreProviderMetadata};
use openidconnect::{AccessToken, AccessTokenHash, ClientId, IssuerUrl, Nonce, RedirectUrl};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::vault_dpop::{self, DpopKey};

const CALLBACK: &str = "https://app.mikaki.org/oidc/native/callback";
const TOKEN_ENDPOINT: &str = "https://auth.mikaki.org/token";
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

pub struct PendingVault {
    pub attribute: String,
    pub key: DpopKey,
}

pub struct StoredVault {
    pub attribute: String,
    pub key: DpopKey,
    access_token: Zeroizing<String>,
    expires_at: Instant,
    closed: AtomicBool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
    id_token: String,
    authorization_details: serde_json::Value,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ciphertext {
    pub format_version: u8,
    pub revision: i64,
    pub ciphertext: String,
    pub owner_envelope: String,
}

fn http_client() -> Result<openidconnect::reqwest::Client, String> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "Vault HTTP client unavailable".into())
}

async fn bounded(mut response: openidconnect::reqwest::Response) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err("Vault response too large".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Vault response unavailable")?
    {
        if chunk.len() > MAX_RESPONSE_BYTES - bytes.len() {
            return Err("Vault response too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

pub async fn exchange(
    code: String,
    verifier: &str,
    nonce: &Nonce,
    pending: PendingVault,
) -> Result<StoredVault, String> {
    let client_id = option_env!("MIKAKI_MOBILE_CLIENT_ID")
        .filter(|id| !id.is_empty())
        .ok_or("mobile client ID is not configured")?;
    let http = http_client()?;
    let provider = CoreProviderMetadata::discover_async(
        IssuerUrl::new(vault_dpop::ISSUER.to_owned()).map_err(|_| "invalid configured issuer")?,
        &http,
    )
    .await
    .map_err(|_| "OIDC discovery failed")?;
    let client =
        CoreClient::from_provider_metadata(provider, ClientId::new(client_id.into()), None)
            .set_redirect_uri(RedirectUrl::new(CALLBACK.into()).map_err(|_| "invalid callback")?);
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code.as_str()),
        ("redirect_uri", CALLBACK),
        ("code_verifier", verifier),
        ("resource", vault_dpop::RESOURCE),
    ];
    let mut challenge_nonce: Option<String> = None;
    let mut reply = None;
    for attempt in 0..2 {
        let proof = pending
            .key
            .proof("POST", TOKEN_ENDPOINT, None, challenge_nonce.as_deref())?;
        let response = http
            .post(TOKEN_ENDPOINT)
            .header("DPoP", proof)
            .form(&form)
            .send()
            .await
            .map_err(|_| "Vault token exchange unavailable")?;
        let nonce_header = response
            .headers()
            .get("DPoP-Nonce")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let status = response.status();
        let bytes = bounded(response).await?;
        if attempt == 0
            && status.as_u16() == 400
            && serde_json::from_slice::<ErrorResponse>(&bytes)
                .ok()
                .is_some_and(|error| error.error == "use_dpop_nonce")
            && nonce_header.is_some()
        {
            challenge_nonce = nonce_header;
            continue;
        }
        if status.as_u16() != 200 {
            return Err("Vault token exchange rejected".into());
        }
        reply = Some(bytes);
        break;
    }
    let response: TokenResponse =
        serde_json::from_slice(&reply.ok_or("Vault token exchange rejected")?)
            .map_err(|_| "invalid Vault token response")?;
    if response.token_type != "DPoP"
        || response.scope != "openid vault.read"
        || response.expires_in == 0
        || response.expires_in > 3600
        || response.access_token.len() != 43
        || !response
            .access_token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || response.authorization_details
            != serde_json::from_str::<serde_json::Value>(&vault_dpop::detail(&pending.attribute)?)
                .map_err(|_| "invalid Vault detail")?
    {
        return Err("invalid Vault token response".into());
    }
    let id_token = CoreIdToken::from_str(&response.id_token).map_err(|_| "invalid ID Token")?;
    let id_verifier = client.id_token_verifier();
    let claims = id_token
        .claims(&id_verifier, nonce)
        .map_err(|_| "ID Token validation failed")?;
    if let Some(expected) = claims.access_token_hash() {
        let actual = AccessTokenHash::from_token(
            &AccessToken::new(response.access_token.clone()),
            id_token
                .signing_alg()
                .map_err(|_| "invalid ID Token algorithm")?,
            id_token
                .signing_key(&id_verifier)
                .map_err(|_| "invalid ID Token key")?,
        )
        .map_err(|_| "access token hash could not be checked")?;
        if actual != *expected {
            return Err("access token hash mismatch".into());
        }
    }
    Ok(StoredVault {
        attribute: pending.attribute,
        key: pending.key,
        access_token: Zeroizing::new(response.access_token),
        expires_at: Instant::now() + Duration::from_secs(response.expires_in),
        closed: AtomicBool::new(false),
    })
}

impl StoredVault {
    pub fn is_live(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && Instant::now() < self.expires_at
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub async fn read(&self) -> Result<Ciphertext, String> {
        if !self.is_live() {
            return Err("Vault grant expired".into());
        }
        let url = format!(
            "{}/vault-api/attributes/{}",
            vault_dpop::ISSUER,
            self.attribute
        );
        let http = http_client()?;
        let mut challenge_nonce: Option<String> = None;
        for attempt in 0..2 {
            if self.closed.load(Ordering::Acquire) {
                return Err("Vault session closed".into());
            }
            let proof = self.key.proof(
                "GET",
                &url,
                Some(&self.access_token),
                challenge_nonce.as_deref(),
            )?;
            let response = http
                .get(&url)
                .header(
                    "Authorization",
                    format!("DPoP {}", self.access_token.as_str()),
                )
                .header("DPoP", proof)
                .send()
                .await
                .map_err(|_| "Vault read unavailable")?;
            let nonce_header = response
                .headers()
                .get("DPoP-Nonce")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let status = response.status();
            let etag = response
                .headers()
                .get("ETag")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let bytes = bounded(response).await?;
            if attempt == 0
                && status.as_u16() == 401
                && serde_json::from_slice::<ErrorResponse>(&bytes)
                    .ok()
                    .is_some_and(|error| error.error == "use_dpop_nonce")
                && nonce_header.is_some()
            {
                challenge_nonce = nonce_header;
                continue;
            }
            if status.as_u16() != 200 {
                return Err("Vault ciphertext read rejected".into());
            }
            let value: Ciphertext =
                serde_json::from_slice(&bytes).map_err(|_| "invalid Vault ciphertext response")?;
            if value.format_version != 1
                || value.revision <= 0
                || URL_SAFE_NO_PAD
                    .decode(&value.ciphertext)
                    .map_or(true, |bytes| bytes.is_empty() || bytes.len() > 24 * 1024)
                || URL_SAFE_NO_PAD
                    .decode(&value.owner_envelope)
                    .map_or(true, |bytes| bytes.is_empty() || bytes.len() > 8 * 1024)
            {
                return Err("invalid Vault ciphertext response".into());
            }
            if etag.as_deref() != Some(format!("\"{}\"", value.revision).as_str()) {
                return Err("Vault revision mismatch".into());
            }
            if self.closed.load(Ordering::Acquire) {
                return Err("Vault session closed".into());
            }
            return Ok(value);
        }
        Err("Vault ciphertext read rejected".into())
    }
}
