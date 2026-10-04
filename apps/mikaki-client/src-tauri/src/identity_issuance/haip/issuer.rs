//! Pinned issuer transport. Only an explicit DPoP nonce challenge permits one retry.
use super::*;
use mikaki_identity::issuance_encryption::WalletEncryption;
use std::future::Future;

pub(super) fn strict(bytes: &[u8]) -> Result<Value, String> {
    mikaki_identity::wallet_profile::strict_json(bytes)
}
async fn json(mut r: Response, status: u16, limit: usize) -> Result<Value, String> {
    if r.status().as_u16() != status
        || r.headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            .is_none_or(|v| !v.eq_ignore_ascii_case("application/json"))
        || r.content_length().is_some_and(|n| n > limit as u64)
    {
        return Err("invalid_response".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = r.chunk().await.map_err(|_| "network_error")? {
        if bytes.len() + chunk.len() > limit {
            return Err("invalid_response".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    strict(&bytes)
}
fn live(guard: &Gate) -> Result<(), String> {
    if guard
        .state
        .lock()
        .is_ok_and(|s| s.generation == guard.generation)
    {
        Ok(())
    } else {
        Err("cancelled".into())
    }
}
fn nonce(r: &Response) -> Result<Option<String>, String> {
    let values: Vec<_> = r.headers().get_all("dpop-nonce").iter().collect();
    if values.len() > 1 {
        return Err("invalid_response".into());
    }
    values
        .first()
        .map(|v| {
            let value = v.to_str().map_err(|_| "invalid_response")?;
            if value.is_empty() || value.len() > 128 || !value.bytes().all(|b| b.is_ascii_graphic())
            {
                return Err("invalid_response".into());
            }
            Ok(value.to_string())
        })
        .transpose()
}
async fn challenge(r: Response) -> Result<String, String> {
    let status = r.status().as_u16();
    if !matches!(status, 400 | 401) {
        return Err("issuance_failed".into());
    }
    let nonce = nonce(&r)?.ok_or("invalid_response")?;
    let value = json(r, status, 4096).await?;
    if value["error"] != "use_dpop_nonce" {
        return Err("issuance_failed".into());
    }
    Ok(nonce)
}
fn headers(
    mut r: openidconnect::reqwest::RequestBuilder,
    h: Value,
) -> Result<openidconnect::reqwest::RequestBuilder, String> {
    for (k, v) in h.as_object().ok_or("invalid_request")? {
        r = r.header(k, v.as_str().ok_or("invalid_request")?);
    }
    Ok(r)
}
pub(super) async fn form<F, Fut>(
    session: &mut Session,
    guard: &Gate,
    attestation: &str,
    trust: &[AttesterTrust],
    endpoint: &str,
    initial_nonce: Option<&str>,
    send: F,
) -> Result<(Value, Option<String>), String>
where
    F: Fn(openidconnect::reqwest::RequestBuilder) -> Fut,
    Fut: Future<Output = Result<Response, String>>,
{
    if !matches!(endpoint, "par" | "token") {
        return Err("invalid_request".into());
    }
    let mut current = initial_nonce.map(str::to_owned);
    for attempt in 0..2 {
        live(guard)?;
        let parameters = if endpoint == "par" {
            session.protocol.par_parameters(now()?)?
        } else {
            session.protocol.token_parameters(now()?)?
        };
        let encoded = {
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in parameters.as_object().ok_or("invalid_request")? {
                encoded.append_pair(k, v.as_str().ok_or("invalid_request")?);
            }
            Zeroizing::new(encoded.finish())
        };
        let mut auth = session.client_headers(attestation, trust)?;
        auth["DPoP"] = json!(session.dpop(endpoint, current.as_deref())?);
        let request = headers(
            client()?
                .post(format!("{ISSUER}/{endpoint}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(encoded.to_string()),
            auth,
        )?;
        let r = send(request).await?;
        live(guard)?;
        let expected = if endpoint == "par" { 201 } else { 200 };
        if r.status().as_u16() == expected {
            let next = nonce(&r)?;
            let value = json(r, expected, 32768).await?;
            live(guard)?;
            return Ok((value, next.or(current)));
        }
        if attempt == 1 {
            return Err("issuance_failed".into());
        }
        current = Some(challenge(r).await?);
    }
    Err("issuance_failed".into())
}
pub(super) async fn send(r: openidconnect::reqwest::RequestBuilder) -> Result<Response, String> {
    r.send().await.map_err(|_| "network_error".into())
}
pub(super) struct Context {
    pub encryption: WalletEncryption,
    pub issuer_key: PublicJwk,
    pub issuer_kid: String,
}
fn validate_metadata(metadata: &Value, oauth: &Value, configuration: &str) -> Result<(), String> {
    mikaki_identity::wallet_profile::validate_metadata(metadata, oauth, configuration)
}
pub(super) async fn metadata(guard: &Gate, configuration: &str) -> Result<Context, String> {
    live(guard)?;
    let http = client()?;
    let metadata = json(
        send(http.get(format!(
            "{ROOT}/.well-known/openid-credential-issuer/identity/issuer"
        )))
        .await?,
        200,
        49152,
    )
    .await?;
    live(guard)?;
    let oauth = json(
        send(http.get(format!(
            "{ROOT}/.well-known/oauth-authorization-server/identity/issuer"
        )))
        .await?,
        200,
        16384,
    )
    .await?;
    validate_metadata(&metadata, &oauth, configuration)?;
    live(guard)?;
    let jwks = json(send(http.get(format!("{ISSUER}/jwks"))).await?, 200, 8192).await?;
    let (key, kid) = mikaki_identity::wallet_profile::issuer_key(&jwks)?;
    let mut entropy = Zeroizing::new([0; 32]);
    OsRng.fill_bytes(&mut *entropy);
    let encryption = WalletEncryption::from_metadata(&metadata, *entropy, &random())
        .map_err(|_| "invalid_metadata")?
        .ok_or("invalid_metadata")?;
    if encryption.request_key().map_err(str::to_string)? == key {
        return Err("invalid_metadata".into());
    }
    live(guard)?;
    Ok(Context {
        encryption,
        issuer_key: key,
        issuer_kid: kid,
    })
}
pub(super) async fn credential_nonce(guard: &Gate) -> Result<String, String> {
    live(guard)?;
    let value = json(
        send(client()?.post(format!("{ISSUER}/nonce"))).await?,
        200,
        4096,
    )
    .await?;
    let nonce = value["c_nonce"]
        .as_str()
        .filter(|v| valid_id(v))
        .ok_or("invalid_response")?
        .to_owned();
    live(guard)?;
    Ok(nonce)
}
pub(super) async fn credential<F, Fut>(
    session: &Session,
    guard: &Gate,
    context: &Context,
    payload: Value,
    send: F,
) -> Result<Value, String>
where
    F: Fn(openidconnect::reqwest::RequestBuilder) -> Fut,
    Fut: Future<Output = Result<Response, String>>,
{
    let mut current = None;
    for attempt in 0..2 {
        live(guard)?;
        let mut entropy = Zeroizing::new([0; 32]);
        let mut iv = [0; 12];
        OsRng.fill_bytes(&mut *entropy);
        OsRng.fill_bytes(&mut iv);
        let wire = Zeroizing::new(
            context
                .encryption
                .prepare_request(payload.clone(), *entropy, iv)
                .map_err(str::to_string)?,
        );
        let r = send(
            client()?
                .post(format!("{ISSUER}/credential"))
                .header("content-type", "application/jwt")
                .header(
                    "authorization",
                    &*session.protocol.authorization_header(now()?)?,
                )
                .header("dpop", session.dpop("credential", current.as_deref())?)
                .body(wire.to_string()),
        )
        .await?;
        live(guard)?;
        if r.status().as_u16() == 200 {
            let mut r = r;
            let media = r
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .ok_or("invalid_response")?
                .to_owned();
            if r.content_length().is_some_and(|n| n > 98304) {
                return Err("invalid_response".into());
            }
            let mut bytes = Zeroizing::new(Vec::new());
            while let Some(chunk) = r.chunk().await.map_err(|_| "network_error")? {
                if bytes.len() + chunk.len() > 98304 {
                    return Err("invalid_response".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            if !media
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/jwt")
            {
                return Err("invalid_response".into());
            }
            let compact = std::str::from_utf8(&bytes).map_err(|_| "invalid_response")?;
            let plain = context
                .encryption
                .decrypt_response(compact)
                .map_err(|_| "invalid_response")?;
            let value = strict(&plain)?;
            live(guard)?;
            return Ok(value);
        }
        if attempt == 1 {
            return Err("issuance_failed".into());
        }
        current = Some(challenge(r).await?);
    }
    Err("issuance_failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ambiguous_json_and_non_nonce_errors_never_allow_retry() {
        assert!(strict(br#"{"access_token":"a","access_token":"b"}"#).is_err());
        assert!(strict(br#"{"keys":[{"x":"a","x":"b"}]}"#).is_err());
        tauri::async_runtime::block_on(async {
            for (status, body, nonce, ok) in [
                (400, "use_dpop_nonce", Some("nonce"), true),
                (401, "use_dpop_nonce", Some("nonce"), true),
                (302, "use_dpop_nonce", Some("nonce"), false),
                (400, "invalid_grant", Some("nonce"), false),
                (400, "use_dpop_nonce", None, false),
            ] {
                let mut r = openidconnect::http::Response::builder()
                    .status(status)
                    .header("content-type", "application/json");
                if let Some(n) = nonce {
                    r = r.header("dpop-nonce", n);
                }
                let r: Response = r.body(json!({"error":body}).to_string()).unwrap().into();
                assert_eq!(challenge(r).await.is_ok(), ok);
            }
        });
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod integration_tests;
