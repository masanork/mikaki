//! Native OID4VP HTTP transport. Callers supply already pinned/approved endpoints.
use openidconnect::reqwest::{Client, Response};
use zeroize::Zeroizing;

pub async fn retrieve(
    builder: openidconnect::reqwest::RequestBuilder,
) -> Result<Zeroizing<String>, &'static str> {
    let mut response = builder.send().await.map_err(|_| "network_error")?;
    if !response.status().is_success()
        || response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::trim)
            != Some("application/oauth-authz-req+jwt")
        || response.content_length().is_some_and(|n| n > 16 * 1024)
    {
        return Err("invalid_response");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| "network_error")? {
        if bytes.len() + chunk.len() > 16 * 1024 {
            return Err("invalid_response");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Zeroizing::new(
        std::str::from_utf8(&bytes)
            .map_err(|_| "invalid_response")?
            .to_owned(),
    ))
}

pub async fn deliver(
    client: &Client,
    uri: &str,
    parameters: &[(&str, &str)],
) -> Result<Response, &'static str> {
    let response = client
        .post(uri)
        .form(parameters)
        .send()
        .await
        .map_err(|_| "presentation_network_error")?;
    if !response.status().is_success() {
        return Err("presentation_rejected");
    }
    Ok(response)
}
