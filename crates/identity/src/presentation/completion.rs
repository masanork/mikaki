//! Bounded acknowledgement and exact registered browser completion destination.
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub client_id: String,
    pub redirect_uri: String,
}
#[derive(Deserialize)]
struct Acknowledgement {
    #[serde(default, deserialize_with = "non_null_uri")]
    redirect_uri: Option<String>,
}
fn non_null_uri<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
pub fn parse(
    bytes: &[u8],
    client_id: &str,
    registry: &[Registration],
) -> Result<Option<url::Url>, &'static str> {
    if bytes.len() > 8192 || bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err("invalid_response");
    }
    let ack: Acknowledgement = serde_json::from_slice(bytes).map_err(|_| "invalid_response")?;
    let Some(value) = ack.redirect_uri else {
        return Ok(None);
    };
    if value.len() > 2048 || value.chars().any(char::is_control) || registry.len() > 32 {
        return Err("completion_rejected");
    }
    let entries: Vec<_> = registry
        .iter()
        .filter(|r| r.client_id == client_id)
        .collect();
    if entries.len() != 1 {
        return Err("completion_rejected");
    }
    let endpoint = url::Url::parse(&entries[0].redirect_uri).map_err(|_| "completion_rejected")?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err("completion_rejected");
    }
    let uri = url::Url::parse(&value).map_err(|_| "completion_rejected")?;
    let mut base = uri.clone();
    base.set_query(None);
    base.set_fragment(None);
    if base != endpoint || uri.query().is_some() == uri.fragment().is_some() {
        return Err("completion_rejected");
    }
    // Annex B peers may return the fresh verifier code as a raw fragment.
    // Keep it opaque and preserve its exact bytes for the browser.
    if uri.fragment().is_some_and(|code| {
        (43..=128).contains(&code.len())
            && code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    }) {
        return Ok(Some(uri));
    }
    let parameters: Vec<_> = url::form_urlencoded::parse(
        uri.query()
            .or(uri.fragment())
            .ok_or("completion_rejected")?
            .as_bytes(),
    )
    .collect();
    if parameters.len() != 1 || parameters[0].0 != "response_code" {
        return Err("completion_rejected");
    }
    let code = parameters[0].1.as_ref();
    // A bounded opaque code; freshness/entropy and one-use redemption are the
    // verifier's responsibility, not properties inferable from a URL.
    if !(22..=128).contains(&code.len())
        || !code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("completion_rejected");
    }
    Ok(Some(uri))
}
