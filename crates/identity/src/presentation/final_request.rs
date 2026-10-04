//! Static-discovery x509_hash request compatibility; consent remains locally bounded.
use super::*;
pub(super) fn parse(value: &Value, now: u64, bound_post: bool) -> Result<Request, &'static str> {
    let source = value.as_object().ok_or("invalid_request")?;
    // Known unsupported features must not turn into ignored extensions.
    if [
        "transaction_data",
        "scope",
        "redirect_uri",
        "expected_origins",
        "presentation_definition",
        "client_id_scheme",
        "require_signed_request_object",
    ]
    .iter()
    .any(|k| source.contains_key(*k))
    {
        return Err("unsupported_request_feature");
    }
    if source.contains_key("wallet_nonce") && !bound_post {
        return Err("unsupported_request_feature");
    }
    let (iat, exp) = times(source, now)?;
    let mut supported = serde_json::Map::new();
    for field in [
        "iss",
        "aud",
        "client_id",
        "response_type",
        "response_mode",
        "response_uri",
        "nonce",
        "state",
        "dcql_query",
        "client_metadata",
    ] {
        if let Some(value) = source.get(field) {
            supported.insert(field.into(), value.clone());
        }
    }
    // Signed expiry can shorten, never extend, this review's two-minute local deadline.
    supported.insert("iat".into(), json!(iat.unwrap_or(now)));
    supported.insert(
        "exp".into(),
        json!(exp.unwrap_or(u64::MAX).min(now.saturating_add(120))),
    );
    let request: Request =
        serde_json::from_value(Value::Object(supported)).map_err(|_| "invalid_request")?;
    if !(16..=512).contains(&request.nonce.len())
        || request.nonce.chars().any(char::is_control)
        || request
            .state
            .as_ref()
            .is_some_and(|s| s.len() > 2048 || s.chars().any(char::is_control))
    {
        return Err("invalid_request");
    }
    Ok(request)
}
/// Validate constraints against the actual supported issuer/holder algorithm and curve.
pub(super) fn validate_formats(metadata: &Value, format: &str) -> Result<(), &'static str> {
    let formats = metadata["vp_formats_supported"]
        .as_object()
        .filter(|m| !m.is_empty() && m.len() <= 16)
        .ok_or("vp_formats_not_supported")?;
    let selected = formats
        .get(format)
        .and_then(Value::as_object)
        .ok_or("vp_formats_not_supported")?;
    let names = match format {
        "dc+sd-jwt" => ["sd-jwt_alg_values", "kb-jwt_alg_values"],
        "mso_mdoc" => ["issuerauth_alg_values", "deviceauth_alg_values"],
        _ => return Err("vp_formats_not_supported"),
    };
    for name in names {
        if let Some(value) = selected.get(name) {
            let values = value
                .as_array()
                .filter(|v| !v.is_empty() && v.len() <= 16)
                .ok_or("vp_formats_not_supported")?;
            let mut matches = false;
            for alg in values {
                if format == "dc+sd-jwt" {
                    let alg = alg
                        .as_str()
                        .filter(|s| !s.is_empty() && s.len() <= 64)
                        .ok_or("vp_formats_not_supported")?;
                    matches |= alg == "ES256";
                } else {
                    let alg = alg.as_i64().ok_or("vp_formats_not_supported")?;
                    // COSE ES256 (-7) and fully specified ESP256 (-9) both match P-256/SHA-256.
                    matches |= matches!(alg, -7 | -9);
                }
            }
            if !matches {
                return Err("vp_formats_not_supported");
            }
        }
    }
    Ok(())
}

pub(super) fn times(
    source: &serde_json::Map<String, Value>,
    now: u64,
) -> Result<(Option<u64>, Option<u64>), &'static str> {
    let timestamp = |name: &str| -> Result<Option<u64>, &'static str> {
        source
            .get(name)
            .map(|v| v.as_u64().ok_or("invalid_request"))
            .transpose()
    };
    let iat = timestamp("iat")?;
    let exp = timestamp("exp")?;
    let nbf = timestamp("nbf")?;
    if iat.is_some_and(|at| at > now.saturating_add(30))
        || exp.is_some_and(|at| at <= now)
        || nbf.is_some_and(|at| at > now)
        || iat.zip(exp).is_some_and(|(a, b)| b <= a)
        || nbf.zip(exp).is_some_and(|(a, b)| b <= a)
    {
        return Err("invalid_request");
    }
    Ok((iat, exp))
}
