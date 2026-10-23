//! Public registration shared by packaging and host-side regression checks.
pub fn mobile_client_id(override_id: Option<String>) -> Result<String, String> {
    let registration: serde_json::Value =
        serde_json::from_str(include_str!("../mobile-client-registration.json"))
            .map_err(|_| "invalid bundled mobile registration")?;
    if registration["sector_identifier"] != "app.mikaki.org"
        || registration["redirect_uris"]
            != serde_json::json!(["https://app.mikaki.org/oidc/native/callback"])
    {
        return Err("unexpected bundled mobile registration".into());
    }
    let id = override_id
        .or_else(|| registration["client_id"].as_str().map(str::to_owned))
        .ok_or("mobile client ID missing")?;
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid MIKAKI_MOBILE_CLIENT_ID".into());
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_builds_include_the_registered_public_client() {
        assert!(!env!("MIKAKI_MOBILE_CLIENT_ID").is_empty());
        assert_eq!(
            mobile_client_id(None).unwrap(),
            "dfd936fd-f33d-4f82-ae39-f25e08ec7948"
        );
    }

    #[test]
    fn explicit_invalid_override_must_not_fall_back() {
        for id in ["", " ", "id\n", "https://wrong.example"] {
            assert!(mobile_client_id(Some(id.into())).is_err());
        }
        assert_eq!(
            mobile_client_id(Some("test-client".into())).unwrap(),
            "test-client"
        );
    }
}
