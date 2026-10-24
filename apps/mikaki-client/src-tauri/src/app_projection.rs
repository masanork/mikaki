//! Unprivileged account projection validation, shared with host regression tests.
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Projection {
    pub subject: String,
    expires_at: u64,
    client_id: String,
}
impl Projection {
    pub fn read(bytes: &[u8], now: u64, client_id: &str) -> Result<(String, u64), String> {
        if bytes.len() > 4096 {
            return Err("invalid_session".into());
        }
        let projection: Self = serde_json::from_slice(bytes).map_err(|_| "invalid_session")?;
        if projection.client_id != client_id
            || projection.subject.len() != 43
            || !projection
                .subject
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || projection.expires_at <= now
        {
            return Err("invalid_session".into());
        }
        Ok((projection.subject, (projection.expires_at - now).min(20)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn stable_pairwise_owner_has_a_bounded_native_lease() {
        let value = json!({"subject":"s".repeat(43),"expires_at":200,"client_id":"client"});
        assert_eq!(
            Projection::read(value.to_string().as_bytes(), 100, "client").unwrap(),
            ("s".repeat(43), 20)
        );
        assert_eq!(
            Projection::read(value.to_string().as_bytes(), 199, "client")
                .unwrap()
                .1,
            1
        );
        assert!(Projection::read(value.to_string().as_bytes(), 200, "client").is_err());
        assert!(Projection::read(value.to_string().as_bytes(), 100, "other-client").is_err());
        for subject in ["owner-account", "", &"s".repeat(42), &"/".repeat(43)] {
            let invalid = json!({"subject":subject,"expires_at":200,"client_id":"client"});
            assert!(Projection::read(invalid.to_string().as_bytes(), 100, "client").is_err());
        }
        let unknown = json!({"subject":"s".repeat(43),"expires_at":200,"client_id":"client","access_token":"must-not-cross"});
        assert!(Projection::read(unknown.to_string().as_bytes(), 100, "client").is_err());
        assert!(Projection::read(&[b' '; 4097], 100, "client").is_err());
    }
}
