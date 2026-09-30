//! Narrow RFC 8707 / RFC 9396 profile for a single Vault ciphertext read.

use serde::Deserialize;

pub const RESOURCE: &str = "https://mikaki.tossa.app/vault-api/";
pub const DETAIL_TYPE: &str = "https://mikaki.tossa.app/authorization-details/vault-read-v1";
const ACTION: &str = "read_ciphertext";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidVaultReadRequest;

/// The exact resource and attribute that must be carried into owner consent,
/// authorization-code context, and token validation without broadening.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "carry the validated attribute and resource into the grant"]
pub struct VaultReadRequest {
    attribute: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Detail {
    #[serde(rename = "type")]
    kind: String,
    locations: Vec<String>,
    actions: Vec<String>,
    attribute: String,
}

impl VaultReadRequest {
    pub fn parse(
        scope: &str,
        resource: &str,
        authorization_details: &str,
    ) -> Result<Self, InvalidVaultReadRequest> {
        if !matches!(scope, "openid vault.read" | "vault.read openid")
            || resource != RESOURCE
            || authorization_details.len() > 2048
        {
            return Err(InvalidVaultReadRequest);
        }
        let mut details: Vec<Detail> =
            serde_json::from_str(authorization_details).map_err(|_| InvalidVaultReadRequest)?;
        if details.len() != 1 {
            return Err(InvalidVaultReadRequest);
        }
        let detail = details.pop().ok_or(InvalidVaultReadRequest)?;
        if detail.kind != DETAIL_TYPE
            || detail.locations != [RESOURCE]
            || detail.actions != [ACTION]
            || !matches!(detail.attribute.as_str(), "name" | "owner_note")
        {
            return Err(InvalidVaultReadRequest);
        }
        Ok(Self {
            attribute: detail.attribute,
        })
    }

    pub fn attribute(&self) -> &str {
        &self.attribute
    }

    pub fn resource(&self) -> &'static str {
        RESOURCE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detail(attribute: &str) -> String {
        serde_json::json!([{
            "type": DETAIL_TYPE,
            "locations": [RESOURCE],
            "actions": [ACTION],
            "attribute": attribute
        }])
        .to_string()
    }

    #[test]
    fn binds_one_attribute_to_the_vault_resource() {
        for scope in ["openid vault.read", "vault.read openid"] {
            let request = VaultReadRequest::parse(scope, RESOURCE, &detail("owner_note")).unwrap();
            assert_eq!(request.attribute(), "owner_note");
            assert_eq!(request.resource(), RESOURCE);
        }
        assert!(VaultReadRequest::parse("openid vault.read", RESOURCE, &detail("name")).is_ok());
    }

    #[test]
    fn rejects_broader_and_ambiguous_authority() {
        for scope in [
            "openid",
            "vault.read",
            "openid vault.read vault.write",
            "openid vault.read vault.read",
            "openid\tvault.read",
            "openid  vault.read",
        ] {
            assert!(VaultReadRequest::parse(scope, RESOURCE, &detail("name")).is_err());
        }
        for resource in [
            "https://mikaki.tossa.app/userinfo",
            "https://mikaki.tossa.app/vault-api",
            "https://evil.example/vault-api/",
        ] {
            assert!(
                VaultReadRequest::parse("openid vault.read", resource, &detail("name")).is_err()
            );
        }
        for details in [
            detail("password"),
            "[]".into(),
            format!(
                "[{},{}]",
                &detail("name")[1..detail("name").len() - 1],
                &detail("owner_note")[1..detail("owner_note").len() - 1]
            ),
            format!(
                r#"[{{"type":"{DETAIL_TYPE}","locations":["{RESOURCE}"],"actions":["{ACTION}"],"attribute":"name","attribute":"owner_note"}}]"#
            ),
            format!(
                r#"[{{"type":"{DETAIL_TYPE}","locations":["{RESOURCE}"],"actions":["{ACTION}"],"attribute":"name","extra":true}}]"#
            ),
        ] {
            assert!(VaultReadRequest::parse("openid vault.read", RESOURCE, &details).is_err());
        }
    }
}
