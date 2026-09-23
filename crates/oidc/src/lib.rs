//! Policy for the static, confidential ES256 client profile. JOSE uses jose/WebCrypto.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}
impl Authorization {
    pub fn valid(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state_limit: usize,
        nonce_limit: usize,
    ) -> bool {
        self.client_id == client_id
            && self.redirect_uri == redirect_uri
            && self.response_type == "code"
            && self.scope == "openid"
            && !self.state.is_empty()
            && self.state.len() <= state_limit
            && !self.nonce.is_empty()
            && self.nonce.len() <= nonce_limit
            && self.code_challenge_method == "S256"
            && B64
                .decode(&self.code_challenge)
                .is_ok_and(|b| b.len() == 32 && B64.encode(b) == self.code_challenge)
    }
}
pub fn pkce(verifier: &str) -> Option<String> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
    {
        return None;
    }
    Some(B64.encode(Sha256::digest(verifier.as_bytes())))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_profile_rejects_redirect_scope_pkce_and_parameter_changes() {
        let mut request = Authorization {
            client_id: "client".into(),
            redirect_uri: "https://app.example/callback".into(),
            response_type: "code".into(),
            scope: "openid".into(),
            state: "state".into(),
            nonce: "nonce".into(),
            code_challenge: pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap(),
            code_challenge_method: "S256".into(),
        };
        let valid = |r: &Authorization| r.valid("client", "https://app.example/callback", 256, 256);
        assert!(valid(&request));
        for field in [
            "client_id",
            "redirect_uri",
            "response_type",
            "scope",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method",
        ] {
            let mut value = serde_json::to_value(&request).unwrap();
            value[field] = serde_json::json!("");
            let changed: Authorization = serde_json::from_value(value).unwrap();
            assert!(!valid(&changed));
        }
        request.state = "x".repeat(257);
        assert!(!valid(&request));
        request.state = "s".into();
        request.nonce = "x".repeat(257);
        assert!(!valid(&request));
        request.nonce = "n".into();
        request.code_challenge.push('=');
        assert!(!valid(&request));
        let mut value = serde_json::to_value(&request).unwrap();
        value["prompt"] = serde_json::json!("none");
        assert!(serde_json::from_value::<Authorization>(value).is_err());
    }
    #[test]
    fn rfc7636_vector_and_invalid_verifiers() {
        assert_eq!(
            pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(pkce("short").is_none());
        assert!(pkce(&" ".repeat(43)).is_none());
    }
}
