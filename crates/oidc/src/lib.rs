//! Static confidential ES256 OIDC profile and typed protocol state.
mod client_assertion;
mod code;
mod exchange;
mod signing;

pub use client_assertion::{
    ClientAssertionKey, ClientAssertionPolicy, InvalidClientAssertion, VerifiedClientAssertion,
    client_assertion_key_id,
};
pub use code::{
    CodeDigest, CodeEntropyError, CodeIssueError, CryptographicRandom, PresentedAuthorizationCode,
};
pub use exchange::{
    AuthenticatedTokenEndpointInput, AuthorizationCodeExchange, CodeExchangeInput,
    InvalidAuthenticatedTokenEndpointInput, InvalidCodeExchange, InvalidTokenEndpointInput,
    PRIVATE_KEY_JWT_ASSERTION_TYPE, PresentedClientAssertion, TokenEndpointInput,
    TokenEndpointInputError, ValidatedTokenEndpointInput,
};
pub use signing::{
    IdTokenSigningInput, InvalidIdTokenClaims, InvalidSigningKey, P256TokenSigner,
    RsaPrivateTokenKey,
};

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
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

/// An authorization request that has passed the static-client profile checks.
/// Fields are private and this type deliberately does not implement `Deserialize`.
///
/// ```compile_fail
/// let _: sakimori_oidc::ValidatedAuthorization = serde_json::from_str("{}").unwrap();
/// ```
#[must_use = "only a validated request may start an authorization transaction"]
pub struct ValidatedAuthorization {
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: Option<String>,
    code_challenge: String,
}

/// A validated authorization request paired with its one-time code material.
#[must_use = "commit this authorization atomically before returning the bearer code"]
pub struct PreparedAuthorizationCode {
    authorization: ValidatedAuthorization,
    code: code::IssuedAuthorizationCode,
}

impl PreparedAuthorizationCode {
    pub fn authorization(&self) -> &ValidatedAuthorization {
        &self.authorization
    }

    pub fn expires_at(&self) -> u64 {
        self.code.expires_at()
    }

    pub fn into_parts(
        self,
    ) -> (
        ValidatedAuthorization,
        PresentedAuthorizationCode,
        CodeDigest,
        u64,
    ) {
        let (presented, digest, expires_at) = self.code.into_parts();
        (self.authorization, presented, digest, expires_at)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAuthorization;

impl Authorization {
    pub fn validate(
        &self,
        client_id: &str,
        redirect_uri: &str,
        state_limit: usize,
        nonce_limit: usize,
    ) -> Result<ValidatedAuthorization, InvalidAuthorization> {
        let challenge = B64
            .decode(&self.code_challenge)
            .map_err(|_| InvalidAuthorization)?;
        if self.client_id != client_id
            || self.redirect_uri != redirect_uri
            || self.response_type != "code"
            || self.scope != "openid"
            || self.state.is_empty()
            || self.state.len() > state_limit
            || self
                .nonce
                .as_ref()
                .is_some_and(|nonce| nonce.is_empty() || nonce.len() > nonce_limit)
            || self.code_challenge_method != "S256"
            || challenge.len() != 32
            || B64.encode(challenge) != self.code_challenge
        {
            return Err(InvalidAuthorization);
        }
        Ok(ValidatedAuthorization {
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            state: self.state.clone(),
            nonce: self.nonce.clone(),
            code_challenge: self.code_challenge.clone(),
        })
    }
}

impl ValidatedAuthorization {
    pub fn prepare_code(
        self,
        random: &mut impl CryptographicRandom,
        now: u64,
        lifetime_seconds: u64,
        parent_expires_at: u64,
    ) -> Result<PreparedAuthorizationCode, CodeIssueError> {
        let code =
            code::issue_authorization_code(random, now, lifetime_seconds, parent_expires_at)?;
        Ok(PreparedAuthorizationCode {
            authorization: self,
            code,
        })
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
    pub fn state(&self) -> &str {
        &self.state
    }
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }
    pub fn code_challenge(&self) -> &str {
        &self.code_challenge
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
            nonce: Some("nonce".into()),
            code_challenge: pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap(),
            code_challenge_method: "S256".into(),
        };
        let validate =
            |r: &Authorization| r.validate("client", "https://app.example/callback", 256, 256);
        let validated = validate(&request).unwrap();
        assert_eq!(validated.client_id(), "client");
        assert_eq!(validated.redirect_uri(), "https://app.example/callback");
        assert_eq!(validated.state(), "state");
        assert_eq!(validated.nonce(), Some("nonce"));
        assert_eq!(validated.code_challenge(), request.code_challenge);
        request.nonce = None;
        assert_eq!(validate(&request).unwrap().nonce(), None);
        request.nonce = Some("nonce".into());
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
            assert!(validate(&changed).is_err());
        }
        request.state = "x".repeat(257);
        assert!(validate(&request).is_err());
        request.state = "s".into();
        request.nonce = Some("x".repeat(257));
        assert!(validate(&request).is_err());
        request.nonce = Some("n".into());
        request.code_challenge.push('=');
        assert!(validate(&request).is_err());
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
