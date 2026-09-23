use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const PRIVATE_KEY_JWT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Untrusted token endpoint fields. Client identity is deliberately absent:
/// it must come from an independently verified client assertion.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeExchangeInput {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub code_verifier: String,
}

/// Untrusted RFC 6749 token request with the private_key_jwt profile fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenEndpointInput {
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
    client_id: String,
    client_assertion_type: String,
    client_assertion: String,
}

/// Compact assertion remains a bearer credential until verification; it is
/// intentionally not printable or serializable after input validation.
pub struct PresentedClientAssertion(String);

#[must_use = "authenticate the client and then atomically exchange the code"]
pub struct ValidatedTokenEndpointInput {
    client_id: String,
    exchange: AuthorizationCodeExchange,
    assertion: PresentedClientAssertion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTokenEndpointInput;

/// A canonical code digest and PKCE challenge ready for a conditional store operation.
/// The bearer code and verifier are not retained after validation.
#[must_use = "exchange only after client authentication, and consume atomically in the store"]
pub struct AuthorizationCodeExchange {
    code_digest: String,
    redirect_uri: String,
    pkce_challenge: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidCodeExchange;

impl CodeExchangeInput {
    pub fn validate(self) -> Result<AuthorizationCodeExchange, InvalidCodeExchange> {
        if self.grant_type != "authorization_code"
            || self.code.len() != 43
            || self.redirect_uri.is_empty()
            || self.redirect_uri.len() > 2048
            || self
                .redirect_uri
                .bytes()
                .any(|byte| byte.is_ascii_control())
        {
            return Err(InvalidCodeExchange);
        }
        let raw_code = B64.decode(&self.code).map_err(|_| InvalidCodeExchange)?;
        if raw_code.len() != 32 || B64.encode(&raw_code) != self.code {
            return Err(InvalidCodeExchange);
        }
        let pkce_challenge = super::pkce(&self.code_verifier).ok_or(InvalidCodeExchange)?;
        Ok(AuthorizationCodeExchange {
            code_digest: B64.encode(Sha256::digest(raw_code)),
            redirect_uri: self.redirect_uri,
            pkce_challenge,
        })
    }
}

impl AuthorizationCodeExchange {
    /// Digest used to find the stored code; never the bearer code itself.
    pub fn code_digest(&self) -> &str {
        &self.code_digest
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Compare this derived challenge inside the final conditional D1 write.
    pub fn pkce_challenge(&self) -> &str {
        &self.pkce_challenge
    }
}

impl TokenEndpointInput {
    pub fn validate(self) -> Result<ValidatedTokenEndpointInput, InvalidTokenEndpointInput> {
        if self.grant_type != "authorization_code"
            || self.client_assertion_type != PRIVATE_KEY_JWT_ASSERTION_TYPE
            || self.client_id.is_empty()
            || self.client_id.len() > 128
            || self.client_id.bytes().any(|byte| byte.is_ascii_control())
            || self.client_assertion.is_empty()
            || self.client_assertion.len() > 16_384
        {
            return Err(InvalidTokenEndpointInput);
        }
        let exchange = CodeExchangeInput {
            grant_type: self.grant_type,
            code: self.code,
            redirect_uri: self.redirect_uri,
            code_verifier: self.code_verifier,
        }
        .validate()
        .map_err(|_| InvalidTokenEndpointInput)?;
        Ok(ValidatedTokenEndpointInput {
            client_id: self.client_id,
            exchange,
            assertion: PresentedClientAssertion(self.client_assertion),
        })
    }
}

impl PresentedClientAssertion {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ValidatedTokenEndpointInput {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn exchange(&self) -> &AuthorizationCodeExchange {
        &self.exchange
    }

    pub fn assertion(&self) -> &PresentedClientAssertion {
        &self.assertion
    }
}
