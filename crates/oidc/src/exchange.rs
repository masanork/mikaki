use crate::VerifiedClientAssertion;
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
    code_verifier: Option<String>,
    client_id: Option<String>,
    client_assertion_type: String,
    client_assertion: String,
}

/// A public native client's token request. This validates syntax and PKCE but
/// does not authenticate the application. The adapter must check that the
/// client is registered as public and consume the code atomically.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicTokenEndpointInput {
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
    client_id: String,
    resource: Option<String>,
}

#[must_use = "bind this request to a registered public client and one-use code"]
pub struct ValidatedPublicTokenEndpointInput {
    client_id: String,
    exchange: AuthorizationCodeExchange,
    resource: Option<String>,
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

/// A validated token request paired with the verified client assertion that
/// authenticated that same client for this exact token endpoint.
#[must_use = "consume the code only with this authenticated token request"]
pub struct AuthenticatedTokenEndpointInput {
    client_id: String,
    exchange: AuthorizationCodeExchange,
    assertion: VerifiedClientAssertion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTokenEndpointInput;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenEndpointInputError {
    UnsupportedGrantType,
    InvalidClient,
    InvalidRequest,
    InvalidGrant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAuthenticatedTokenEndpointInput;

/// A canonical code digest and PKCE challenge ready for a conditional store operation.
/// The bearer code and verifier are not retained after validation.
#[must_use = "exchange only after client authentication, and consume atomically in the store"]
#[derive(Clone)]
pub struct AuthorizationCodeExchange {
    code_digest: String,
    redirect_uri: String,
    pkce_challenge: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidCodeExchange;

impl CodeExchangeInput {
    pub fn validate(self) -> Result<AuthorizationCodeExchange, InvalidCodeExchange> {
        self.validate_with_optional_pkce(false)
    }

    pub fn validate_with_optional_pkce(
        self,
        allow_missing_pkce: bool,
    ) -> Result<AuthorizationCodeExchange, InvalidCodeExchange> {
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
        let pkce_challenge = if allow_missing_pkce && self.code_verifier.is_empty() {
            String::new()
        } else {
            super::pkce(&self.code_verifier).ok_or(InvalidCodeExchange)?
        };
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
    pub fn validate(
        self,
        max_assertion_bytes: usize,
    ) -> Result<ValidatedTokenEndpointInput, TokenEndpointInputError> {
        self.validate_with_client_id_policy(max_assertion_bytes, false)
    }

    /// FAPI private_key_jwt permits an omitted form `client_id`; the assertion
    /// issuer is only a lookup hint until the registered key verifies it.
    pub fn validate_for_fapi(
        self,
        max_assertion_bytes: usize,
    ) -> Result<ValidatedTokenEndpointInput, TokenEndpointInputError> {
        self.validate_with_client_id_policy(max_assertion_bytes, true)
    }

    fn validate_with_client_id_policy(
        self,
        max_assertion_bytes: usize,
        allow_missing_client_id: bool,
    ) -> Result<ValidatedTokenEndpointInput, TokenEndpointInputError> {
        if self.grant_type != "authorization_code" {
            return Err(TokenEndpointInputError::UnsupportedGrantType);
        }
        let client_id = match self.client_id {
            Some(client_id) => client_id,
            None if allow_missing_client_id => {
                crate::client_assertion_issuer(&self.client_assertion, max_assertion_bytes)
                    .map_err(|_| TokenEndpointInputError::InvalidClient)?
            }
            None => return Err(TokenEndpointInputError::InvalidClient),
        };
        if self.client_assertion_type != PRIVATE_KEY_JWT_ASSERTION_TYPE
            || client_id.is_empty()
            || client_id.len() > 128
            || client_id.bytes().any(|byte| byte.is_ascii_control())
            || self.client_assertion.is_empty()
            || max_assertion_bytes == 0
            || self.client_assertion.len() > max_assertion_bytes
        {
            return Err(TokenEndpointInputError::InvalidClient);
        }
        let code_verifier = match self.code_verifier {
            Some(value) => value,
            None if allow_missing_client_id => return Err(TokenEndpointInputError::InvalidGrant),
            None => return Err(TokenEndpointInputError::InvalidRequest),
        };
        let exchange = CodeExchangeInput {
            grant_type: self.grant_type,
            code: self.code,
            redirect_uri: self.redirect_uri,
            code_verifier,
        }
        .validate()
        .map_err(|_| TokenEndpointInputError::InvalidRequest)?;
        Ok(ValidatedTokenEndpointInput {
            client_id,
            exchange,
            assertion: PresentedClientAssertion(self.client_assertion),
        })
    }
}

impl PublicTokenEndpointInput {
    pub fn validate(self) -> Result<ValidatedPublicTokenEndpointInput, TokenEndpointInputError> {
        if self.client_id.is_empty()
            || self.client_id.len() > 128
            || self.client_id.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(TokenEndpointInputError::InvalidClient);
        }
        if self.grant_type != "authorization_code" {
            return Err(TokenEndpointInputError::UnsupportedGrantType);
        }
        let exchange = CodeExchangeInput {
            grant_type: self.grant_type,
            code: self.code,
            redirect_uri: self.redirect_uri,
            code_verifier: self.code_verifier,
        }
        .validate()
        .map_err(|_| TokenEndpointInputError::InvalidRequest)?;
        Ok(ValidatedPublicTokenEndpointInput {
            client_id: self.client_id,
            exchange,
            resource: self.resource,
        })
    }
}

impl ValidatedPublicTokenEndpointInput {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn exchange(&self) -> &AuthorizationCodeExchange {
        &self.exchange
    }

    pub fn resource(&self) -> Option<&str> {
        self.resource.as_deref()
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

    /// Bind the request's client and token endpoint to its verified assertion.
    /// The assertion must already have been signature-checked and reserved in
    /// the replay store by the platform adapter.
    pub fn authenticate(
        self,
        assertion: VerifiedClientAssertion,
        token_endpoint: &str,
    ) -> Result<AuthenticatedTokenEndpointInput, InvalidAuthenticatedTokenEndpointInput> {
        if token_endpoint.is_empty()
            || self.client_id != assertion.client_id()
            || assertion.audience() != token_endpoint
        {
            return Err(InvalidAuthenticatedTokenEndpointInput);
        }
        Ok(AuthenticatedTokenEndpointInput {
            client_id: self.client_id,
            exchange: self.exchange,
            assertion,
        })
    }
}

impl AuthenticatedTokenEndpointInput {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn exchange(&self) -> &AuthorizationCodeExchange {
        &self.exchange
    }

    pub fn assertion(&self) -> &VerifiedClientAssertion {
        &self.assertion
    }
}
