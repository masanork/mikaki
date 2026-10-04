//! Request URI POST metadata/nonce exchange. No credential inventory or device identifiers.
use super::*;
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    Get,
    Post,
}
/// Static capabilities for the implemented x509_hash profile, not a compliance claim.
pub fn wallet_metadata() -> Value {
    json!({
        "response_types_supported":["vp_token"],
        "response_modes_supported":["direct_post.jwt"],
        "client_id_prefixes_supported":["x509_hash"],
        "request_object_signing_alg_values_supported":["ES256"],
        "authorization_encryption_alg_values_supported":["ECDH-ES"],
        "authorization_encryption_enc_values_supported":["A256GCM"],
        "vp_formats_supported":{
            "dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]},
            "mso_mdoc":{"issuerauth_alg_values":[-7],"deviceauth_alg_values":[-7]}
        }
    })
}
pub struct RequestRetrieval {
    client_id: String,
    profile: Profile,
    method: Method,
    nonce: Option<String>,
    expires: u64,
    consumed: bool,
}
pub enum InventoryOutcome {
    Approved(Box<inventory::InventoryRequest>),
    Error(Box<error_response::ProtocolError>),
}
impl RequestRetrieval {
    pub fn evaluate_inventory(
        &mut self,
        compact: &str,
        registry: &[VerifierRegistration],
        vct: &str,
        now: u64,
    ) -> Result<InventoryOutcome, &'static str> {
        if self.consumed {
            return Err("request_consumed");
        }
        self.consumed = true;
        match inventory::verify_inner(compact, registry, vct, now, Some(self)) {
            Ok(request) if request.type_feasible() => {
                Ok(InventoryOutcome::Approved(Box::new(request)))
            }
            Ok(_) => error_response::authorize(compact, registry, self, vct, now)
                .map(|error| InventoryOutcome::Error(Box::new(error))),
            Err(failure) => error_response::authorize(compact, registry, self, vct, now)
                .map(|error| InventoryOutcome::Error(Box::new(error)))
                .map_err(|_| failure),
        }
    }
    /// Caller supplies fresh native CSPRNG entropy, never data from invocation or WebView.
    pub fn new(
        registered: &VerifierRegistration,
        method: Method,
        now: u64,
        entropy: [u8; 32],
    ) -> Result<Self, &'static str> {
        registered.validate_identifier()?;
        if registered.profile != Profile::Oid4vpFinalX509Hash {
            return Err("unsupported_retrieval_profile");
        }
        Ok(Self {
            client_id: registered.client_id.clone(),
            profile: registered.profile,
            method,
            nonce: if method == Method::Post {
                Some(B64.encode(entropy))
            } else {
                None
            },
            expires: now.saturating_add(120),
            consumed: false,
        })
    }
    pub fn method(&self) -> Method {
        self.method
    }
    pub fn expires_at(&self) -> u64 {
        self.expires
    }
    pub fn form(&self) -> Result<Vec<(String, String)>, &'static str> {
        if self.consumed {
            return Err("request_consumed");
        }
        Ok(match &self.nonce {
            Some(nonce) => vec![
                (
                    "wallet_metadata".into(),
                    serde_json::to_string(&wallet_metadata()).map_err(|_| "invalid_request")?,
                ),
                ("wallet_nonce".into(), nonce.clone()),
            ],
            None => vec![],
        })
    }
    pub(super) fn check(
        &self,
        payload: &Value,
        registered: &VerifierRegistration,
        now: u64,
    ) -> Result<(), &'static str> {
        if now >= self.expires {
            return Err("request_expired");
        }
        if self.profile != registered.profile || self.client_id != registered.client_id {
            return Err("untrusted_verifier");
        }
        match &self.nonce {
            Some(nonce)
                if payload.get("wallet_nonce").and_then(Value::as_str) == Some(nonce.as_str()) =>
            {
                Ok(())
            }
            None if payload.get("wallet_nonce").is_none() => Ok(()),
            _ => Err("invalid_wallet_nonce"),
        }
    }
    /// One-use evaluation; only independently authenticated failures can produce an error.
    pub fn evaluate(
        &mut self,
        compact: &str,
        registry: &[VerifierRegistration],
        vct: &str,
        now: u64,
    ) -> Result<error_response::Outcome, &'static str> {
        if self.consumed {
            return Err("request_consumed");
        }
        self.consumed = true;
        match verify_request_inner(compact, registry, vct, now, None, Some(self)) {
            Ok(request) => Ok(error_response::Outcome::Approved(Box::new(request))),
            Err(failure) => error_response::authorize(compact, registry, self, vct, now)
                .map(|error| error_response::Outcome::Error(Box::new(error)))
                .map_err(|_| failure),
        }
    }
    /// Authenticate the complete Final query before consulting a local credential inventory.
    pub fn verify_inventory(
        &mut self,
        compact: &str,
        registry: &[VerifierRegistration],
        vct: &str,
        now: u64,
    ) -> Result<inventory::InventoryRequest, &'static str> {
        if self.consumed {
            return Err("request_consumed");
        }
        self.consumed = true;
        inventory::verify_inner(compact, registry, vct, now, Some(self))
    }
    /// Any verification attempt consumes this context, including invalid signed responses.
    pub fn verify(
        &mut self,
        compact: &str,
        registry: &[VerifierRegistration],
        vct: &str,
        now: u64,
    ) -> Result<ApprovedRequest, &'static str> {
        if self.consumed {
            return Err("request_consumed");
        }
        self.consumed = true;
        verify_request_inner(compact, registry, vct, now, None, Some(self))
    }
}
