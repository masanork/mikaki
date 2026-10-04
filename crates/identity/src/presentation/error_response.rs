//! Credential-free errors, only for a bound and independently authenticated x509_hash request.
use super::*;
pub enum Outcome {
    Approved(Box<ApprovedRequest>),
    Error(Box<ProtocolError>),
}
pub struct ProtocolError {
    response_uri: String,
    code: &'static str,
    state: Option<String>,
    nonce: Option<String>,
    recipient: encryption::ResponseEncryption,
    deadline: u64,
    hash: String,
}
impl ProtocolError {
    pub fn response_uri(&self) -> &str {
        &self.response_uri
    }
    pub fn code(&self) -> &'static str {
        self.code
    }
    pub fn expires_at(&self) -> u64 {
        self.deadline
    }
    pub fn request_hash(&self) -> &str {
        &self.hash
    }
    /// Consumes the error context. No signing/holder key or credential is needed.
    pub fn encrypt(
        self,
        now: u64,
        ephemeral: p256::SecretKey,
        iv: [u8; 12],
    ) -> Result<String, &'static str> {
        if now >= self.deadline {
            return Err("request_expired");
        }
        let mut payload = json!({"error":self.code});
        if let Some(state) = self.state {
            payload["state"] = json!(state);
        }
        encryption::encrypt_payload(
            &self.recipient,
            self.nonce.as_deref(),
            None,
            &payload,
            ephemeral,
            iv,
        )
    }
}
pub(super) fn authorize(
    compact: &str,
    registry: &[VerifierRegistration],
    retrieval: &retrieval::RequestRetrieval,
    vct: &str,
    now: u64,
) -> Result<ProtocolError, &'static str> {
    let abort = "silent_rejection";
    if compact.len() > 16384 || registry.len() > 32 {
        return Err(abort);
    }
    let (input, sig) = compact.rsplit_once('.').ok_or(abort)?;
    let (h, p) = input.split_once('.').ok_or(abort)?;
    let header: Header =
        serde_json::from_slice(&B64.decode(h).map_err(|_| abort)?).map_err(|_| abort)?;
    if header.typ != "oauth-authz-req+jwt" || header.alg != "ES256" {
        return Err(abort);
    }
    let value = crate::wallet_profile::strict_json(&B64.decode(p).map_err(|_| abort)?)
        .map_err(|_| abort)?;
    let source = value.as_object().ok_or(abort)?;
    let clients: Vec<_> = registry
        .iter()
        .filter(|r| value["client_id"].as_str() == Some(r.client_id.as_str()))
        .collect();
    let [registered] = clients.as_slice() else {
        return Err(abort);
    };
    if registered.profile != Profile::Oid4vpFinalX509Hash {
        return Err(abort);
    }
    registered.validate_identifier()?;
    retrieval.check(&value, registered, now)?;
    if value["aud"] != "https://self-issued.me/v2"
        || value["response_type"] != "vp_token"
        || value["response_mode"] != "direct_post.jwt"
        || value["response_uri"].as_str() != Some(registered.response_uri.as_str())
    {
        return Err(abort);
    }
    let uri = url::Url::parse(&registered.response_uri).map_err(|_| abort)?;
    if uri.scheme() != "https"
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
        || uri.fragment().is_some()
    {
        return Err(abort);
    }
    let (_, exp) = final_request::times(source, now)?;
    let policy = registered.certificate_trust.as_ref().ok_or(abort)?;
    let chain = header
        .x5c
        .as_ref()
        .filter(|c| !c.is_empty() && c.len() <= 4)
        .ok_or(abort)?
        .iter()
        .map(|s| crate::certificate::decode_certificate(s))
        .collect::<Result<Vec<_>, _>>()?;
    let deadline = crate::certificate::verify_x509_hash_reader_chain(
        &chain,
        policy,
        &registered.jwk,
        &registered.client_id,
        now,
    )?
    .min(retrieval.expires_at())
    .min(exp.unwrap_or(u64::MAX))
    .min(now.saturating_add(120));
    let signature =
        Signature::from_slice(&B64.decode(sig).map_err(|_| abort)?).map_err(|_| abort)?;
    registered
        .jwk
        .verifying_key()?
        .verify(input.as_bytes(), &signature)
        .map_err(|_| abort)?;
    let text = |name: &str, min: usize, max: usize| -> Result<Option<String>, &'static str> {
        value
            .get(name)
            .map(|v| {
                v.as_str()
                    .filter(|s| (min..=max).contains(&s.len()) && !s.chars().any(char::is_control))
                    .map(str::to_owned)
                    .ok_or(abort)
            })
            .transpose()
    };
    let nonce = text("nonce", 16, 512)?;
    let state = text("state", 0, 2048)?;
    let recipient = encryption::from_client_metadata(value.get("client_metadata").ok_or(abort)?)?;
    if recipient.jwk == registered.jwk {
        return Err(abort);
    }
    // Only a fully understood, impossible linked-document query can be denied.
    // Unsupported features are never relabeled as missing credentials.
    let code = if nonce.is_none() || source.contains_key("redirect_uri") {
        "invalid_request"
    } else if source.contains_key("transaction_data") {
        "invalid_transaction_data"
    } else {
        let query: Dcql = serde_json::from_value(value.get("dcql_query").ok_or(abort)?.clone())
            .map_err(|_| abort)?;
        // Other known unsupported authorization features remain silent rejections.
        final_request::parse(&value, now, retrieval.method() == retrieval::Method::Post)?;
        if dcql::select(&query, vct).err() != Some("credential_query_unsatisfied") {
            return Err(abort);
        }
        "access_denied"
    };
    Ok(ProtocolError {
        response_uri: registered.response_uri.clone(),
        code,
        state,
        nonce,
        recipient,
        deadline,
        hash: B64.encode(Sha256::digest(compact.as_bytes())),
    })
}
