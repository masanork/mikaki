//! Bounded preregistered OID4VP 1.0 direct_post profile, signed requests and SD-JWT+KB.
mod authorities;
pub mod completion;
mod dcql;
pub mod encryption;
pub mod error_response;
mod final_request;
pub mod inventory;
mod legacy;
pub mod retrieval;
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    Oid4vpFinal,
    Oid4vpFinalRequestKeys,
    Oid4vpFinalX509Hash,
    Oid4vpDraft18Mdoc,
}
use crate::issuance::{PublicJwk, sign_jwt};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{Signature, SigningKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierRegistration {
    pub client_id: String,
    pub name: String,
    pub response_uri: String,
    pub kid: String,
    pub jwk: PublicJwk,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_trust: Option<crate::certificate::ReaderTrust>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_encryption: Option<encryption::ResponseEncryption>,
    #[serde(default)]
    pub profile: Profile,
}
impl VerifierRegistration {
    /// Explicit profile selection prevents client-prefix downgrade or fallback.
    pub fn validate_identifier(&self) -> Result<(), &'static str> {
        if self.client_id.is_empty() || self.client_id.len() > 128 {
            return Err("invalid_verifier_identifier");
        }
        if self.profile == Profile::Oid4vpFinalX509Hash {
            let hash = self
                .client_id
                .strip_prefix("x509_hash:")
                .ok_or("invalid_verifier_identifier")?;
            let bytes = B64
                .decode(hash)
                .map_err(|_| "invalid_verifier_identifier")?;
            if bytes.len() != 32
                || B64.encode(bytes) != hash
                || self.certificate_trust.is_none()
                || self.response_encryption.is_some()
            {
                return Err("invalid_verifier_identifier");
            }
        } else if self.client_id.contains(':') {
            return Err("invalid_verifier_identifier");
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    #[serde(default, deserialize_with = "non_null_chain")]
    x5c: Option<Vec<String>>,
    typ: String,
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}
fn non_null_chain<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<String>>, D::Error> {
    Vec::<String>::deserialize(d).map(Some)
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    path: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intent_to_retain: Option<bool>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "dcql::non_null_types"
    )]
    vct_values: Option<Vec<String>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_state"
    )]
    doctype_value: Option<String>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Query {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "authorities::non_null"
    )]
    trusted_authorities: Option<Vec<authorities::Authority>>,
    id: String,
    format: String,
    meta: Meta,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "dcql::present_claims"
    )]
    claims: Vec<Claim>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Dcql {
    credentials: Vec<Query>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "dcql::non_null_sets"
    )]
    credential_sets: Option<Vec<dcql::CredentialSet>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    iss: Option<Value>,
    aud: String,
    client_id: String,
    response_type: String,
    response_mode: String,
    response_uri: String,
    nonce: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_state"
    )]
    state: Option<String>,
    iat: u64,
    exp: u64,
    dcql_query: Dcql,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "non_null_metadata"
    )]
    client_metadata: Option<Value>,
}
fn present_state<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}
fn non_null_metadata<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    let value = Value::deserialize(d)?;
    if !value.is_object() {
        return Err(serde::de::Error::custom("client metadata object required"));
    }
    Ok(Some(value))
}
#[derive(Clone)]
pub struct ApprovedRequest {
    request: Request,
    pub verifier_name: String,
    pub fields: Vec<String>,
    pub retained_fields: Vec<String>,
    pub request_hash: String,
    authentication_deadline: u64,
    encryption: Option<encryption::ResponseEncryption>,
    legacy: Option<legacy::Binding>,
}
impl ApprovedRequest {
    pub fn response_encryption(&self) -> Option<&encryption::ResponseEncryption> {
        self.encryption.as_ref()
    }
    pub fn wallet_nonce(&self) -> Option<&str> {
        self.legacy.as_ref().map(|b| b.nonce.as_str())
    }
    pub fn authorization_payload(&self, vp: &str) -> Value {
        if let Some(binding) = &self.legacy {
            json!({"vp_token":vp,"state":self.state(),"presentation_submission":{"id":binding.nonce,"definition_id":binding.definition_id,"descriptor_map":[{"id":crate::mdoc::DOCTYPE,"format":"mso_mdoc","path":"$"}]}})
        } else {
            let mut response = json!({"vp_token":response_body(vp,self)});
            if let Some(state) = self.state() {
                response["state"] = json!(state);
            }
            response
        }
    }
    pub fn mdoc_transcript(&self) -> Result<Vec<u8>, &'static str> {
        if let Some(binding) = &self.legacy {
            return crate::mdoc::oid4vp_draft18_transcript(
                self.client_id(),
                self.nonce(),
                self.response_uri(),
                &binding.nonce,
            );
        }
        let thumbprint = self
            .encryption
            .as_ref()
            .map(|e| e.thumbprint())
            .transpose()?;
        crate::mdoc::oid4vp_encrypted_transcript(
            self.client_id(),
            self.nonce(),
            self.response_uri(),
            thumbprint.as_ref(),
        )
    }
    pub fn format(&self) -> &str {
        &self.request.dcql_query.credentials[0].format
    }
    pub fn client_id(&self) -> &str {
        &self.request.client_id
    }
    pub fn response_uri(&self) -> &str {
        &self.request.response_uri
    }
    pub fn expires_at(&self) -> u64 {
        self.request.exp.min(self.authentication_deadline)
    }
    pub fn state(&self) -> Option<&str> {
        self.request.state.as_deref()
    }
    pub fn nonce(&self) -> &str {
        &self.request.nonce
    }
    pub fn query_ids(&self) -> impl Iterator<Item = &str> {
        self.request
            .dcql_query
            .credentials
            .iter()
            .map(|q| q.id.as_str())
    }
    /// First selected query; response serialization uses every selected ID.
    pub fn query_id(&self) -> &str {
        &self.request.dcql_query.credentials[0].id
    }
}
fn token_id(s: &str) -> bool {
    s.len() == 43
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
pub fn verify_request(
    compact: &str,
    registry: &[VerifierRegistration],
    vct: &str,
    now: u64,
) -> Result<ApprovedRequest, &'static str> {
    verify_request_inner(compact, registry, vct, now, None, None)
}
/// Wallet nonce must be freshly generated with a CSPRNG for each review attempt.
pub fn verify_request_with_wallet_nonce(
    compact: &str,
    registry: &[VerifierRegistration],
    vct: &str,
    now: u64,
    wallet_nonce: [u8; 32],
) -> Result<ApprovedRequest, &'static str> {
    verify_request_inner(
        compact,
        registry,
        vct,
        now,
        Some(B64.encode(wallet_nonce)),
        None,
    )
}
fn verify_request_inner(
    compact: &str,
    registry: &[VerifierRegistration],
    vct: &str,
    now: u64,
    wallet_nonce: Option<String>,
    retrieval: Option<&retrieval::RequestRetrieval>,
) -> Result<ApprovedRequest, &'static str> {
    verify_request_mode(compact, registry, vct, now, wallet_nonce, retrieval, false)
}
fn verify_request_mode(
    compact: &str,
    registry: &[VerifierRegistration],
    vct: &str,
    now: u64,
    wallet_nonce: Option<String>,
    retrieval: Option<&retrieval::RequestRetrieval>,
    inventory: bool,
) -> Result<ApprovedRequest, &'static str> {
    if compact.len() > 16384 || registry.len() > 32 {
        return Err("invalid_request");
    }
    let (input, sig) = compact.rsplit_once('.').ok_or("invalid_request")?;
    let (h, p) = input.split_once('.').ok_or("invalid_request")?;
    let header: Header = serde_json::from_slice(&B64.decode(h).map_err(|_| "invalid_request")?)
        .map_err(|_| "invalid_request")?;
    let payload = B64.decode(p).map_err(|_| "invalid_request")?;
    // Reject duplicates at every nesting level, including client_metadata/JWKS.
    let unambiguous =
        crate::wallet_profile::strict_json(&payload).map_err(|_| "invalid_request")?;
    #[derive(Deserialize)]
    struct Route {
        client_id: String,
    }
    let route: Route = serde_json::from_slice(&payload).map_err(|_| "invalid_request")?;
    let selected = registry
        .iter()
        .filter(|r| r.client_id == route.client_id)
        .collect::<Vec<_>>();
    let [registered] = selected.as_slice() else {
        return Err("untrusted_verifier");
    };
    if let Some(retrieval) = retrieval {
        retrieval.check(&unambiguous, registered, now)?;
    }
    let (mut request, legacy) = match registered.profile {
        Profile::Oid4vpFinal | Profile::Oid4vpFinalRequestKeys => (
            serde_json::from_slice::<Request>(&payload).map_err(|_| "invalid_request")?,
            None,
        ),
        Profile::Oid4vpFinalX509Hash => (
            final_request::parse(
                &unambiguous,
                now,
                retrieval.is_some_and(|r| r.method() == retrieval::Method::Post),
            )?,
            None,
        ),
        Profile::Oid4vpDraft18Mdoc => {
            let (request, binding) =
                legacy::parse(&payload, wallet_nonce.ok_or("wallet_nonce_required")?)?;
            (request, Some(binding))
        }
    };
    registered.validate_identifier()?;
    let x509_hash = registered.profile == Profile::Oid4vpFinalX509Hash;
    if header.typ != "oauth-authz-req+jwt"
        || header.alg != "ES256"
        || (!x509_hash
            && request.iss.as_ref().and_then(Value::as_str) != Some(request.client_id.as_str()))
        || request.aud != "https://self-issued.me/v2"
        || request.response_type != "vp_token"
        || !matches!(
            request.response_mode.as_str(),
            "direct_post" | "direct_post.jwt"
        )
        || (!x509_hash
            && (request.iat > now.saturating_add(30)
                || now.saturating_sub(request.iat) > 300
                || request.exp <= now
                || request.exp > request.iat.saturating_add(300)
                || !token_id(&request.nonce)
                || !request.state.as_deref().is_some_and(token_id)))
    {
        return Err("invalid_request");
    }
    if (!x509_hash && header.kid.as_deref() != Some(registered.kid.as_str()))
        || registered.response_uri != request.response_uri
        || !request.response_uri.starts_with("https://")
        || registered.name.is_empty()
        || registered.name.len() > 160
    {
        return Err("untrusted_verifier");
    }
    let encryption = if matches!(
        registered.profile,
        Profile::Oid4vpFinalRequestKeys | Profile::Oid4vpFinalX509Hash
    ) {
        if registered.response_encryption.is_some() || request.response_mode != "direct_post.jwt" {
            return Err("response_encryption_required");
        }
        let recipient = encryption::from_client_metadata(
            request
                .client_metadata
                .as_ref()
                .ok_or("response_encryption_required")?,
        )?;
        if recipient.jwk == registered.jwk {
            return Err("invalid_response_encryption");
        }
        Some(recipient)
    } else {
        if request.client_metadata.is_some() || unambiguous.get("client_metadata").is_some() {
            return Err("invalid_request");
        }
        match (
            &registered.response_encryption,
            request.response_mode.as_str(),
        ) {
            (Some(encryption), "direct_post.jwt") => encryption.validate()?,
            (None, "direct_post") => {}
            _ => return Err("response_encryption_required"),
        }
        registered.response_encryption.clone()
    };
    let authentication_deadline = match (&registered.certificate_trust, &header.x5c) {
        (Some(policy), Some(chain)) => {
            if (!x509_hash && policy.dns_name.is_none()) || chain.len() > 4 {
                return Err("invalid_certificate_policy");
            }
            let chain = chain
                .iter()
                .map(|s| crate::certificate::decode_certificate(s))
                .collect::<Result<Vec<_>, _>>()?;
            if x509_hash {
                crate::certificate::verify_x509_hash_reader_chain(
                    &chain,
                    policy,
                    &registered.jwk,
                    &request.client_id,
                    now,
                )?
            } else {
                crate::certificate::verify_reader_chain(&chain, policy, &registered.jwk, now)?
            }
        }
        (None, None) => u64::MAX,
        _ => return Err("certificate_required"),
    };
    let signature = Signature::from_slice(&B64.decode(sig).map_err(|_| "invalid_request")?)
        .map_err(|_| "invalid_request")?;
    registered
        .jwk
        .verifying_key()?
        .verify(input.as_bytes(), &signature)
        .map_err(|_| "invalid_request_signature")?;
    let selected = if inventory {
        if legacy.is_some() {
            return Err("unsupported_inventory_profile");
        }
        match dcql::select(&request.dcql_query, vct) {
            Ok(_) | Err("credential_query_unsatisfied") => {}
            Err(error) => return Err(error),
        }
        (0..request.dcql_query.credentials.len()).collect()
    } else {
        dcql::select(&request.dcql_query, vct)?
    };
    let mut queries = Vec::new();
    let mut fields = Vec::new();
    let mut retained_fields = Vec::new();
    for index in selected {
        let query = &request.dcql_query.credentials[index];
        if !inventory
            && queries
                .first()
                .is_some_and(|q: &Query| q.format != query.format)
        {
            return Err("mixed_presentation_formats_unsupported");
        }
        if x509_hash {
            final_request::validate_formats(
                request.client_metadata.as_ref().ok_or("invalid_request")?,
                &query.format,
            )?;
        }
        let (selected_fields, retained) = if inventory {
            (Vec::new(), Vec::new())
        } else {
            dcql::fields(query)?
        };
        for field in selected_fields {
            if !fields.contains(&field) {
                fields.push(field);
            }
        }
        for field in retained {
            if !retained_fields.contains(&field) {
                retained_fields.push(field);
            }
        }
        queries.push(query.clone());
    }
    // One receipt/holder proof covers only the union of the selected signed queries.
    if !inventory {
        request.dcql_query = Dcql {
            credentials: queries,
            credential_sets: None,
        };
    }
    Ok(ApprovedRequest {
        authentication_deadline: authentication_deadline
            .min(retrieval.map_or(u64::MAX, |r| r.expires_at())),
        legacy,
        encryption,
        request,
        verifier_name: registered.name.clone(),
        fields,
        retained_fields,
        request_hash: B64.encode(Sha256::digest(compact.as_bytes())),
    })
}
/// Input must already have passed receipt validation using the pinned issuer and holder.
pub fn select_disclosures(
    credential: &str,
    request: &ApprovedRequest,
) -> Result<(String, Value), &'static str> {
    if credential.len() > 24000 || !credential.ends_with('~') {
        return Err("invalid_credential");
    }
    let mut parts = credential.split('~');
    let jwt = parts.next().ok_or("invalid_credential")?;
    let mut selected = format!("{jwt}~");
    let mut values = json!({});
    let mut seen = HashSet::new();
    for disclosure in parts.filter(|p| !p.is_empty()) {
        let v: Value =
            serde_json::from_slice(&B64.decode(disclosure).map_err(|_| "invalid_credential")?)
                .map_err(|_| "invalid_credential")?;
        let a = v
            .as_array()
            .filter(|a| a.len() == 3)
            .ok_or("invalid_credential")?;
        let name = a[1].as_str().ok_or("invalid_credential")?;
        if !seen.insert(name.to_string()) {
            return Err("invalid_credential");
        }
        if request.fields.iter().any(|f| f == name) {
            selected.push_str(disclosure);
            selected.push('~');
            values[name] = a[2].clone();
        }
    }
    if request.fields.iter().any(|f| values.get(f).is_none()) {
        return Err("credential_does_not_match");
    }
    Ok((selected, values))
}
pub fn binding_claims(
    selected: &str,
    request: &ApprovedRequest,
    now: u64,
) -> Result<Value, &'static str> {
    if now >= request.expires_at() {
        return Err("request_expired");
    }
    Ok(
        json!({"aud":request.client_id(),"nonce":request.nonce(),"iat":now,"sd_hash":B64.encode(Sha256::digest(selected.as_bytes()))}),
    )
}
pub fn present(
    key: &SigningKey,
    selected: &str,
    request: &ApprovedRequest,
    now: u64,
) -> Result<String, &'static str> {
    let kb = sign_jwt(
        key,
        json!({"typ":"kb+jwt","alg":"ES256"}),
        binding_claims(selected, request, now)?,
    )?;
    Ok(format!("{selected}{kb}"))
}
pub fn response_body(presentation: &str, request: &ApprovedRequest) -> Value {
    let mut body = serde_json::Map::new();
    for id in request.query_ids() {
        body.insert(id.to_owned(), json!([presentation]));
    }
    Value::Object(body)
}
