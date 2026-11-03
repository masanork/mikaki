//! Narrow, native-only proof construction for installation qualification.
//! This module neither authorizes a device nor implements an app session.
use crate::issuance::PublicJwk;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{Signature, signature::Verifier};
use serde_json::json;
use url::Url;

/// Native key custody signs a JWS input using SHA-256/ECDSA and returns DER.
/// The key must remain outside this protocol module.
pub trait InstallationSigner {
    fn public_key(&self) -> Result<PublicJwk, String>;
    fn sign_der(&self, input: &str) -> Result<Vec<u8>, String>;
}

#[derive(Clone, Copy)]
pub enum Step<'a> {
    Start,
    Complete { nonce: &'a str },
}

pub(crate) fn opaque(value: &str) -> bool {
    value.len() == 43
        && B64
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32 && B64.encode(bytes) == value)
}

/// Caller provides fresh cryptographic randomness for each proof and the trusted
/// local clock. The issuer is configured locally, never supplied by a WebView.
pub fn proof(
    signer: &impl InstallationSigner,
    issuer: &str,
    step: Step<'_>,
    jti: &str,
    now: u64,
) -> Result<String, String> {
    proof_for_key(signer, issuer, step, jti, now, None)
}

pub(crate) fn proof_for_key(
    signer: &impl InstallationSigner,
    issuer: &str,
    step: Step<'_>,
    jti: &str,
    now: u64,
    expected: Option<&PublicJwk>,
) -> Result<String, String> {
    let invalid = || "invalid_installation_proof".to_owned();
    let url = Url::parse(issuer).map_err(|_| invalid())?;
    if issuer.len() > 2048
        || issuer.ends_with('/')
        || url.scheme() != "https"
        || url.origin().ascii_serialization() != issuer
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || now == 0
        || !opaque(jti)
    {
        return Err(invalid());
    }
    let (path, nonce) = match step {
        Step::Start => ("/native/installations/start", None),
        Step::Complete { nonce } if opaque(nonce) => {
            ("/native/installations/complete", Some(nonce))
        }
        _ => return Err(invalid()),
    };
    let public = signer.public_key()?;
    if expected.is_some_and(|key| key != &public) {
        return Err(invalid());
    }
    let verifier = public.verifying_key().map_err(|_| invalid())?;
    let header = json!({"typ":"dpop+jwt","alg":"ES256","jwk":public});
    let mut claims = json!({"htm":"POST","htu":format!("{issuer}{path}"),"iat":now,"jti":jti});
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    let input = format!(
        "{}.{}",
        B64.encode(serde_json::to_vec(&header).map_err(|_| invalid())?),
        B64.encode(serde_json::to_vec(&claims).map_err(|_| invalid())?)
    );
    let der = signer.sign_der(&input)?;
    let signature = Signature::from_der(&der).map_err(|_| invalid())?;
    verifier
        .verify(input.as_bytes(), &signature)
        .map_err(|_| invalid())?;
    Ok(format!("{input}.{}", B64.encode(signature.to_bytes())))
}
