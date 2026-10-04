//! Credential roots are operator provisioned, never learned from issuer metadata or receipts.
use crate::{
    certificate::CrlPolicy,
    credential_certificate::{self, Purpose, SigningTrust},
    issuance::PublicJwk,
    mdoc,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRoots {
    pub trust_anchors: Vec<String>,
    pub revocation: Option<CrlPolicy>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialTrust {
    pub sd_jwt: CredentialRoots,
    pub mdoc: CredentialRoots,
}
impl CredentialTrust {
    pub fn validate(&self, now: u64) -> Result<(), String> {
        if self
            .sd_jwt
            .trust_anchors
            .iter()
            .any(|r| self.mdoc.trust_anchors.contains(r))
        {
            return Err("wallet_configuration_invalid".into());
        }
        for roots in [&self.sd_jwt, &self.mdoc] {
            if let Some(policy) = &roots.revocation {
                policy.validate().map_err(str::to_string)?;
            }
        }
        credential_certificate::validate_roots(&self.sd_jwt.trust_anchors, Purpose::SdJwt, now)
            .map_err(str::to_string)?;
        credential_certificate::validate_roots(&self.mdoc.trust_anchors, Purpose::Mdoc, now)
            .map_err(str::to_string)
    }
    pub fn verify(
        &self,
        credential: &str,
        format: &str,
        key: &PublicJwk,
        now: u64,
        expires: u64,
    ) -> Result<(), String> {
        self.verify_chain(credential, format, key, now, expires)
            .map(|_| ())
    }
    pub(crate) fn verify_chain(
        &self,
        credential: &str,
        format: &str,
        key: &PublicJwk,
        now: u64,
        expires: u64,
    ) -> Result<Vec<Vec<u8>>, String> {
        let (chain, roots, purpose) = match format {
            "dc+sd-jwt" => {
                // Typed parsing rejects duplicate fields; receipt validation checks the exact header.
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Header {
                    typ: String,
                    alg: String,
                    kid: String,
                    x5c: Vec<String>,
                }
                let encoded = credential.split('.').next().ok_or("invalid_credential")?;
                if encoded.len() > 24000 {
                    return Err("invalid_credential".into());
                }
                let bytes = URL_SAFE_NO_PAD
                    .decode(encoded)
                    .map_err(|_| "invalid_credential")?;
                let header: Header =
                    serde_json::from_slice(&bytes).map_err(|_| "invalid_credential")?;
                if header.typ != "dc+sd-jwt" || header.alg != "ES256" || header.kid.is_empty() {
                    return Err("invalid_credential".into());
                }
                (header.x5c, &self.sd_jwt, Purpose::SdJwt)
            }
            "mso_mdoc" => {
                if credential.len() > 43000 {
                    return Err("invalid_mdoc".into());
                }
                let bytes = URL_SAFE_NO_PAD
                    .decode(credential)
                    .map_err(|_| "invalid_mdoc")?;
                let signed = mdoc::decode(&bytes).map_err(str::to_string)?;
                let auth = signed
                    .as_map()
                    .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("issuerAuth")))
                    .and_then(|(_, v)| v.as_array())
                    .filter(|a| a.len() == 4)
                    .ok_or("invalid_mdoc")?;
                let headers = auth[1]
                    .as_map()
                    .filter(|m| m.len() == 1)
                    .ok_or("invalid_mdoc_certificate")?;
                if headers[0]
                    .0
                    .as_integer()
                    .and_then(|i| i64::try_from(i).ok())
                    != Some(33)
                {
                    return Err("invalid_mdoc_certificate".into());
                }
                let cert = headers[0].1.as_bytes().ok_or("invalid_mdoc_certificate")?;
                (vec![STANDARD.encode(cert)], &self.mdoc, Purpose::Mdoc)
            }
            _ => return Err("invalid_credential".into()),
        };
        let trust = SigningTrust {
            chain,
            trust_anchors: roots.trust_anchors.clone(),
            revocation: roots.revocation.clone(),
        };
        let (chain, deadline) =
            credential_certificate::verify(&trust, key, purpose, now).map_err(str::to_string)?;
        if expires > deadline {
            return Err("credential_trust_expired".into());
        }
        Ok(chain)
    }
}
