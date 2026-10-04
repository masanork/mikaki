//! DCQL authority conditions minimize disclosure; they never establish issuer trust.
use super::*;
use crate::credential_receipt::CredentialTrust;
use der::Decode;
use x509_cert::{Certificate, ext::pkix::AuthorityKeyIdentifier};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Authority {
    #[serde(rename = "type")]
    kind: String,
    values: Vec<String>,
}
pub(super) fn non_null<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<Authority>>, D::Error> {
    Vec::<Authority>::deserialize(d).map(Some)
}
fn aki(value: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = B64.decode(value).map_err(|_| "invalid_authority_query")?;
    if bytes.is_empty() || bytes.len() > 64 || B64.encode(&bytes) != value {
        return Err("invalid_authority_query");
    }
    Ok(bytes)
}
pub(super) fn validate(authorities: &[Authority]) -> Result<(), &'static str> {
    if authorities.is_empty() || authorities.len() > 8 {
        return Err("invalid_authority_query");
    }
    for authority in authorities {
        if authority.kind.is_empty()
            || authority.kind.len() > 64
            || authority.values.is_empty()
            || authority.values.len() > 16
        {
            return Err("invalid_authority_query");
        }
        for value in &authority.values {
            if value.is_empty() || value.len() > 1024 {
                return Err("invalid_authority_query");
            }
            if authority.kind == "aki" {
                aki(value)?;
            }
        }
    }
    Ok(())
}
impl ApprovedRequest {
    /// Call after signature/holder receipt validation, before revealing consent values,
    /// and again on confirmation. Match only certificates actually carried in the
    /// credential, after purpose-specific chain/status validation with provisioned roots.
    pub fn check_credential_authorities(
        &self,
        credential: &str,
        trust: Option<&CredentialTrust>,
        key: &PublicJwk,
        now: u64,
        expires: u64,
    ) -> Result<(), String> {
        let constraints: Vec<_> = self
            .request
            .dcql_query
            .credentials
            .iter()
            .filter_map(|q| q.trusted_authorities.as_ref())
            .collect();
        if constraints.is_empty() {
            return Ok(());
        }
        let trust = trust.ok_or("credential_authority_unavailable")?;
        let chain = trust.verify_chain(credential, self.format(), key, now, expires)?;
        let mut identifiers = Vec::new();
        for bytes in chain {
            let cert =
                Certificate::from_der(&bytes).map_err(|_| "invalid_credential_certificate")?;
            if let Some(ext) = cert
                .tbs_certificate
                .extensions
                .as_ref()
                .and_then(|es| es.iter().find(|e| e.extn_id.to_string() == "2.5.29.35"))
            {
                let authority = AuthorityKeyIdentifier::from_der(ext.extn_value.as_bytes())
                    .map_err(|_| "invalid_credential_certificate")?;
                if let Some(identifier) = authority.key_identifier {
                    identifiers.push(identifier.as_bytes().to_vec());
                }
            }
        }
        for authorities in constraints {
            let mut matched = false;
            for authority in authorities {
                // OR across each query's authority entries/values; AND across queries.
                if authority.kind == "aki" {
                    for value in &authority.values {
                        if identifiers.contains(&aki(value).map_err(str::to_string)?) {
                            matched = true;
                        }
                    }
                }
            }
            if !matched {
                return Err("credential_does_not_match".into());
            }
        }
        Ok(())
    }
}
