//! WebAuthn Android Key extension checks; trust anchors come from authenticated metadata.
use super::*;
use der::{
    Tag, Tagged,
    asn1::{Any, OctetString, SetOfVec},
};

#[derive(der::Sequence)]
struct KeyDescription {
    attestation_version: u64,
    attestation_security_level: Any,
    keymaster_version: u64,
    keymaster_security_level: Any,
    attestation_challenge: OctetString,
    unique_id: OctetString,
    software_enforced: Vec<Any>,
    tee_enforced: Vec<Any>,
}

fn authorizations(list: &[Any]) -> Result<(bool, bool)> {
    require(list.len() <= 64)?;
    let (mut purpose, mut origin, mut previous) = (false, false, None);
    for field in list {
        let Tag::ContextSpecific {
            number,
            constructed: true,
        } = field.tag()
        else {
            return Err(Invalid::Attestation);
        };
        let tag = number.value();
        require(previous.is_none_or(|p| p < tag))?;
        previous = Some(tag);
        match tag {
            1 => {
                let values =
                    SetOfVec::<u64>::from_der(field.value()).map_err(|_| Invalid::Attestation)?;
                // WebAuthn requires a signing key, not a multi-purpose encryption key.
                require(values.len() == 1 && values.iter().next() == Some(&2))?;
                purpose = true;
            }
            600 => return Err(Invalid::Attestation), // allApplications is forbidden in either list.
            702 => {
                require(u64::from_der(field.value()).map_err(|_| Invalid::Attestation)? == 0)?;
                origin = true;
            }
            _ => {
                // Other explicit Android authorizations do not change these WebAuthn checks.
                // Parse the complete inner TLV, rather than searching for matching bytes.
                Any::from_der(field.value()).map_err(|_| Invalid::Attestation)?;
            }
        }
    }
    Ok((purpose, origin))
}

pub(super) fn verify(cert: &Certificate, client_hash: &[u8]) -> Result<()> {
    let extension = cert
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .find(|e| e.extn_id.to_string() == "1.3.6.1.4.1.11129.2.1.17")
        .ok_or(Invalid::Attestation)?;
    validate_extension(extension.extn_value.as_bytes(), client_hash)
}

pub(crate) fn validate_extension(bytes: &[u8], client_hash: &[u8]) -> Result<()> {
    ensure(
        bytes.len() <= 16384 && client_hash.len() == 32,
        Invalid::Limit,
    )?;
    let description = KeyDescription::from_der(bytes).map_err(|_| Invalid::Attestation)?;
    for level in [
        &description.attestation_security_level,
        &description.keymaster_security_level,
    ] {
        require(level.tag() == Tag::Enumerated && matches!(level.value(), [0] | [1] | [2]))?;
    }
    require(description.attestation_challenge.as_bytes() == client_hash)?;
    // Accept software or TEE authorization; this is not a hardware-only policy.
    let software = authorizations(&description.software_enforced)?;
    let tee = authorizations(&description.tee_enforced)?;
    require((software.0 || tee.0) && (software.1 || tee.1))
}
