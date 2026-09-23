//! Bounded attestation certificate paths. Trust and time are supplied by the server.
use super::*;
use rsa::pkcs8::DecodePublicKey;
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
    ext::pkix::{BasicConstraints, KeyUsage},
};

pub(super) fn parse(bytes: &[u8]) -> Result<Certificate> {
    ensure(bytes.len() <= 16384, Invalid::Limit)?;
    require(!bytes.is_empty())?;
    Certificate::from_der(bytes).map_err(|_| Invalid::Certificate)
}
pub(super) fn verify(cert: &Certificate, alg: i32, message: &[u8], sig: &[u8]) -> Result<()> {
    verify_spki(
        cert.tbs_certificate().subject_public_key_info(),
        alg,
        message,
        sig,
    )
}
pub(super) fn verify_spki(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    alg: i32,
    message: &[u8],
    sig: &[u8],
) -> Result<()> {
    let bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(Invalid::Certificate)?;
    let oid = spki.algorithm.oid.to_string();
    match alg {
        -7 | -35 => {
            require(oid == "1.2.840.10045.2.1")?;
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .ok_or(Invalid::Certificate)?
                .decode_as::<x509_cert::der::asn1::ObjectIdentifier>()
                .map_err(|_| Invalid::Certificate)?
                .to_string();
            if alg == -7 {
                require(curve == "1.2.840.10045.3.1.7")?;
                PublicKey::Es256(
                    VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Invalid::Certificate)?,
                )
                .verify(message, sig)
            } else {
                require(curve == "1.3.132.0.34")?;
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)
                    .map_err(|_| Invalid::Certificate)?;
                key.verify(
                    message,
                    &p384::ecdsa::Signature::from_der(sig).map_err(|_| Invalid::Signature)?,
                )
                .map_err(|_| Invalid::Signature)
            }
        }
        -257 | -65535 => {
            require(oid == "1.2.840.113549.1.1.1")?;
            let key = rsa::RsaPublicKey::from_public_key_der(
                &spki.to_der().map_err(|_| Invalid::Certificate)?,
            )
            .map_err(|_| Invalid::Certificate)?;
            use rsa::traits::PublicKeyParts;
            require((256..=512).contains(&key.size()))?;
            PublicKey::Rsa { key, alg }.verify(message, sig)
        }
        -8 => {
            require(oid == "1.3.101.112" && spki.algorithm.parameters.is_none())?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(
                bytes.try_into().map_err(|_| Invalid::Certificate)?,
            )
            .map_err(|_| Invalid::Certificate)?;
            require(!key.is_weak())?;
            PublicKey::Ed25519(key).verify(message, sig)
        }
        _ => Err(Invalid::Certificate),
    }
}
pub(super) fn signature(
    parent: &Certificate,
    algorithm: &x509_cert::spki::AlgorithmIdentifierOwned,
    message: &[u8],
    sig: &[u8],
) -> Result<()> {
    signature_spki(
        parent.tbs_certificate().subject_public_key_info(),
        algorithm,
        message,
        sig,
    )
}
pub(super) fn signature_spki(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    algorithm: &x509_cert::spki::AlgorithmIdentifierOwned,
    message: &[u8],
    sig: &[u8],
) -> Result<()> {
    let alg = match algorithm.oid.to_string().as_str() {
        "1.2.840.10045.4.3.2" => -7,
        "1.2.840.10045.4.3.3" => -35,
        "1.2.840.113549.1.1.11" => -257,
        "1.2.840.113549.1.1.5" => -65535,
        "1.3.101.112" => -8,
        _ => return Err(Invalid::Certificate),
    };
    if matches!(alg, -7 | -35 | -8) {
        require(algorithm.parameters.is_none())?;
    }
    verify_spki(spki, alg, message, sig)
}
pub(super) fn link(child: &Certificate, parent: &Certificate) -> Result<()> {
    let tbs = child.tbs_certificate();
    ensure(
        tbs.issuer() == parent.tbs_certificate().subject()
            && tbs.signature() == child.signature_algorithm(),
        Invalid::CertificatePath,
    )?;
    signature(
        parent,
        child.signature_algorithm(),
        &tbs.to_der().map_err(|_| Invalid::Certificate)?,
        child.signature().as_bytes().ok_or(Invalid::Certificate)?,
    )
}
pub(super) fn valid(
    cert: &Certificate,
    now: u64,
    ca_depth: Option<usize>,
    anchor: bool,
) -> Result<()> {
    let tbs = cert.tbs_certificate();
    ensure(
        tbs.validity().not_before.to_unix_duration().as_secs() <= now
            && now <= tbs.validity().not_after.to_unix_duration().as_secs(),
        Invalid::CertificateTime,
    )?;
    let extensions = tbs.extensions().map(Vec::as_slice).unwrap_or_default();
    for (i, ext) in extensions.iter().enumerate() {
        require(!extensions[..i].iter().any(|e| e.extn_id == ext.extn_id))?;
        // This bounded attestation profile has no name/policy constraint engine.
        require(!matches!(
            ext.extn_id.to_string().as_str(),
            "2.5.29.30" | "2.5.29.33" | "2.5.29.36" | "2.5.29.54"
        ))?;
        // Critical semantics not implemented here are rejected, never ignored.
        require(
            !ext.critical
                || matches!(
                    ext.extn_id.to_string().as_str(),
                    "2.5.29.19" | "2.5.29.15" | "2.5.29.17" | "2.5.29.32"
                ),
        )?;
    }
    if tbs
        .get_extension::<x509_cert::ext::pkix::SubjectAltName>()
        .map_err(|_| Invalid::Certificate)?
        .is_some_and(|(critical, _)| critical)
    {
        require(ca_depth.is_none() && tbs.subject().is_empty())?;
    }
    // The attestation profile accepts any policy; policy mappings/constraints are
    // unsupported critical extensions. Parse the standard informational qualifiers.
    if let Some((_, policies)) = tbs
        .get_extension::<x509_cert::ext::pkix::CertificatePolicies>()
        .map_err(|_| Invalid::Certificate)?
    {
        use x509_cert::ext::pkix::certpolicy::CpsUri;
        require(!policies.0.is_empty())?;
        for (i, p) in policies.0.iter().enumerate() {
            require(
                !policies.0[..i]
                    .iter()
                    .any(|q| q.policy_identifier == p.policy_identifier),
            )?;
            for q in p.policy_qualifiers.iter().flatten() {
                let value = q.qualifier.as_ref().ok_or(Invalid::Certificate)?;
                match q.policy_qualifier_id.to_string().as_str() {
                    "1.3.6.1.5.5.7.2.1" => {
                        value
                            .decode_as::<CpsUri>()
                            .map_err(|_| Invalid::Certificate)?;
                    }
                    "1.3.6.1.5.5.7.2.2" => {
                        value
                            .decode_as::<UserNotice>()
                            .map_err(|_| Invalid::Certificate)?;
                    }
                    _ => return Err(Invalid::Certificate),
                }
            }
        }
    }
    let bc = tbs
        .get_extension::<BasicConstraints>()
        .map_err(|_| Invalid::Certificate)?;
    let usage = tbs
        .get_extension::<KeyUsage>()
        .map_err(|_| Invalid::Certificate)?;
    if let Some(depth) = ca_depth {
        if let Some((_, bc)) = bc {
            require(
                bc.ca
                    && bc
                        .path_len_constraint
                        .is_none_or(|n| depth <= usize::from(n)),
            )?;
        } else {
            require(anchor)?;
        }
        require(usage.is_none_or(|(_, u)| u.key_cert_sign()))?;
    } else {
        require(bc.is_none_or(|(_, b)| !b.ca))?;
        require(usage.is_none_or(|(_, u)| u.digital_signature()))?;
    }
    Ok(())
}
/// The root is excluded from the supplied path, except a directly trusted batch certificate.
pub(super) fn path(
    chain: &[Vec<u8>],
    roots: &[Vec<u8>],
    now: u64,
) -> Result<(Certificate, String)> {
    ensure(
        !chain.is_empty() && chain.len() <= 6 && !roots.is_empty() && roots.len() <= 32,
        Invalid::CertificatePath,
    )?;
    let certs: Vec<_> = chain.iter().map(|b| parse(b)).collect::<Result<_>>()?;
    for (i, cert) in certs.iter().enumerate() {
        ensure(!chain[..i].contains(&chain[i]), Invalid::CertificatePath)?;
        valid(cert, now, if i == 0 { None } else { Some(i - 1) }, false)?;
        if i > 0 {
            link(&certs[i - 1], cert)?;
        }
    }
    if chain.len() == 1 && roots.contains(&chain[0]) {
        return Ok((certs[0].clone(), B64.encode(Sha256::digest(&chain[0]))));
    }
    ensure(
        !chain.iter().any(|c| roots.contains(c)),
        Invalid::CertificatePath,
    )?;
    let last = certs.last().ok_or(Invalid::Certificate)?;
    for der in roots {
        let root = parse(der)?;
        if valid(&root, now, Some(chain.len() - 1), true).is_ok() && link(last, &root).is_ok() {
            return Ok((certs[0].clone(), B64.encode(Sha256::digest(der))));
        }
    }
    Err(Invalid::CertificatePath)
}

// x509-cert's DisplayText currently omits BMPString, used by TPM notices.
#[derive(der::Choice)]
enum DisplayText {
    Ia5(der::asn1::Ia5String),
    Utf8(String),
    Bmp(der::asn1::BmpString),
}
#[derive(der::Sequence)]
struct NoticeReference {
    organization: DisplayText,
    notice_numbers: Vec<der::asn1::Uint>,
}
#[derive(der::Sequence)]
struct UserNotice {
    notice_ref: Option<NoticeReference>,
    explicit_text: Option<DisplayText>,
}

fn require(ok: bool) -> Result<()> {
    ensure(ok, Invalid::Certificate)
}
