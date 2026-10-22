//! Bounded DG1/SOD verification. Only separately pinned CSCA keys establish trust.
//! CMS schemas follow RFC 5652. No network discovery or VP authority.
mod curves;
#[cfg(test)]
mod tests;
mod trust;
use der::{
    Decode, Encode, Sequence, Tag, Tagged, ValueOrd,
    asn1::{Any, ObjectIdentifier, OctetString, SetOfVec},
};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
    pkcs8::DecodePublicKey,
};
use rsa::{Pkcs1v15Sign, Pss, RsaPublicKey, traits::PublicKeyParts};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::{
    AlgorithmIdentifier, Certificate,
    attr::Attribute,
    ext::pkix::{BasicConstraints, KeyUsage},
};

pub(crate) const MAX_SOD: usize = 8192;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    NotChecked,
    Unsupported,
    Invalid,
    Consistent,
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub state: State,
    pub checked_data_groups: Vec<u8>,
    pub issuer_trust: &'static str,
    pub revocation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
}
impl Report {
    pub fn new(state: State) -> Self {
        Self {
            state,
            checked_data_groups: if state == State::Consistent {
                vec![1]
            } else {
                vec![]
            },
            issuer_trust: "not_configured",
            revocation: "not_checked",
            checked_at: None,
            valid_until: None,
        }
    }
}
#[derive(Sequence)]
struct ContentInfo {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    content: Any,
}
#[derive(Sequence)]
struct EncapsulatedContent {
    content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    content: Option<OctetString>,
}
#[derive(Sequence)]
struct SignedData {
    version: u8,
    digest_algorithms: SetOfVec<AlgorithmIdentifier>,
    encapsulated: EncapsulatedContent,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    certificates: Option<SetOfVec<Any>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    crls: Option<SetOfVec<Any>>,
    signers: SetOfVec<Signer>,
}
#[derive(Sequence, ValueOrd)]
struct Signer {
    version: u8,
    sid: Any,
    digest: AlgorithmIdentifier,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    attributes: Option<SetOfVec<Attribute>>,
    algorithm: AlgorithmIdentifier,
    signature: OctetString,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    unsigned_attributes: Option<SetOfVec<Attribute>>,
}
#[derive(Sequence)]
struct IssuerSerial {
    issuer: x509_cert::name::Name,
    serial: x509_cert::serial_number::SerialNumber,
}
#[derive(Sequence)]
struct Lds {
    version: u8,
    algorithm: AlgorithmIdentifier,
    hashes: Vec<GroupHash>,
    version_info: Option<Any>,
}
#[derive(Sequence)]
struct GroupHash {
    number: u8,
    hash: OctetString,
}
#[derive(Sequence)]
struct PssParameters {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifier>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask: Option<AlgorithmIdentifier>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    salt: Option<u8>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    trailer: Option<u8>,
}
#[derive(Sequence)]
struct AlgorithmProtection {
    digest: AlgorithmIdentifier,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    signature: Option<AlgorithmIdentifier>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    mac: Option<AlgorithmIdentifier>,
}
type Result<T> = std::result::Result<T, State>;
fn invalid<T>(_: T) -> State {
    State::Invalid
}
fn required<T>(v: Option<T>) -> Result<T> {
    v.ok_or(State::Invalid)
}
fn ensure(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(State::Invalid)
    }
}
fn oid(value: ObjectIdentifier, expected: &str) -> bool {
    value == ObjectIdentifier::new_unwrap(expected)
}
fn no_parameters(alg: &AlgorithmIdentifier) -> bool {
    alg.parameters.as_ref().is_none_or(Any::is_null)
}

#[derive(Clone, Copy, PartialEq)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}
impl Hash {
    fn parse(alg: &AlgorithmIdentifier) -> Result<Self> {
        ensure(no_parameters(alg))?;
        match alg.oid.to_string().as_str() {
            "2.16.840.1.101.3.4.2.1" => Ok(Self::Sha256),
            "2.16.840.1.101.3.4.2.2" => Ok(Self::Sha384),
            "2.16.840.1.101.3.4.2.3" => Ok(Self::Sha512),
            _ => Err(State::Unsupported),
        }
    }
    fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }
    fn size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

pub(super) fn inspect(sod: &[u8], dg1: &[u8], policy: &super::Policy, now: u64) -> Report {
    if super::mrz::claims(dg1).is_err() {
        return Report::new(State::Invalid);
    }
    let cert = match verify_inner(sod, dg1) {
        Ok(cert) => cert,
        Err(state) => return Report::new(state),
    };
    let mut report = Report::new(State::Consistent);
    trust::check(&cert, &dg1[7..10], &policy.crls, now, &mut report);
    report
}
// Retained test adapter: production callers supply their own trusted time and policy.
#[cfg(test)]
fn verify(sod: &[u8], dg1: &[u8]) -> Report {
    inspect(sod, dg1, &super::Policy::default(), 1792627200)
}
fn verify_inner(sod: &[u8], dg1: &[u8]) -> Result<Certificate> {
    ensure(!sod.is_empty() && sod.len() <= MAX_SOD && dg1.len() == 93)?;
    let mut pos = 0;
    let cms = super::encoding::value(sod, &mut pos, &[0x77]).map_err(invalid)?;
    ensure(pos == sod.len())?;
    let info = ContentInfo::from_der(cms).map_err(invalid)?;
    ensure(oid(info.content_type, "1.2.840.113549.1.7.2"))?;
    let signed = info.content.decode_as::<SignedData>().map_err(invalid)?;
    // SetOfVec normalizes order on decode; never verify normalized signedAttrs
    // when the original wire encoding was not DER.
    ensure(signed.to_der().map_err(invalid)? == info.content.to_der().map_err(invalid)?)?;
    ensure(
        signed.version == 3
            && signed.signers.len() == 1
            && signed.digest_algorithms.len() == 1
            && signed.crls.is_none(),
    )?;
    ensure(oid(signed.encapsulated.content_type, "2.23.136.1.1.1"))?;
    let content = required(signed.encapsulated.content)?;
    let lds = Lds::from_der(content.as_bytes()).map_err(invalid)?;
    ensure(lds.version <= 1 && (lds.version == 1) == lds.version_info.is_some())?;
    if let Some(v) = &lds.version_info {
        #[derive(Sequence)]
        struct Versions {
            lds: der::asn1::PrintableString,
            unicode: der::asn1::PrintableString,
        }
        let versions = v.decode_as::<Versions>().map_err(invalid)?;
        ensure(
            versions.lds.as_str().len() == 4
                && versions.unicode.as_str().len() == 6
                && versions
                    .lds
                    .as_str()
                    .bytes()
                    .chain(versions.unicode.as_str().bytes())
                    .all(|b| b.is_ascii_digit()),
        )?;
    }
    ensure((2..=16).contains(&lds.hashes.len()))?;
    let dg_hash = Hash::parse(&lds.algorithm)?;
    let mut seen = std::collections::HashSet::new();
    let mut matched = false;
    for group in &lds.hashes {
        ensure(
            (1..=16).contains(&group.number)
                && seen.insert(group.number)
                && group.hash.as_bytes().len() == dg_hash.size(),
        )?;
        if group.number == 1 {
            ensure(super::encoding::equal(
                group.hash.as_bytes(),
                &dg_hash.digest(dg1),
            ))?;
            matched = true;
        }
    }
    ensure(matched)?;
    let signer = required(signed.signers.get(0))?;
    let digest = Hash::parse(&signer.digest)?;
    ensure(Hash::parse(required(signed.digest_algorithms.get(0))?)? == digest)?;
    ensure(signer.unsigned_attributes.is_none())?;
    let attrs = required(signer.attributes.as_ref())?;
    ensure((2..=16).contains(&attrs.len()))?;
    let mut seen = std::collections::HashSet::new();
    let (mut content_type, mut message_digest) = (false, false);
    for attr in attrs.iter() {
        ensure(seen.insert(attr.oid) && (1..=4).contains(&attr.values.len()))?;
        match attr.oid.to_string().as_str() {
            "1.2.840.113549.1.9.3" => {
                ensure(
                    attr.values.len() == 1
                        && required(attr.values.get(0))?
                            .decode_as::<ObjectIdentifier>()
                            .map_err(invalid)?
                            == signed.encapsulated.content_type,
                )?;
                content_type = true;
            }
            "1.2.840.113549.1.9.4" => {
                ensure(attr.values.len() == 1)?;
                let value = required(attr.values.get(0))?
                    .decode_as::<OctetString>()
                    .map_err(invalid)?;
                ensure(super::encoding::equal(
                    value.as_bytes(),
                    &digest.digest(content.as_bytes()),
                ))?;
                message_digest = true;
            }
            "1.2.840.113549.1.9.52" => {
                ensure(attr.values.len() == 1)?;
                let p = required(attr.values.get(0))?
                    .decode_as::<AlgorithmProtection>()
                    .map_err(invalid)?;
                ensure(
                    p.digest == signer.digest
                        && p.signature.as_ref() == Some(&signer.algorithm)
                        && p.mac.is_none(),
                )?;
            }
            _ => (), // Authenticated bytes; no unrecognized attribute confers authority.
        }
    }
    ensure(content_type && message_digest)?;
    let certificates = required(signed.certificates)?;
    ensure((1..=4).contains(&certificates.len()))?;
    let mut selected = None;
    let mut seen = std::collections::HashSet::new();
    for value in certificates.iter() {
        let bytes = value.to_der().map_err(invalid)?;
        ensure(bytes.len() <= 4096 && seen.insert(bytes.clone()))?;
        let cert = Certificate::from_der(&bytes).map_err(invalid)?;
        ensure(cert.to_der().map_err(invalid)? == bytes)?;
        let matches = if signer.sid.tag() == Tag::Sequence {
            ensure(signer.version == 1)?;
            let id = signer.sid.decode_as::<IssuerSerial>().map_err(invalid)?;
            cert.tbs_certificate().issuer() == &id.issuer
                && cert.tbs_certificate().serial_number() == &id.serial
        } else if matches!(signer.sid.tag(), Tag::ContextSpecific { constructed: false, number } if number == der::TagNumber(0))
        {
            ensure(signer.version == 3)?;
            ensure((1..=64).contains(&signer.sid.value().len()))?;
            cert.tbs_certificate()
                .extensions()
                .is_some_and(|extensions| {
                    extensions.iter().any(|e| {
                        oid(e.extn_id, "2.5.29.14")
                            && OctetString::from_der(e.extn_value.as_bytes()).is_ok_and(|ski| {
                                super::encoding::equal(ski.as_bytes(), signer.sid.value())
                            })
                    })
                })
        } else {
            return Err(State::Unsupported);
        };
        if matches {
            ensure(selected.is_none())?;
            selected = Some(cert);
        }
    }
    let cert = required(selected)?;
    let mut seen = std::collections::HashSet::new();
    let extensions = required(cert.tbs_certificate().extensions())?;
    let mut digital_signature = false;
    for ext in extensions {
        ensure(seen.insert(ext.extn_id))?;
        if oid(ext.extn_id, "2.5.29.19") {
            ensure(
                !BasicConstraints::from_der(ext.extn_value.as_bytes())
                    .map_err(invalid)?
                    .ca,
            )?;
        }
        if oid(ext.extn_id, "2.5.29.15") {
            let usage = KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(invalid)?;
            ensure(usage.digital_signature() && !usage.key_cert_sign())?;
            digital_signature = true;
        }
    }
    ensure(digital_signature)?;
    verify_signature(
        &cert,
        &signer.algorithm,
        digest,
        signer.signature.as_bytes(),
        &attrs.to_der().map_err(invalid)?,
    )?;
    Ok(cert)
}
fn verify_signature(
    cert: &Certificate,
    algorithm: &AlgorithmIdentifier,
    digest: Hash,
    signature: &[u8],
    message: &[u8],
) -> Result<()> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let signature_oid = algorithm.oid.to_string();
    if oid(spki.algorithm.oid, "1.2.840.113549.1.1.1") {
        ensure(no_parameters(&spki.algorithm))?;
        let key =
            RsaPublicKey::from_public_key_der(&spki.to_der().map_err(invalid)?).map_err(invalid)?;
        ensure((2048..=4096).contains(&key.n().bits_vartime()) && key.e().bits_vartime() <= 32)?;
        let hashed = digest.digest(message);
        let pss_salt = if signature_oid == "1.2.840.113549.1.1.10" {
            let p = required(algorithm.parameters.as_ref())?
                .decode_as::<PssParameters>()
                .map_err(invalid)?;
            ensure(
                Hash::parse(required(p.hash.as_ref())?)? == digest && p.trailer.unwrap_or(1) == 1,
            )?;
            let mask = required(p.mask.as_ref())?;
            ensure(oid(mask.oid, "1.2.840.113549.1.1.8"))?;
            let mask_hash = required(mask.parameters.as_ref())?
                .decode_as::<AlgorithmIdentifier>()
                .map_err(invalid)?;
            ensure(Hash::parse(&mask_hash)? == digest)?;
            let salt = p.salt.unwrap_or(20) as usize;
            ensure(salt <= 64)?;
            Some(salt)
        } else {
            ensure(no_parameters(algorithm))?;
            let expected = match digest {
                Hash::Sha256 => "1.2.840.113549.1.1.11",
                Hash::Sha384 => "1.2.840.113549.1.1.12",
                Hash::Sha512 => "1.2.840.113549.1.1.13",
            };
            if signature_oid != "1.2.840.113549.1.1.1" && signature_oid != expected {
                return Err(State::Unsupported);
            }
            None
        };
        let valid = match (digest, pss_salt) {
            (Hash::Sha256, Some(n)) => {
                key.verify(Pss::<Sha256>::new_with_salt(n), &hashed, signature)
            }
            (Hash::Sha384, Some(n)) => {
                key.verify(Pss::<Sha384>::new_with_salt(n), &hashed, signature)
            }
            (Hash::Sha512, Some(n)) => {
                key.verify(Pss::<Sha512>::new_with_salt(n), &hashed, signature)
            }
            (Hash::Sha256, None) => key.verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, signature),
            (Hash::Sha384, None) => key.verify(Pkcs1v15Sign::new::<Sha384>(), &hashed, signature),
            (Hash::Sha512, None) => key.verify(Pkcs1v15Sign::new::<Sha512>(), &hashed, signature),
        };
        valid.map_err(invalid)
    } else if oid(spki.algorithm.oid, "1.2.840.10045.2.1") {
        ensure(algorithm.parameters.is_none())?;
        let curve = curves::identify(required(spki.algorithm.parameters.as_ref())?)?;
        let point = required(spki.subject_public_key.as_bytes())?;
        match (curve, digest, signature_oid.as_str()) {
            (curves::Curve::P256, Hash::Sha256, "1.2.840.10045.4.3.2") => {
                let key = VerifyingKey::from_sec1_bytes(point).map_err(invalid)?;
                key.verify_prehash(
                    &digest.digest(message),
                    &Signature::from_der(signature).map_err(invalid)?,
                )
                .map_err(invalid)
            }
            (curves::Curve::P384, Hash::Sha384, "1.2.840.10045.4.3.3") => {
                use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(invalid)?;
                key.verify_prehash(
                    &digest.digest(message),
                    &p384::ecdsa::Signature::from_der(signature).map_err(invalid)?,
                )
                .map_err(invalid)
            }
            _ => Err(State::Unsupported),
        }
    } else {
        Err(State::Unsupported)
    }
}
/// Certificates and CRLs carry their digest in the signature AlgorithmIdentifier.
fn verify_signed(
    cert: &Certificate,
    alg: &AlgorithmIdentifier,
    sig: &[u8],
    message: &[u8],
) -> Result<()> {
    let hash = match alg.oid.to_string().as_str() {
        "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => Hash::Sha256,
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => Hash::Sha384,
        "1.2.840.113549.1.1.13" => Hash::Sha512,
        "1.2.840.113549.1.1.10" => {
            let p = required(alg.parameters.as_ref())?
                .decode_as::<PssParameters>()
                .map_err(invalid)?;
            Hash::parse(required(p.hash.as_ref())?)?
        }
        _ => return Err(State::Unsupported),
    };
    // Japan's independently pinned 2019/2024 CSCAs encode ECDSA signature
    // parameters as NULL. For certificate/CRL signatures only, accept absent or
    // NULL parameters; verify the original, unmodified TBS bytes. CMS stays strict.
    let mut algorithm = alg.clone();
    if matches!(
        alg.oid.to_string().as_str(),
        "1.2.840.10045.4.3.2" | "1.2.840.10045.4.3.3"
    ) && algorithm.parameters.as_ref().is_some_and(Any::is_null)
    {
        algorithm.parameters = None;
    }
    verify_signature(cert, &algorithm, hash, sig, message)
}

pub(super) fn policy_crls(json: &str) -> std::result::Result<Vec<Vec<u8>>, &'static str> {
    trust::decode_crls(json)
}

pub(super) fn policy_fingerprint(crls: &[Vec<u8>]) -> String {
    trust::policy_fingerprint(crls)
}
pub(super) fn policy_valid_until(
    crls: &[Vec<u8>],
    now: u64,
) -> std::result::Result<u64, &'static str> {
    trust::policy_valid_until(crls, now)
}

#[cfg(test)]
pub(super) fn test_verified_fixture() -> super::VerifiedDg1 {
    trust::test_verified_fixture()
}
