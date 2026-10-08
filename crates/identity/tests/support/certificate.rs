//! Mutable RFC 5280 encoding for deliberately altered, re-signed test fixtures.
//! x509-cert 0.3 exposes immutable certificates; product parsing uses that API.
use der::{Sequence, asn1::BitString};
use x509_cert::{
    AlgorithmIdentifier, SubjectPublicKeyInfo, Version, ext::Extensions, name::Name,
    serial_number::SerialNumber, time::Validity,
};

#[derive(Clone, Sequence)]
pub struct Certificate {
    pub tbs_certificate: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: BitString,
}

#[derive(Clone, Sequence)]
pub struct TbsCertificate {
    #[asn1(context_specific = "0", default = "Default::default")]
    pub version: Version,
    pub serial_number: SerialNumber,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub issuer_unique_id: Option<BitString>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    pub subject_unique_id: Option<BitString>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    pub extensions: Option<Extensions>,
}
