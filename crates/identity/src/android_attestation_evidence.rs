//! Bounded *untrusted* Android evidence for an independent attester.
//! Matching the challenge/key is a local sanity check, never a trust decision.
use crate::issuance::PublicJwk;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
};
use der::{
    Decode, Encode, Reader, SliceReader, Tag, Tagged,
    asn1::{AnyRef, ObjectIdentifier},
};
use p256::{ecdsa::VerifyingKey, pkcs8::DecodePublicKey};
use serde::Serialize;
use x509_cert::Certificate;

const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.1.17");
const ERROR: &str = "wallet_attestation_unavailable";

/// Only constructed after bounded parsing and challenge/public-key matching.
/// It deliberately contains no interpreted security-level or assurance claims.
#[derive(Serialize)]
pub struct UntrustedAndroidEvidence {
    challenge: String,
    public_key: PublicJwk,
    certificate_chain: Vec<String>,
}
impl UntrustedAndroidEvidence {
    pub fn collect(
        challenge: &[u8; 32],
        public_key: PublicJwk,
        certificate_chain: Vec<String>,
    ) -> Result<Self, &'static str> {
        public_key.verifying_key().map_err(|_| ERROR)?;
        if !(2..=8).contains(&certificate_chain.len()) {
            return Err(ERROR);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut total = 0;
        let mut certificates = Vec::new();
        for encoded in &certificate_chain {
            if encoded.len() > 10924 || !seen.insert(encoded) {
                return Err(ERROR);
            }
            let der = STANDARD.decode(encoded).map_err(|_| ERROR)?;
            total += der.len();
            if der.is_empty()
                || der.len() > 8192
                || total > 32768
                || STANDARD.encode(&der) != *encoded
            {
                return Err(ERROR);
            }
            let certificate = Certificate::from_der(&der).map_err(|_| ERROR)?;
            if certificate.to_der().map_err(|_| ERROR)? != der {
                return Err(ERROR);
            }
            certificates.push(certificate);
        }
        let leaf = &certificates[0];
        let key = VerifyingKey::from_public_key_der(
            &leaf
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|_| ERROR)?,
        )
        .map_err(|_| ERROR)?;
        if PublicJwk::from_key(&key) != public_key {
            return Err(ERROR);
        }
        let mut description = None;
        for (index, certificate) in certificates.iter().enumerate() {
            for extension in certificate.tbs_certificate.extensions.iter().flatten() {
                if extension.extn_id == OID {
                    // Strict leaf-only subset: refuse extension ambiguity or an
                    // attacker-appended child of another attested key. A server
                    // verifier must implement authoritative root-to-leaf selection.
                    if index != 0 || description.is_some() {
                        return Err(ERROR);
                    }
                    description = Some(extension.extn_value.as_bytes());
                }
            }
        }
        let sequence = AnyRef::from_der(description.ok_or(ERROR)?).map_err(|_| ERROR)?;
        if sequence.tag() != Tag::Sequence {
            return Err(ERROR);
        }
        let mut reader = SliceReader::new(sequence.value()).map_err(|_| ERROR)?;
        // KeyDescription: version, security level, keymaster version/level,
        // challenge, unique ID, software/hardware authorization lists.
        for tag in [Tag::Integer, Tag::Enumerated, Tag::Integer, Tag::Enumerated] {
            let field: AnyRef = reader.decode().map_err(|_| ERROR)?;
            if field.tag() != tag || field.value().is_empty() {
                return Err(ERROR);
            }
            if tag == Tag::Integer {
                let _: u32 = field.decode_as().map_err(|_| ERROR)?;
            } else if field.value().len() != 1 || field.value()[0] > 2 {
                return Err(ERROR);
            }
        }
        let actual: AnyRef = reader.decode().map_err(|_| ERROR)?;
        if actual.tag() != Tag::OctetString || actual.value() != challenge {
            return Err(ERROR);
        }
        let unique_id: AnyRef = reader.decode().map_err(|_| ERROR)?;
        if unique_id.tag() != Tag::OctetString || !unique_id.value().is_empty() {
            return Err(ERROR);
        }
        for tag in [Tag::Sequence, Tag::Sequence] {
            let field: AnyRef = reader.decode().map_err(|_| ERROR)?;
            if field.tag() != tag {
                return Err(ERROR);
            }
        }
        reader.finish(()).map_err(|_| ERROR)?;
        Ok(Self {
            challenge: B64.encode(challenge),
            public_key,
            certificate_chain,
        })
    }
}
