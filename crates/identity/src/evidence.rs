//! Static issuer signatures prove data authenticity, not live card possession.
use crate::card::{CardPreview, DocumentType, license_fields, parse_license, parse_preview};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub document_type: DocumentType,
    pub attributes: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(default)]
    pub domicile: Vec<u8>,
    #[serde(default)]
    pub photo: Vec<u8>,
}
impl Evidence {
    pub fn new(document_type: DocumentType) -> Self {
        Self {
            document_type,
            attributes: vec![],
            signature: vec![],
            domicile: vec![],
            photo: vec![],
        }
    }
}
impl Drop for Evidence {
    fn drop(&mut self) {
        self.attributes.zeroize();
        self.signature.zeroize();
        self.domicile.zeroize();
        self.photo.zeroize();
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub id: String,
    pub document_type: DocumentType,
    pub n: String,
    pub e: String,
    /// NPA EF07/B6. Must match for a driver's licence.
    pub subject_key_identifier: Option<String>,
    pub not_before: u64,
    pub not_after: u64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedDocument {
    pub attributes: CardPreview,
    pub trusted_key_id: String,
    pub verified_at: u64,
    pub assurance: String,
    pub attributes_source: String,
}
#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    InvalidEvidence,
    UntrustedIssuer,
    SignatureInvalid,
    ExpiredDocument,
}

fn tlv(bytes: &[u8]) -> Result<(u32, &[u8], &[u8]), VerificationError> {
    let bad = VerificationError::InvalidEvidence;
    let first = *bytes.first().ok_or(bad)?;
    let mut tag = first as u32;
    let mut i = 1;
    if first & 31 == 31 {
        loop {
            if i >= 4 {
                return Err(VerificationError::InvalidEvidence);
            }
            let b = *bytes.get(i).ok_or(VerificationError::InvalidEvidence)?;
            tag = (tag << 8) | b as u32;
            i += 1;
            if b & 128 == 0 {
                break;
            }
        }
    }
    let b = *bytes.get(i).ok_or(VerificationError::InvalidEvidence)?;
    i += 1;
    let length = if b < 128 {
        b as usize
    } else {
        let n = (b & 127) as usize;
        if n == 0 || n > 2 || i + n > bytes.len() {
            return Err(VerificationError::InvalidEvidence);
        }
        let mut length = 0;
        for b in &bytes[i..i + n] {
            length = (length << 8) | *b as usize;
        }
        i += n;
        length
    };
    let value = bytes
        .get(i..i + length)
        .ok_or(VerificationError::InvalidEvidence)?;
    Ok((tag, value, &bytes[i + length..]))
}
struct MncSignature {
    message: Zeroizing<Vec<u8>>,
    attributes_hash: Vec<u8>,
    signature: Vec<u8>,
}
fn mnc_signature(raw: &[u8]) -> Result<MncSignature, VerificationError> {
    let (tag, mut body, rest) = tlv(raw)?;
    if tag != 0xff30 || !rest.iter().all(|b| matches!(b, 0 | 255)) {
        return Err(VerificationError::InvalidEvidence);
    }
    let mut fields = std::collections::HashMap::new();
    while !body.is_empty() {
        let (tag, value, rest) = tlv(body)?;
        if !matches!(tag, 0xdf31..=0xdf33) || fields.insert(tag, value).is_some() {
            return Err(VerificationError::InvalidEvidence);
        }
        body = rest;
    }
    let get = |tag, len| {
        fields
            .get(&tag)
            .filter(|v| v.len() == len)
            .copied()
            .ok_or(VerificationError::InvalidEvidence)
    };
    let h1 = get(0xdf31, 32)?;
    let h2 = get(0xdf32, 32)?;
    let sig = get(0xdf33, 256)?;
    let mut message = Zeroizing::new(vec![0xdf, 0x31, 32]);
    message.extend(h1);
    message.extend([0xdf, 0x32, 32]);
    message.extend(h2);
    Ok(MncSignature {
        message,
        attributes_hash: h2.to_vec(),
        signature: sig.to_vec(),
    })
}
pub fn date_end(date: &str) -> Option<u64> {
    if !crate::card::valid_date(date) {
        return None;
    }
    let mut y = date[..4].parse::<i64>().ok()?;
    let m = date[5..7].parse::<i64>().ok()?;
    let d = date[8..].parse::<i64>().ok()?;
    y -= i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yo = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let days = era * 146097 + yo * 365 + yo / 4 - yo / 100 + (153 * mp + 2) / 5 + d - 1 - 719468;
    u64::try_from((days + 1) * 86400).ok()
}

pub fn verify(
    evidence: &Evidence,
    trust: &[TrustedKey],
    now: u64,
) -> Result<VerifiedDocument, VerificationError> {
    let bad = || VerificationError::InvalidEvidence;
    if evidence.attributes.len() > 4096
        || evidence.signature.len() > 4096
        || evidence.domicile.len() > 82
        || evidence.photo.len() > 2005
        || trust.len() > 16
    {
        return Err(bad());
    }
    let (mut attributes, hash, signature, ski, padding) = match evidence.document_type {
        DocumentType::MyNumberCard => {
            if !evidence.domicile.is_empty() || !evidence.photo.is_empty() {
                return Err(bad());
            }
            let attributes = parse_preview(&evidence.attributes).map_err(|_| bad())?;
            let MncSignature {
                message,
                attributes_hash: expected_hash,
                signature: sig,
            } = mnc_signature(&evidence.signature)?;
            let raw = &evidence.attributes;
            let trimmed = raw;
            let end = trimmed
                .iter()
                .rposition(|b| *b != 255 && *b != 0)
                .map(|i| i + 1)
                .ok_or_else(bad)?;
            // Every accepted signed preimage must independently yield precisely the same four attributes.
            let mut candidates: Vec<&[u8]> = vec![raw, &raw[..end]];
            for (i, w) in raw.windows(2).enumerate() {
                if w == [0xdf, 0x22] {
                    candidates.push(&raw[i..end]);
                    break;
                }
            }
            if !candidates.iter().any(|v| {
                Sha256::digest(v)[..] == expected_hash
                    && parse_preview(v).is_ok_and(|p| p == attributes)
            }) {
                return Err(VerificationError::SignatureInvalid);
            }
            (
                attributes,
                Sha256::digest(&message[..]).to_vec(),
                sig,
                None,
                Pkcs1v15Sign::new::<Sha256>(),
            )
        }
        DocumentType::DrivingLicense => {
            // NPA specification §4: hash entire fixed-size EFs, including padding.
            if evidence.attributes.len() != 880
                || evidence.domicile.len() != 82
                || evidence.photo.len() != 2005
                || evidence.signature.len() != 578
            {
                return Err(bad());
            }
            let attributes = parse_license(&evidence.attributes).map_err(|_| bad())?;
            if date_end(attributes.expiry_date.as_deref().ok_or_else(bad)?)
                .is_none_or(|end| now >= end)
            {
                return Err(VerificationError::ExpiredDocument);
            }
            let fields = license_fields(&evidence.signature).map_err(|_| bad())?;
            let sig = fields
                .get(&0xb1)
                .filter(|v| v.len() == 256)
                .ok_or_else(bad)?
                .to_vec();
            let ski = fields
                .get(&0xb6)
                .filter(|v| v.len() == 32)
                .ok_or_else(bad)?
                .to_vec();
            let mut h = Sha256::new();
            h.update(&evidence.attributes);
            h.update(&evidence.domicile);
            h.update(&evidence.photo);
            (
                attributes,
                h.finalize().to_vec(),
                sig,
                Some(B64.encode(ski)),
                Pkcs1v15Sign::new_unprefixed(),
            )
        }
    };
    let mut eligible = false;
    for key in trust.iter().filter(|k| {
        k.document_type == evidence.document_type
            && k.not_before <= now
            && now < k.not_after
            && (ski.is_none() || k.subject_key_identifier == ski)
    }) {
        let (Ok(n), Ok(e)) = (B64.decode(&key.n), B64.decode(&key.e)) else {
            continue;
        };
        if n.len() != 256
            || n[0] & 128 == 0
            || e != [1, 0, 1]
            || key.id.is_empty()
            || key.id.len() > 128
        {
            continue;
        }
        let Ok(public) = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
        else {
            continue;
        };
        eligible = true;
        if public.verify(padding.clone(), &hash, &signature).is_ok() {
            attributes.verification = "issuer_signed_static_data".into();
            return Ok(VerifiedDocument {
                attributes,
                trusted_key_id: key.id.clone(),
                verified_at: now,
                assurance: "issuer_signed_static_data".into(),
                attributes_source: match evidence.document_type {
                    DocumentType::DrivingLicense => "issuance_base_ef",
                    DocumentType::MyNumberCard => "input_support_ef",
                }
                .into(),
            });
        }
    }
    Err(if eligible {
        VerificationError::SignatureInvalid
    } else {
        VerificationError::UntrustedIssuer
    })
}
