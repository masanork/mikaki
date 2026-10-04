//! First-party linked-attribute mdoc. Not an ISO mDL or government PID.
//! DeviceAuthentication is transport independent; transcript constructors are explicit.
use crate::{evidence::VerifiedDocument, issuance::PublicJwk};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ciborium::Value as C;
use der::{Decode, Encode};
use p256::{
    ecdsa::{
        Signature, SigningKey,
        signature::{Signer, Verifier},
    },
    pkcs8::DecodePublicKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
pub const CONFIGURATION: &str = "linked_document_mdoc";
pub const DOCTYPE: &str = "app.tossa.mikaki.linked_document.1";
pub const NAMESPACE: &str = "app.tossa.mikaki.linked_document.1";
fn text(s: &str) -> C {
    C::Text(s.into())
}
fn integer(n: i64) -> C {
    C::Integer(n.into())
}
fn bytes(b: impl Into<Vec<u8>>) -> C {
    C::Bytes(b.into())
}
fn array(v: Vec<C>) -> C {
    C::Array(v)
}
fn map(v: Vec<(&str, C)>) -> C {
    C::Map(v.into_iter().map(|(k, v)| (text(k), v)).collect())
}
fn tag(v: C) -> Result<C, &'static str> {
    Ok(C::Tag(24, Box::new(bytes(encode(&v)?))))
}
pub fn encode(v: &C) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).map_err(|_| "invalid_mdoc")?;
    Ok(out)
}
// Scan before allocating: definite-length, bounded-depth/collections/total nodes, no floats.
fn scan(b: &[u8], p: &mut usize, depth: usize, nodes: &mut usize) -> Result<(), &'static str> {
    *nodes += 1;
    if depth > 16 || *nodes > 512 {
        return Err("invalid_mdoc");
    }
    let h = *b.get(*p).ok_or("invalid_mdoc")?;
    *p += 1;
    let major = h >> 5;
    let ai = h & 31;
    let n = match ai {
        0..=23 => u64::from(ai),
        24..=27 => {
            let size = 1usize << (ai - 24);
            let end = p.checked_add(size).ok_or("invalid_mdoc")?;
            let raw = b.get(*p..end).ok_or("invalid_mdoc")?;
            *p = end;
            raw.iter().fold(0u64, |a, v| (a << 8) | u64::from(*v))
        }
        _ => return Err("invalid_mdoc"),
    };
    match major {
        0 | 1 => {}
        2 | 3 => {
            let len = usize::try_from(n).map_err(|_| "invalid_mdoc")?;
            *p = p
                .checked_add(len)
                .filter(|p| *p <= b.len())
                .ok_or("invalid_mdoc")?
        }
        4 | 5 => {
            if n > 64 {
                return Err("invalid_mdoc");
            }
            for _ in 0..n * (if major == 5 { 2 } else { 1 }) {
                scan(b, p, depth + 1, nodes)?
            }
        }
        6 => {
            if n != 24 && n != 0 {
                return Err("invalid_mdoc");
            }
            scan(b, p, depth + 1, nodes)?
        }
        7 if matches!(ai, 20..=22) => {}
        _ => return Err("invalid_mdoc"),
    };
    Ok(())
}
fn unique(v: &C) -> Result<(), &'static str> {
    match v {
        C::Map(m) => {
            let mut seen = HashSet::new();
            for (k, v) in m {
                if !seen.insert(encode(k)?) {
                    return Err("invalid_mdoc");
                }
                unique(k)?;
                unique(v)?;
            }
        }
        C::Array(a) => {
            for v in a {
                unique(v)?
            }
        }
        C::Tag(_, v) => unique(v)?,
        _ => {}
    }
    Ok(())
}
pub fn decode(b: &[u8]) -> Result<C, &'static str> {
    if b.is_empty() || b.len() > 32000 {
        return Err("invalid_mdoc");
    }
    let mut p = 0;
    scan(b, &mut p, 0, &mut 0)?;
    if p != b.len() {
        return Err("invalid_mdoc");
    }
    let v: C = ciborium::de::from_reader(b).map_err(|_| "invalid_mdoc")?;
    unique(&v)?;
    if encode(&v)? != b {
        return Err("invalid_mdoc");
    }
    Ok(v)
}
fn get<'a>(v: &'a C, k: &str) -> Result<&'a C, &'static str> {
    let C::Map(m) = v else {
        return Err("invalid_mdoc");
    };
    m.iter()
        .find(|(key, _)| key == &text(k))
        .map(|(_, v)| v)
        .ok_or("invalid_mdoc")
}
fn numeric(v: &C) -> Result<u64, &'static str> {
    v.as_integer()
        .and_then(|n| u64::try_from(n).ok())
        .ok_or("invalid_mdoc")
}
fn embedded(v: &C) -> Result<C, &'static str> {
    let C::Tag(24, b) = v else {
        return Err("invalid_mdoc");
    };
    decode(b.as_bytes().ok_or("invalid_mdoc")?)
}
fn date(now: u64) -> Result<C, &'static str> {
    let t = der::DateTime::from_unix_duration(std::time::Duration::from_secs(now))
        .map_err(|_| "invalid_mdoc")?;
    Ok(C::Tag(
        0,
        Box::new(text(&format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year(),
            t.month(),
            t.day(),
            t.hour(),
            t.minutes(),
            t.seconds()
        ))),
    ))
}
fn timestamp(v: &C) -> Result<u64, &'static str> {
    let C::Tag(0, v) = v else {
        return Err("invalid_mdoc");
    };
    let s = v.as_text().ok_or("invalid_mdoc")?;
    if s.len() != 20
        || !s.is_ascii()
        || s.as_bytes()[4] != b'-'
        || s.as_bytes()[7] != b'-'
        || s.as_bytes()[10] != b'T'
        || s.as_bytes()[13] != b':'
        || s.as_bytes()[16] != b':'
        || s.as_bytes()[19] != b'Z'
    {
        return Err("invalid_mdoc");
    }
    let part = |a, b| s[a..b].parse::<u16>().map_err(|_| "invalid_mdoc");
    der::DateTime::new(
        part(0, 4)?,
        part(5, 7)? as u8,
        part(8, 10)? as u8,
        part(11, 13)? as u8,
        part(14, 16)? as u8,
        part(17, 19)? as u8,
    )
    .map(|t| t.unix_duration().as_secs())
    .map_err(|_| "invalid_mdoc")
}
fn protected() -> Result<Vec<u8>, &'static str> {
    encode(&C::Map(vec![(integer(1), integer(-7))]))
}
pub fn signature_input(payload: &[u8]) -> Result<Vec<u8>, &'static str> {
    encode(&array(vec![
        text("Signature1"),
        bytes(protected()?),
        bytes(vec![]),
        bytes(payload.to_vec()),
    ]))
}
fn sign1(payload: C, unprotected: C, sig: &[u8]) -> Result<C, &'static str> {
    if sig.len() != 64 {
        return Err("invalid_mdoc");
    }
    Ok(array(vec![
        bytes(protected()?),
        unprotected,
        payload,
        bytes(sig.to_vec()),
    ]))
}
fn cose_key(jwk: &PublicJwk) -> Result<C, &'static str> {
    jwk.verifying_key()?;
    Ok(C::Map(vec![
        (integer(1), integer(2)),
        (integer(-1), integer(1)),
        (
            integer(-2),
            bytes(B64.decode(&jwk.x).map_err(|_| "invalid_key")?),
        ),
        (
            integer(-3),
            bytes(B64.decode(&jwk.y).map_err(|_| "invalid_key")?),
        ),
    ]))
}
/// Exact TLS-pinned issuer key is the trust anchor here, not a certificate supplied by a card.
/// Full IACA chain/revocation validation belongs to the relying-party trust profile.
pub fn validate_certificate(cert: &[u8], key: &PublicJwk, now: u64) -> Result<(), &'static str> {
    use der::asn1::ObjectIdentifier;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
    if cert.len() > 4096 {
        return Err("invalid_mdoc_certificate");
    }
    let c = x509_cert::Certificate::from_der(cert).map_err(|_| "invalid_mdoc_certificate")?;
    let t = &c.tbs_certificate;
    let public = p256::ecdsa::VerifyingKey::from_public_key_der(
        &t.subject_public_key_info
            .to_der()
            .map_err(|_| "invalid_mdoc_certificate")?,
    )
    .map_err(|_| "invalid_mdoc_certificate")?;
    if PublicJwk::from_key(&public) != *key
        || now < t.validity.not_before.to_unix_duration().as_secs()
        || now >= t.validity.not_after.to_unix_duration().as_secs()
    {
        return Err("invalid_mdoc_certificate");
    }
    let mut extension_ids = HashSet::new();
    if t.extensions
        .as_ref()
        .is_none_or(|exts| exts.iter().any(|ext| !extension_ids.insert(ext.extn_id)))
    {
        return Err("invalid_mdoc_certificate");
    }
    let extension = |oid: ObjectIdentifier| {
        t.extensions
            .as_ref()
            .and_then(|e| e.iter().find(|x| x.extn_id == oid))
            .map(|e| e.extn_value.as_bytes())
            .ok_or("invalid_mdoc_certificate")
    };
    let ku = KeyUsage::from_der(extension(ObjectIdentifier::new_unwrap("2.5.29.15"))?)
        .map_err(|_| "invalid_mdoc_certificate")?;
    let eku = ExtendedKeyUsage::from_der(extension(ObjectIdentifier::new_unwrap("2.5.29.37"))?)
        .map_err(|_| "invalid_mdoc_certificate")?;
    let bc = BasicConstraints::from_der(extension(ObjectIdentifier::new_unwrap("2.5.29.19"))?)
        .map_err(|_| "invalid_mdoc_certificate")?;
    if !ku.digital_signature()
        || ku.key_cert_sign()
        || bc.ca
        || !eku
            .0
            .contains(&ObjectIdentifier::new_unwrap("1.0.18013.5.1.2"))
    {
        return Err("invalid_mdoc_certificate");
    }
    Ok(())
}
pub fn certificate_valid_until(
    cert: &[u8],
    issuer: &PublicJwk,
    now: u64,
) -> Result<u64, &'static str> {
    validate_certificate(cert, issuer, now)?;
    Ok(x509_cert::Certificate::from_der(cert)
        .map_err(|_| "invalid_mdoc_certificate")?
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs())
}
pub fn issue(
    key: &SigningKey,
    cert: &[u8],
    holder: &PublicJwk,
    document: &VerifiedDocument,
    now: u64,
    salts: &[[u8; 16]],
) -> Result<String, &'static str> {
    issue_with_validity(
        key,
        cert,
        holder,
        document,
        crate::issuance::Validity::new(document, now, u64::MAX)?,
        salts,
    )
}
pub fn issue_with_validity(
    key: &SigningKey,
    cert: &[u8],
    holder: &PublicJwk,
    document: &VerifiedDocument,
    validity: crate::issuance::Validity,
    salts: &[[u8; 16]],
) -> Result<String, &'static str> {
    let now = validity.issued_at();
    let end = certificate_valid_until(cert, &PublicJwk::from_key(key.verifying_key()), now)?;
    let validity = crate::issuance::Validity::new(document, now, validity.expires_at().min(end))?;
    let a = &document.attributes;
    let mut values = vec![
        ("name", text(&a.name)),
        ("address", text(&a.address)),
        ("birthdate", text(&a.birth_date)),
    ];
    if !a.gender.is_empty() {
        values.push(("gender", text(&a.gender)))
    }
    if let Some(exp) = &a.expiry_date {
        values.push(("document_expiry_date", text(exp)))
    }
    if values.len() != salts.len() {
        return Err("invalid_salts");
    }
    let mut items = Vec::new();
    let mut digests = Vec::new();
    for (i, ((name, value), salt)) in values.into_iter().zip(salts).enumerate() {
        let item = tag(map(vec![
            ("digestID", integer(i as i64)),
            ("random", bytes(salt.to_vec())),
            ("elementIdentifier", text(name)),
            ("elementValue", value),
        ]))?;
        digests.push((
            integer(i as i64),
            bytes(Sha256::digest(encode(&item)?).to_vec()),
        ));
        items.push(item);
    }
    let mso = tag(map(vec![
        ("version", text("1.0")),
        ("digestAlgorithm", text("SHA-256")),
        ("valueDigests", map(vec![(NAMESPACE, C::Map(digests))])),
        ("deviceKeyInfo", map(vec![("deviceKey", cose_key(holder)?)])),
        ("docType", text(DOCTYPE)),
        (
            "validityInfo",
            map(vec![
                ("signed", date(now)?),
                ("validFrom", date(now)?),
                ("validUntil", date(validity.expires_at())?),
            ]),
        ),
    ]))?;
    let payload = encode(&mso)?;
    let signature: Signature = key.sign(&signature_input(&payload)?);
    let auth = sign1(
        bytes(payload),
        C::Map(vec![(integer(33), bytes(cert.to_vec()))]),
        &signature.to_bytes(),
    )?;
    Ok(B64.encode(encode(&map(vec![
        ("nameSpaces", map(vec![(NAMESPACE, array(items))])),
        ("issuerAuth", auth),
    ]))?))
}
pub struct Validated {
    holder: PublicJwk,
    pub issuer_signed: C,
    pub values: Value,
    pub expires_at: u64,
}
pub fn verify_receipt(
    credential: &str,
    issuer: &PublicJwk,
    holder: &PublicJwk,
    now: u64,
) -> Result<Validated, &'static str> {
    if credential.len() > 43000 {
        return Err("invalid_mdoc");
    }
    let signed = decode(&B64.decode(credential).map_err(|_| "invalid_mdoc")?)?;
    let auth = get(&signed, "issuerAuth")?
        .as_array()
        .filter(|a| a.len() == 4)
        .ok_or("invalid_mdoc")?;
    if auth[0] != bytes(protected()?) {
        return Err("invalid_mdoc");
    }
    let headers = auth[1]
        .as_map()
        .filter(|m| m.len() == 1)
        .ok_or("invalid_mdoc")?;
    let (label, cert) = &headers[0];
    if *label != integer(33) {
        return Err("invalid_mdoc_certificate");
    }
    validate_certificate(
        cert.as_bytes().ok_or("invalid_mdoc_certificate")?,
        issuer,
        now,
    )?;
    let payload = auth[2].as_bytes().ok_or("invalid_mdoc")?;
    let signature = Signature::from_slice(auth[3].as_bytes().ok_or("invalid_mdoc")?)
        .map_err(|_| "invalid_mdoc")?;
    issuer
        .verifying_key()?
        .verify(&signature_input(payload)?, &signature)
        .map_err(|_| "invalid_mdoc_signature")?;
    let mso = embedded(&decode(payload)?)?;
    if get(&mso, "version")? != &text("1.0")
        || get(&mso, "digestAlgorithm")? != &text("SHA-256")
        || get(&mso, "docType")? != &text(DOCTYPE)
        || get(get(&mso, "deviceKeyInfo")?, "deviceKey")? != &cose_key(holder)?
    {
        return Err("invalid_mdoc");
    }
    let validity = get(&mso, "validityInfo")?;
    let signed_at = timestamp(get(validity, "signed")?)?;
    let from = timestamp(get(validity, "validFrom")?)?;
    let exp = timestamp(get(validity, "validUntil")?)?;
    if from != signed_at
        || signed_at > now.saturating_add(30)
        || exp <= now
        || exp <= signed_at
        || exp > signed_at.saturating_add(300)
    {
        return Err("invalid_mdoc");
    }
    validate_certificate(
        cert.as_bytes().ok_or("invalid_mdoc_certificate")?,
        issuer,
        exp.saturating_sub(1),
    )?;
    let digests = get(get(&mso, "valueDigests")?, NAMESPACE)?
        .as_map()
        .ok_or("invalid_mdoc")?;
    let spaces = get(&signed, "nameSpaces")?
        .as_map()
        .filter(|m| m.len() == 1)
        .ok_or("invalid_mdoc")?;
    if spaces[0].0 != text(NAMESPACE) {
        return Err("invalid_mdoc");
    }
    let items = spaces[0]
        .1
        .as_array()
        .filter(|a| (3..=5).contains(&a.len()) && a.len() == digests.len())
        .ok_or("invalid_mdoc")?;
    let mut values = json!({});
    let mut ids = HashSet::new();
    for item in items {
        let inner = embedded(item)?;
        let id = numeric(get(&inner, "digestID")?)?;
        if id > 4 || !ids.insert(id) {
            return Err("invalid_mdoc");
        }
        let digest = digests
            .iter()
            .find(|(k, _)| *k == integer(id as i64))
            .map(|(_, v)| v)
            .ok_or("invalid_mdoc")?;
        if *digest != bytes(Sha256::digest(encode(item)?).to_vec())
            || get(&inner, "random")?
                .as_bytes()
                .is_none_or(|b| b.len() < 16)
        {
            return Err("invalid_mdoc_digest");
        }
        let name = get(&inner, "elementIdentifier")?
            .as_text()
            .ok_or("invalid_mdoc")?;
        if !matches!(
            name,
            "name" | "address" | "birthdate" | "gender" | "document_expiry_date"
        ) || values.get(name).is_some()
        {
            return Err("invalid_mdoc");
        }
        values[name] = json!(
            get(&inner, "elementValue")?
                .as_text()
                .ok_or("invalid_mdoc")?
        );
    }
    if ["name", "address", "birthdate"]
        .iter()
        .any(|k| values.get(k).is_none())
    {
        return Err("invalid_mdoc");
    }
    crate::issuance::check_document_expiry(&values, exp).map_err(|_| "invalid_mdoc")?;
    Ok(Validated {
        holder: holder.clone(),
        issuer_signed: signed,
        values,
        expires_at: exp,
    })
}
/// OpenID4VP Final redirect/direct_post (NOT ISO 18013-7 Annex B).
pub fn oid4vp_transcript(
    client_id: &str,
    nonce: &str,
    response_uri: &str,
) -> Result<Vec<u8>, &'static str> {
    oid4vp_encrypted_transcript(client_id, nonce, response_uri, None)
}
/// Final redirect handover binds the RFC 7638 recipient key thumbprint for encrypted responses.
pub fn oid4vp_encrypted_transcript(
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    thumbprint: Option<&[u8; 32]>,
) -> Result<Vec<u8>, &'static str> {
    let info = encode(&array(vec![
        text(client_id),
        text(nonce),
        thumbprint.map(|h| bytes(h.to_vec())).unwrap_or(C::Null),
        text(response_uri),
    ]))?;
    encode(&array(vec![
        C::Null,
        C::Null,
        array(vec![
            text("OpenID4VPHandover"),
            bytes(Sha256::digest(info).to_vec()),
        ]),
    ]))
}
/// Draft 18 / 18013-7:2024 Annex B wire handover; never substitute the Final hash.
pub fn oid4vp_draft18_transcript(
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    wallet_nonce: &str,
) -> Result<Vec<u8>, &'static str> {
    if wallet_nonce.len() != 43 {
        return Err("invalid_wallet_nonce");
    }
    let client_hash = Sha256::digest(encode(&array(vec![text(client_id), text(wallet_nonce)]))?);
    let uri_hash = Sha256::digest(encode(&array(vec![
        text(response_uri),
        text(wallet_nonce),
    ]))?);
    encode(&array(vec![
        C::Null,
        C::Null,
        array(vec![
            bytes(client_hash.to_vec()),
            bytes(uri_hash.to_vec()),
            text(nonce),
        ]),
    ]))
}
/// Transport-generated engagement and reader key must be retained exactly for QR retrieval.
pub fn qr_transcript(engagement: &[u8], reader_key: &[u8]) -> Result<Vec<u8>, &'static str> {
    decode(engagement)?;
    decode(reader_key)?;
    encode(&array(vec![
        C::Tag(24, Box::new(bytes(engagement.to_vec()))),
        C::Tag(24, Box::new(bytes(reader_key.to_vec()))),
        C::Null,
    ]))
}
pub fn device_authentication(transcript: &[u8]) -> Result<Vec<u8>, &'static str> {
    let transcript = decode(transcript)?;
    if transcript.as_array().is_none_or(|a| a.len() != 3) {
        return Err("invalid_transcript");
    }
    encode(&tag(array(vec![
        text("DeviceAuthentication"),
        transcript,
        text(DOCTYPE),
        tag(map(vec![]))?,
    ]))?)
}
pub fn selected_values(receipt: &Validated, fields: &[String]) -> Result<Value, &'static str> {
    if fields.len() > 5 {
        return Err("unsupported_query");
    }
    let mut values = json!({});
    let mut seen = HashSet::new();
    for field in fields {
        if !seen.insert(field) {
            return Err("unsupported_query");
        }
        values[field] = receipt
            .values
            .get(field)
            .ok_or("credential_does_not_match")?
            .clone();
    }
    Ok(values)
}
/// Signature is from the MSO's existing device key over signature_input(device_authentication).
pub fn device_response(
    receipt: &Validated,
    fields: &[String],
    transcript: &[u8],
    signature: &[u8],
    holder: &PublicJwk,
) -> Result<String, &'static str> {
    if receipt.holder != *holder {
        return Err("invalid_device_key");
    }
    selected_values(receipt, fields)?;
    let payload = device_authentication(transcript)?;
    holder
        .verifying_key()?
        .verify(
            &signature_input(&payload)?,
            &Signature::from_slice(signature).map_err(|_| "invalid_device_signature")?,
        )
        .map_err(|_| "invalid_device_signature")?;
    let items = get(get(&receipt.issuer_signed, "nameSpaces")?, NAMESPACE)?
        .as_array()
        .ok_or("invalid_mdoc")?;
    let selected = items
        .iter()
        .filter_map(|item| {
            let inner = embedded(item).ok()?;
            let name = get(&inner, "elementIdentifier").ok()?.as_text()?;
            fields.iter().any(|s| s == name).then_some(item.clone())
        })
        .collect();
    let mut issuer_fields = vec![(
        "issuerAuth",
        get(&receipt.issuer_signed, "issuerAuth")?.clone(),
    )];
    // ISO IssuerSigned.nameSpaces is optional; do not emit an empty namespace array.
    if !fields.is_empty() {
        issuer_fields.push(("nameSpaces", map(vec![(NAMESPACE, array(selected))])));
    }
    let issuer_signed = map(issuer_fields);
    let device_signed = map(vec![
        ("nameSpaces", tag(map(vec![]))?),
        (
            "deviceAuth",
            map(vec![(
                "deviceSignature",
                sign1(C::Null, map(vec![]), signature)?,
            )]),
        ),
    ]);
    Ok(B64.encode(encode(&map(vec![
        ("version", text("1.0")),
        (
            "documents",
            array(vec![map(vec![
                ("docType", text(DOCTYPE)),
                ("issuerSigned", issuer_signed),
                ("deviceSigned", device_signed),
            ])]),
        ),
        ("status", integer(0)),
    ]))?))
}

/// NFC handover uses exact NDEF Handover Select/Request bytes from the transport.
/// This does not implement NDEF negotiation or reader authentication.
pub fn nfc_transcript(
    engagement: &[u8],
    reader_key: &[u8],
    handover_select: &[u8],
    handover_request: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    let mut transcript = decode(&qr_transcript(engagement, reader_key)?)?;
    if handover_select.is_empty()
        || handover_select.len() > 4096
        || handover_request.is_some_and(|r| r.is_empty() || r.len() > 4096)
    {
        return Err("invalid_transcript");
    }
    let C::Array(ref mut a) = transcript else {
        return Err("invalid_transcript");
    };
    a[2] = array(vec![
        bytes(handover_select.to_vec()),
        handover_request
            .map(|b| bytes(b.to_vec()))
            .unwrap_or(C::Null),
    ]);
    encode(&transcript)
}

pub mod proximity;
