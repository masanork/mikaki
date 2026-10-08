//! ISO 18013-5 QR + BLE peripheral holder core. No radio or WebView secrets here.
use super::*;
mod handover;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub struct HolderSession {
    ephemeral: Option<SecretKey>,
    engagement: Vec<u8>,
    transcript: Option<Vec<u8>>,
    handover_select: Option<Vec<u8>>,
    negotiated: bool,
    nfc_data_handover: bool,
    handover_request: Option<Vec<u8>>,
    cipher: Option<SessionCipher>,
    requested: Option<DeviceRequest>,
    closed: bool,
}
impl HolderSession {
    /// Caller supplies a freshly generated, per-session P-256 key; never the MSO device key.
    pub fn new(ephemeral: SecretKey, service_uuid: [u8; 16]) -> Result<Self, &'static str> {
        let jwk = PublicJwk::from_key(&p256::ecdsa::VerifyingKey::from(ephemeral.public_key()));
        let security = array(vec![integer(1), tag(cose_key(&jwk)?)?]);
        let method = array(vec![
            integer(2),
            integer(1),
            C::Map(vec![
                (integer(0), C::Bool(true)),
                (integer(1), C::Bool(false)),
                (integer(10), bytes(service_uuid.to_vec())),
            ]),
        ]);
        let engagement = encode(&C::Map(vec![
            (integer(0), text("1.0")),
            (integer(1), security),
            (integer(2), array(vec![method])),
        ]))?;
        Ok(Self {
            ephemeral: Some(ephemeral),
            engagement,
            transcript: None,
            handover_select: None,
            negotiated: false,
            nfc_data_handover: false,
            handover_request: None,
            cipher: None,
            requested: None,
            closed: false,
        })
    }
    /// Explicit NFC static handover profile. QR and NFC transcripts are never auto-detected.
    pub fn new_nfc(ephemeral: SecretKey, service_uuid: [u8; 16]) -> Result<Self, &'static str> {
        let mut session = Self::new(ephemeral, service_uuid)?;
        let mut engagement = decode(&session.engagement)?;
        engagement
            .as_map_mut()
            .ok_or("invalid_engagement")?
            .retain(|(k, _)| *k != integer(2));
        session.engagement = encode(&engagement)?;
        session.handover_select = Some(static_handover_select(&session.engagement, service_uuid)?);
        Ok(session)
    }
    /// NFC TNEP negotiation must complete before any encrypted session is accepted.
    pub fn new_nfc_negotiated(ephemeral: SecretKey, uuid: [u8; 16]) -> Result<Self, &'static str> {
        let mut session = Self::new_nfc(ephemeral, uuid)?;
        session.negotiated = true;
        Ok(session)
    }
    /// TNEP engagement followed by NFC APDU retrieval; no BLE carrier or QR fallback.
    pub fn new_nfc_negotiated_data(ephemeral: SecretKey) -> Result<Self, &'static str> {
        let mut session = Self::new_nfc_negotiated(ephemeral, [0; 16])?;
        session.nfc_data_handover = true;
        session.handover_select = Some(nfc_data_handover_select(&session.engagement)?);
        Ok(session)
    }
    /// Preserve original NDEF bytes, including record flags/order, in the transcript.
    pub fn negotiate(&mut self, request: &[u8]) -> Result<&[u8], &'static str> {
        if self.closed || !self.negotiated || self.handover_request.is_some() {
            self.close();
            return Err("invalid_handover_state");
        }
        if let Err(error) = handover::validate_request(request, self.nfc_data_handover) {
            self.close();
            return Err(error);
        }
        self.handover_request = Some(request.to_vec());
        self.handover_select.as_deref().ok_or("invalid_handover")
    }
    /// QR engagement with NFC data retrieval only: short command data 255, response data 256.
    pub fn new_nfc_data(ephemeral: SecretKey) -> Result<Self, &'static str> {
        let mut session = Self::new(ephemeral, [0; 16])?;
        let mut engagement = decode(&session.engagement)?;
        let fields = engagement.as_map_mut().ok_or("invalid_engagement")?;
        let method = array(vec![
            integer(1),
            integer(1),
            C::Map(vec![(integer(0), integer(255)), (integer(1), integer(256))]),
        ]);
        fields
            .iter_mut()
            .find(|(k, _)| *k == integer(2))
            .ok_or("invalid_engagement")?
            .1 = array(vec![method]);
        session.engagement = encode(&engagement)?;
        Ok(session)
    }
    pub fn handover_select(&self) -> Option<&[u8]> {
        self.handover_select.as_deref()
    }
    pub fn qr_uri(&self) -> String {
        format!("mdoc:{}", B64.encode(&self.engagement))
    }
    pub fn engagement(&self) -> &[u8] {
        &self.engagement
    }
    pub fn transcript(&self) -> Result<&[u8], &'static str> {
        self.transcript.as_deref().ok_or("session_not_established")
    }
    /// Exactly one SessionEstablishment. Any parse/authentication error destroys the session.
    pub fn establish(
        &mut self,
        packet: &[u8],
        readers: &[ReaderRegistration],
        now: u64,
    ) -> Result<&DeviceRequest, &'static str> {
        if self.closed || self.ephemeral.is_none() {
            return Err("session_consumed");
        }
        let key = self.ephemeral.take().ok_or("session_consumed")?;
        let result = (|| {
            if self.negotiated && self.handover_request.is_none() {
                return Err("handover_required");
            }
            let establishment = decode(packet)?;
            exact_fields(&establishment, &["eReaderKey", "data"])?;
            let reader_bytes = get(&establishment, "eReaderKey")?;
            let reader = embedded(reader_bytes)?;
            let public = public_from_cose(&reader)?;
            let C::Tag(24, original) = reader_bytes else {
                return Err("invalid_reader_key");
            };
            let reader_key = original.as_bytes().ok_or("invalid_reader_key")?;
            let transcript = match &self.handover_select {
                Some(hs) => nfc_transcript(
                    &self.engagement,
                    reader_key,
                    hs,
                    self.handover_request.as_deref(),
                )?,
                None => qr_transcript(&self.engagement, reader_key)?,
            };
            let shared = diffie_hellman(key.to_nonzero_scalar(), public.as_affine());
            let mut cipher =
                SessionCipher::derive(shared.raw_secret_bytes().as_ref(), &transcript)?;
            let plain = Zeroizing::new(
                cipher.decrypt_reader(
                    get(&establishment, "data")?
                        .as_bytes()
                        .ok_or("invalid_session_data")?,
                )?,
            );
            let request = parse_device_request(&plain, &transcript, readers, now)?;
            self.transcript = Some(transcript);
            self.cipher = Some(cipher);
            self.requested = Some(request);
            Ok(())
        })();
        if let Err(error) = result {
            self.close();
            return Err(error);
        }
        self.requested.as_ref().ok_or("invalid_device_request")
    }
    /// One approved DeviceResponse. Callers must bind consent to this immutable request.
    pub fn seal_response(&mut self, response: &[u8]) -> Result<Vec<u8>, &'static str> {
        if self.closed || self.requested.is_none() {
            return Err("review_required");
        }
        let result = self
            .cipher
            .as_mut()
            .ok_or("session_not_established")?
            .encrypt_device(response)
            .and_then(|data| encode(&map(vec![("data", bytes(data))])));
        self.close();
        result
    }
    pub fn seal_response_at(&mut self, response: &[u8], now: u64) -> Result<Vec<u8>, &'static str> {
        if self.request()?.expires_at <= now {
            self.close();
            return Err("reader_authentication_expired");
        }
        self.seal_response(response)
    }
    pub fn request(&self) -> Result<&DeviceRequest, &'static str> {
        self.requested.as_ref().ok_or("review_required")
    }
    pub fn close(&mut self) {
        self.closed = true;
        self.ephemeral = None;
        self.cipher = None;
        self.requested = None;
        self.transcript = None;
        self.handover_request = None;
    }
}

pub struct SessionCipher {
    reader: Zeroizing<[u8; 32]>,
    device: Zeroizing<[u8; 32]>,
    read_counter: u32,
    send_counter: u32,
    failed: bool,
}
/// NFC Forum Handover Select 1.5 with one active BLE peripheral retrieval carrier.
/// Bluetooth OOB LE role is expressed from the receiving reader's perspective.
fn static_handover_select(engagement: &[u8], uuid: [u8; 16]) -> Result<Vec<u8>, &'static str> {
    let mut oob = vec![2, 0x1c, 0, 17, 7];
    oob.extend(uuid.iter().rev());
    handover_select(
        engagement,
        0x42,
        b"application/vnd.bluetooth.le.oob",
        b"0",
        &oob,
    )
}
fn nfc_data_handover_select(engagement: &[u8]) -> Result<Vec<u8>, &'static str> {
    handover_select(
        engagement,
        0x44,
        b"iso.org:18013:nfc",
        b"nfc",
        &[1, 2, 1, 255, 3, 2, 1, 0],
    )
}
fn handover_select(
    engagement: &[u8],
    carrier_flags: u8,
    carrier_kind: &[u8],
    carrier_id: &[u8],
    carrier: &[u8],
) -> Result<Vec<u8>, &'static str> {
    fn record(flags: u8, kind: &[u8], id: &[u8], payload: &[u8]) -> Result<Vec<u8>, &'static str> {
        let length = u8::try_from(payload.len()).map_err(|_| "invalid_handover")?;
        let mut out = vec![
            flags | 0x10 | if id.is_empty() { 0 } else { 8 },
            kind.len() as u8,
            length,
        ];
        if !id.is_empty() {
            out.push(id.len() as u8);
        }
        out.extend(kind);
        out.extend(id);
        out.extend(payload);
        Ok(out)
    }
    let mut ac_payload = vec![1, carrier_id.len() as u8];
    ac_payload.extend(carrier_id);
    ac_payload.extend([1, 4, b'm', b'd', b'o', b'c']);
    let ac = record(0xc1, b"ac", b"", &ac_payload)?;
    let mut hs_payload = vec![0x15];
    hs_payload.extend(ac);
    let mut message = record(0x81, b"Hs", b"", &hs_payload)?;
    message.extend(record(
        4,
        b"iso.org:18013:deviceengagement",
        b"mdoc",
        engagement,
    )?);
    message.extend(record(carrier_flags, carrier_kind, carrier_id, carrier)?);
    Ok(message)
}
impl SessionCipher {
    pub fn derive(shared: &[u8], transcript: &[u8]) -> Result<Self, &'static str> {
        if shared.len() != 32 {
            return Err("invalid_session_key");
        }
        let parsed = decode(transcript)?;
        if parsed.as_array().is_none_or(|a| a.len() != 3) {
            return Err("invalid_transcript");
        }
        let transcript_bytes = encode(&C::Tag(24, Box::new(bytes(transcript.to_vec()))))?;
        let salt = Sha256::digest(transcript_bytes);
        let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
        let mut reader = Zeroizing::new([0; 32]);
        let mut device = Zeroizing::new([0; 32]);
        hk.expand(b"SKReader", &mut *reader)
            .map_err(|_| "invalid_session_key")?;
        hk.expand(b"SKDevice", &mut *device)
            .map_err(|_| "invalid_session_key")?;
        Ok(Self {
            reader,
            device,
            read_counter: 1,
            send_counter: 1,
            failed: false,
        })
    }
    fn iv(direction: u32, counter: u32) -> [u8; 12] {
        let mut iv = [0; 12];
        iv[4..8].copy_from_slice(&direction.to_be_bytes());
        iv[8..].copy_from_slice(&counter.to_be_bytes());
        iv
    }
    pub fn decrypt_reader(&mut self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if self.failed || self.read_counter == u32::MAX || !(16..=32000).contains(&data.len()) {
            self.failed = true;
            return Err("session_closed");
        }
        let cipher = Aes256Gcm::new_from_slice(&*self.reader).map_err(|_| "invalid_session_key")?;
        match cipher.decrypt(&Nonce::from(Self::iv(0, self.read_counter)), data) {
            Ok(plain) => {
                self.read_counter += 1;
                Ok(plain)
            }
            Err(_) => {
                self.failed = true;
                Err("session_authentication_failed")
            }
        }
    }
    pub fn encrypt_device(&mut self, plain: &[u8]) -> Result<Vec<u8>, &'static str> {
        if self.failed || self.send_counter == u32::MAX || plain.len() > 31000 {
            self.failed = true;
            return Err("session_closed");
        }
        let cipher = Aes256Gcm::new_from_slice(&*self.device).map_err(|_| "invalid_session_key")?;
        let result = cipher
            .encrypt(&Nonce::from(Self::iv(1, self.send_counter)), plain)
            .map_err(|_| "session_encryption_failed");
        self.send_counter += 1;
        if result.is_err() {
            self.failed = true
        }
        result
    }
}
fn exact_fields(v: &C, allowed: &[&str]) -> Result<(), &'static str> {
    let m = v.as_map().ok_or("invalid_device_request")?;
    if m.len() != allowed.len()
        || m.iter()
            .any(|(k, _)| k.as_text().is_none_or(|s| !allowed.contains(&s)))
    {
        return Err("invalid_device_request");
    }
    Ok(())
}
fn public_from_cose(v: &C) -> Result<PublicKey, &'static str> {
    let fields = v
        .as_map()
        .filter(|m| m.len() == 4)
        .ok_or("invalid_reader_key")?;
    let lookup = |n| {
        fields
            .iter()
            .find(|(k, _)| *k == integer(n))
            .map(|(_, v)| v)
            .ok_or("invalid_reader_key")
    };
    if lookup(1)? != &integer(2) || lookup(-1)? != &integer(1) {
        return Err("invalid_reader_key");
    }
    let x = lookup(-2)?
        .as_bytes()
        .filter(|b| b.len() == 32)
        .ok_or("invalid_reader_key")?;
    let y = lookup(-3)?
        .as_bytes()
        .filter(|b| b.len() == 32)
        .ok_or("invalid_reader_key")?;
    let mut point = vec![4];
    point.extend(x);
    point.extend(y);
    PublicKey::from_sec1_bytes(&point).map_err(|_| "invalid_reader_key")
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ReaderRegistration {
    pub name: String,
    pub jwk: PublicJwk,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_trust: Option<crate::certificate::ReaderTrust>,
}
#[derive(Clone)]
pub struct DeviceRequest {
    pub expires_at: u64,
    pub fields: Vec<String>,
    pub retained_fields: Vec<String>,
    pub reader_name: String,
}
/// This first profile requires an authenticated, explicitly registered reader, never anonymous trust.
pub fn parse_device_request(
    packet: &[u8],
    transcript: &[u8],
    readers: &[ReaderRegistration],
    now: u64,
) -> Result<DeviceRequest, &'static str> {
    if readers.len() > 32 {
        return Err("reader_configuration_invalid");
    }
    let request = decode(packet)?;
    exact_fields(&request, &["version", "docRequests"])?;
    if get(&request, "version")? != &text("1.0") {
        return Err("invalid_device_request");
    }
    let documents = get(&request, "docRequests")?
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("unsupported_device_request")?;
    let doc = &documents[0];
    exact_fields(doc, &["itemsRequest", "readerAuth"])?;
    let items_bytes = get(doc, "itemsRequest")?;
    let items = embedded(items_bytes)?;
    exact_fields(&items, &["docType", "nameSpaces"])?;
    if get(&items, "docType")? != &text(DOCTYPE) {
        return Err("unsupported_device_request");
    }
    let spaces = get(&items, "nameSpaces")?
        .as_map()
        .filter(|m| m.len() == 1)
        .ok_or("unsupported_device_request")?;
    if spaces[0].0 != text(NAMESPACE) {
        return Err("unsupported_device_request");
    }
    let claims = spaces[0]
        .1
        .as_map()
        .filter(|m| !m.is_empty() && m.len() <= 5)
        .ok_or("unsupported_device_request")?;
    let mut fields = Vec::new();
    let mut retained_fields = Vec::new();
    for (name, retain) in claims {
        let name = name.as_text().ok_or("unsupported_device_request")?;
        if !matches!(
            name,
            "name" | "address" | "birthdate" | "gender" | "document_expiry_date"
        ) {
            return Err("unsupported_device_request");
        }
        let C::Bool(retain) = retain else {
            return Err("unsupported_device_request");
        };
        fields.push(name.into());
        if *retain {
            retained_fields.push(name.into())
        }
    }
    let auth = get(doc, "readerAuth")?
        .as_array()
        .filter(|a| a.len() == 4)
        .ok_or("reader_authentication_required")?;
    if auth[0] != bytes(protected()?) || auth[2] != C::Null {
        return Err("invalid_reader_authentication");
    }
    let headers = auth[1]
        .as_map()
        .filter(|m| m.len() == 1 && m[0].0 == integer(33))
        .ok_or("invalid_reader_certificate")?;
    let chain = match &headers[0].1 {
        C::Bytes(bytes) if bytes.len() <= 4096 => vec![bytes.clone()],
        C::Array(certs) if !certs.is_empty() && certs.len() <= 4 => certs
            .iter()
            .map(|c| {
                c.as_bytes()
                    .filter(|b| b.len() <= 4096)
                    .cloned()
                    .ok_or("invalid_reader_certificate")
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err("invalid_reader_certificate"),
    };
    let cert_bytes = &chain[0];
    let cert =
        x509_cert::Certificate::from_der(cert_bytes).map_err(|_| "invalid_reader_certificate")?;
    let t = cert.tbs_certificate();
    if now < t.validity().not_before.to_unix_duration().as_secs()
        || now >= t.validity().not_after.to_unix_duration().as_secs()
    {
        return Err("invalid_reader_certificate");
    }
    use der::asn1::ObjectIdentifier;
    use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
    let mut ids = HashSet::new();
    let extensions = t.extensions().ok_or("invalid_reader_certificate")?;
    if extensions.iter().any(|e| {
        !ids.insert(e.extn_id)
            || (e.critical
                && !matches!(
                    e.extn_id.to_string().as_str(),
                    "2.5.29.15" | "2.5.29.19" | "2.5.29.37"
                ))
    }) {
        return Err("invalid_reader_certificate");
    }
    let extension = |oid| {
        extensions
            .iter()
            .find(|e| e.extn_id == ObjectIdentifier::new_unwrap(oid))
            .ok_or("invalid_reader_certificate")
    };
    let ku_ext = extension("2.5.29.15")?;
    let eku_ext = extension("2.5.29.37")?;
    let ku = KeyUsage::from_der(ku_ext.extn_value.as_bytes())
        .map_err(|_| "invalid_reader_certificate")?;
    let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
        .map_err(|_| "invalid_reader_certificate")?;
    let bc = BasicConstraints::from_der(extension("2.5.29.19")?.extn_value.as_bytes())
        .map_err(|_| "invalid_reader_certificate")?;
    if !ku_ext.critical
        || !eku_ext.critical
        || !ku.digital_signature()
        || ku.key_cert_sign()
        || bc.ca
        || !eku
            .0
            .contains(&ObjectIdentifier::new_unwrap("1.0.18013.5.1.6"))
    {
        return Err("invalid_reader_certificate");
    }
    let public = p256::ecdsa::VerifyingKey::from_public_key_der(
        &t.subject_public_key_info()
            .to_der()
            .map_err(|_| "invalid_reader_certificate")?,
    )
    .map_err(|_| "invalid_reader_certificate")?;
    let key = PublicJwk::from_key(&public);
    let matches = readers.iter().filter(|r| r.jwk == key).collect::<Vec<_>>();
    let [registered] = matches.as_slice() else {
        return Err("untrusted_reader");
    };
    let expires_at = if let Some(policy) = &registered.certificate_trust {
        crate::certificate::verify_reader_chain(&chain, policy, &registered.jwk, now)?
    } else {
        if !matches!(&headers[0].1, C::Bytes(_)) {
            return Err("certificate_required");
        }
        t.validity().not_after.to_unix_duration().as_secs()
    };
    if registered.name.is_empty() || registered.name.len() > 160 {
        return Err("reader_configuration_invalid");
    }
    let payload = encode(&tag(array(vec![
        text("ReaderAuthentication"),
        decode(transcript)?,
        items_bytes.clone(),
    ]))?)?;
    public
        .verify(
            &signature_input(&payload)?,
            &Signature::from_slice(auth[3].as_bytes().ok_or("invalid_reader_authentication")?)
                .map_err(|_| "invalid_reader_authentication")?,
        )
        .map_err(|_| "invalid_reader_authentication")?;
    Ok(DeviceRequest {
        expires_at,
        fields,
        retained_fields,
        reader_name: registered.name.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negotiation_failure_and_repetition_erase_ephemeral_key() {
        let key = || SecretKey::from_slice(&[7; 32]).unwrap();
        let mut session = HolderSession::new_nfc_negotiated(key(), [8; 16]).unwrap();
        assert!(session.negotiate(&[0]).is_err());
        assert!(session.ephemeral.is_none());
        assert_eq!(
            session.establish(&[0xa0], &[], 0).err(),
            Some("session_consumed")
        );
        let mut qr = HolderSession::new(key(), [8; 16]).unwrap();
        assert_eq!(qr.negotiate(&[0]).err(), Some("invalid_handover_state"));
        assert!(qr.ephemeral.is_none());
        let mut session = HolderSession::new_nfc_negotiated(key(), [8; 16]).unwrap();
        // Hr 1.5: one active AC referencing the BLE OOB reader offer, mdoc peripheral.
        let mut hr = vec![
            0x91, 2, 10, b'H', b'r', 0x15, 0xd1, 2, 4, b'a', b'c', 1, 1, b'0', 0,
        ];
        let kind = b"application/vnd.bluetooth.le.oob";
        hr.extend([0x5a, kind.len() as u8, 3, 1]);
        hr.extend(kind);
        hr.extend([b'0', 2, 0x1c, 0]);
        assert!(session.negotiate(&hr).is_ok());
        assert!(session.negotiate(&hr).is_err());
        assert!(session.ephemeral.is_none());
        assert!(session.handover_request.is_none());
    }
    #[test]
    fn failed_session_authentication_and_counter_wrap_are_terminal() {
        let transcript = encode(&array(vec![C::Null, C::Null, C::Null])).unwrap();
        let mut cipher = SessionCipher::derive(&[8; 32], &transcript).unwrap();
        let reader = Aes256Gcm::new_from_slice(&*cipher.reader).unwrap();
        let packet = reader
            .encrypt(&Nonce::from(SessionCipher::iv(0, 1)), b"request".as_slice())
            .unwrap();
        assert_eq!(cipher.decrypt_reader(&packet).unwrap(), b"request");
        assert_eq!(
            cipher.decrypt_reader(&packet).unwrap_err(),
            "session_authentication_failed"
        );
        assert!(cipher.encrypt_device(b"response").is_err());
        let mut cipher = SessionCipher::derive(&[8; 32], &transcript).unwrap();
        cipher.send_counter = u32::MAX;
        assert!(cipher.encrypt_device(b"response").is_err());
        assert!(cipher.decrypt_reader(&packet).is_err());
    }
    #[test]
    fn device_and_reader_keys_and_iv_directions_are_separate() {
        let transcript = encode(&array(vec![C::Null, C::Null, C::Null])).unwrap();
        let mut cipher = SessionCipher::derive(&[8; 32], &transcript).unwrap();
        assert_ne!(*cipher.reader, *cipher.device);
        let packet = cipher.encrypt_device(b"response").unwrap();
        let reader = Aes256Gcm::new_from_slice(&*cipher.reader).unwrap();
        assert!(
            reader
                .decrypt(&Nonce::from(SessionCipher::iv(0, 1)), packet.as_slice())
                .is_err()
        );
        let device = Aes256Gcm::new_from_slice(&*cipher.device).unwrap();
        assert_eq!(
            device
                .decrypt(&Nonce::from(SessionCipher::iv(1, 1)), packet.as_slice())
                .unwrap(),
            b"response"
        );
        assert!(
            device
                .decrypt(&Nonce::from(SessionCipher::iv(1, 2)), packet.as_slice())
                .is_err()
        );
    }
    #[test]
    fn malformed_establishment_consumes_ephemeral_key_without_a_response() {
        let mut session =
            HolderSession::new(SecretKey::from_slice(&[7; 32]).unwrap(), [8; 16]).unwrap();
        assert!(session.seal_response(b"unapproved").is_err());
        assert!(session.establish(&[0xa0], &[], 1800000000).is_err());
        assert!(session.ephemeral.is_none());
        assert!(session.cipher.is_none());
        assert_eq!(
            session.establish(&[0xa0], &[], 1800000000).err(),
            Some("session_consumed")
        );
        assert!(session.seal_response(b"unapproved").is_err());
    }
    #[test]
    fn reader_authentication_requires_registered_chain_and_signature() {
        use crate::certificate::ReaderTrust;
        use base64::engine::general_purpose::STANDARD;
        let leaf = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/trust/reader.der"
        ));
        let intermediate = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/trust/intermediate.der"
        ));
        let root = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/trust/root.der"
        ));
        let key = SigningKey::from_slice(&[4; 32]).unwrap();
        let transcript = encode(&array(vec![C::Null, C::Null, C::Null])).unwrap();
        let items = tag(map(vec![
            ("docType", text(DOCTYPE)),
            (
                "nameSpaces",
                map(vec![(NAMESPACE, map(vec![("name", C::Bool(false))]))]),
            ),
        ]))
        .unwrap();
        let payload = encode(
            &tag(array(vec![
                text("ReaderAuthentication"),
                decode(&transcript).unwrap(),
                items.clone(),
            ]))
            .unwrap(),
        )
        .unwrap();
        let signature: Signature = key.sign(&signature_input(&payload).unwrap());
        let packet = |chain: C, signature: C| {
            encode(&map(vec![
                ("version", text("1.0")),
                (
                    "docRequests",
                    array(vec![map(vec![
                        ("itemsRequest", items.clone()),
                        (
                            "readerAuth",
                            array(vec![
                                bytes(protected().unwrap()),
                                C::Map(vec![(integer(33), chain)]),
                                C::Null,
                                signature,
                            ]),
                        ),
                    ])]),
                ),
            ]))
            .unwrap()
        };
        let chain = array(vec![bytes(leaf.to_vec()), bytes(intermediate.to_vec())]);
        let mut reader = ReaderRegistration {
            name: "Registered reader".into(),
            jwk: PublicJwk::from_key(key.verifying_key()),
            certificate_trust: Some(ReaderTrust {
                trust_anchors: vec![STANDARD.encode(root)],
                dns_name: None,
                revocation: None,
            }),
        };
        let now = 1790899200;
        let valid = packet(chain.clone(), bytes(signature.to_bytes().to_vec()));
        let request = parse_device_request(&valid, &transcript, &[reader.clone()], now).unwrap();
        assert_eq!(request.fields, ["name"]);
        assert_eq!(request.reader_name, "Registered reader");
        assert!(
            parse_device_request(
                &packet(chain, bytes(vec![0; 64])),
                &transcript,
                &[reader.clone()],
                now
            )
            .is_err()
        );
        assert!(
            parse_device_request(
                &packet(bytes(leaf.to_vec()), bytes(signature.to_bytes().to_vec())),
                &transcript,
                &[reader.clone()],
                now
            )
            .is_err()
        );
        let crl = |name: &str| {
            STANDARD.encode(
                std::fs::read(format!(
                    "{}/tests/fixtures/trust/{name}.crl",
                    env!("CARGO_MANIFEST_DIR")
                ))
                .unwrap(),
            )
        };
        reader.certificate_trust.as_mut().unwrap().revocation =
            Some(crate::certificate::CrlPolicy {
                crls: vec![crl("clean-intermediate"), crl("clean-root")],
                max_age_seconds: 172801,
            });
        let request = parse_device_request(&valid, &transcript, &[reader.clone()], now).unwrap();
        assert_eq!(request.expires_at, now + 1);
        let mut session =
            HolderSession::new(SecretKey::from_slice(&[7; 32]).unwrap(), [8; 16]).unwrap();
        session.requested = Some(request);
        assert_eq!(
            session.seal_response_at(b"expired", now + 1),
            Err("reader_authentication_expired")
        );
        assert!(session.closed);
        assert!(session.ephemeral.is_none());
        reader.certificate_trust = None;
        assert!(parse_device_request(&valid, &transcript, &[reader], now).is_err());
    }
}
