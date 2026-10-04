//! Bounded, transport-neutral input-support and IC driving-licence reads.
//! Local previews remain unverified. No personal-number EF is selected.
use civ_card::{
    apdu::{ApduCommand, file_ids},
    jpki_utils::parse_basic_info,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_EF: usize = 4096;
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DocumentType {
    #[default]
    MyNumberCard,
    DrivingLicense,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    UnsupportedPlatform,
    InvalidPin,
    ReaderBusy,
    NfcUnavailable,
    NfcDisabled,
    Cancelled,
    ReadTimeout,
    CardRemoved,
    UnsupportedCard,
    PinFailed,
    PinBlocked,
    AccessDenied,
    InvalidResponse,
    InvalidData,
    TransportError,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CardFailure {
    pub code: FailureCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_retries: Option<u8>,
}
impl From<FailureCode> for CardFailure {
    fn from(code: FailureCode) -> Self {
        Self {
            code,
            remaining_retries: None,
        }
    }
}

pub trait CardTransport {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CardFailure>;
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CardPreview {
    pub name: String,
    pub address: String,
    pub birth_date: String,
    pub gender: String,
    pub verification: String,
    #[serde(default)]
    pub document_type: DocumentType,
    #[serde(default)]
    pub expiry_date: Option<String>,
    #[serde(default)]
    pub backend_verifiable: bool,
}
impl Drop for CardPreview {
    fn drop(&mut self) {
        self.name.zeroize();
        self.address.zeroize();
        self.birth_date.zeroize();
        self.gender.zeroize();
        if let Some(date) = &mut self.expiry_date {
            date.zeroize();
        }
    }
}

pub fn validate_pin(pin: &str) -> Result<(), CardFailure> {
    if pin.len() == 4 && pin.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(FailureCode::InvalidPin.into())
    }
}

fn status(sw: u16) -> CardFailure {
    if sw & 0xfff0 == 0x63c0 {
        CardFailure {
            code: FailureCode::PinFailed,
            remaining_retries: Some((sw & 15) as u8),
        }
    } else {
        match sw {
            0x6983 => FailureCode::PinBlocked,
            0x6982 => FailureCode::AccessDenied,
            0x6a82 => FailureCode::UnsupportedCard,
            _ => FailureCode::InvalidResponse,
        }
        .into()
    }
}

fn exchange(t: &mut impl CardTransport, cmd: Vec<u8>) -> Result<(Vec<u8>, u16), CardFailure> {
    let mut cmd = Zeroizing::new(cmd);
    let mut data = Vec::new();
    let can_correct_length = cmd.get(1) == Some(&0xb0);
    for _ in 0..16 {
        let response = Zeroizing::new(t.transmit(&cmd)?);
        if response.len() < 2 || response.len() > MAX_EF + 2 {
            cmd.zeroize();
            return Err(FailureCode::InvalidResponse.into());
        }
        let n = response.len() - 2;
        let sw = u16::from_be_bytes([response[n], response[n + 1]]);
        if sw >> 8 == 0x6c && can_correct_length && data.is_empty() {
            *cmd.last_mut().ok_or(FailureCode::InvalidResponse)? = sw as u8;
            continue;
        }
        if data.len() + n > MAX_EF {
            cmd.zeroize();
            return Err(FailureCode::InvalidResponse.into());
        }
        data.extend_from_slice(&response[..n]);
        if sw >> 8 == 0x61 {
            cmd.zeroize();
            *cmd = vec![0, 0xc0, 0, 0, sw as u8];
            continue;
        }
        cmd.zeroize();
        return Ok((data, sw));
    }
    cmd.zeroize();
    Err(FailureCode::InvalidResponse.into())
}

fn checked(t: &mut impl CardTransport, cmd: Vec<u8>) -> Result<Vec<u8>, CardFailure> {
    let (mut data, sw) = exchange(t, cmd)?;
    if sw != 0x9000 {
        data.zeroize();
        return Err(status(sw));
    }
    Ok(data)
}

fn select_ef(t: &mut impl CardTransport, ef: &[u8]) -> Result<(), CardFailure> {
    checked(
        t,
        ApduCommand::new(0, 0xa4, 0x02, 0x0c)
            .with_data(ef)
            .to_bytes(),
    )
    .map(|_| ())
}

pub fn read_ef(t: &mut impl CardTransport, ef: &[u8]) -> Result<Zeroizing<Vec<u8>>, CardFailure> {
    select_ef(t, ef)?;
    let mut data = Zeroizing::new(Vec::new());
    loop {
        if data.len() >= MAX_EF {
            return Err(FailureCode::InvalidData.into());
        }
        let offset = data.len() as u16;
        let (chunk, sw) = exchange(
            t,
            ApduCommand::read_binary((offset >> 8) as u8, offset as u8, 0).to_bytes(),
        )?;
        let chunk = Zeroizing::new(chunk);
        if sw == 0x6b00 && !data.is_empty() && chunk.is_empty() {
            break;
        }
        if sw != 0x9000 && sw != 0x6282 {
            return Err(status(sw));
        }
        if data.len() + chunk.len() > MAX_EF {
            return Err(FailureCode::InvalidData.into());
        }
        data.extend_from_slice(&chunk);
        if sw == 0x6282 || chunk.len() < 256 {
            break;
        }
    }
    Ok(data)
}

/// A single PIN verification attempt. Never retries a failed VERIFY command.
pub fn read_mnc(t: &mut impl CardTransport, pin: &str) -> Result<CardPreview, CardFailure> {
    validate_pin(pin)?;
    checked(
        t,
        ApduCommand::select(&file_ids::DF_INPUT_SUPPORT).to_bytes(),
    )?;
    select_ef(t, &file_ids::EF_INPUT_SUPPORT_PIN)?;
    let mut verify = Zeroizing::new(vec![0, 0x20, 0, 0x80, 4]);
    verify.extend_from_slice(pin.as_bytes());
    checked(t, std::mem::take(&mut *verify))?;
    let raw = read_ef(t, &file_ids::EF_ATTRIBUTES)?;
    parse_preview(&raw)
}

pub fn parse_preview(raw: &[u8]) -> Result<CardPreview, CardFailure> {
    // civ's parser is intentionally lenient; reject truncation, duplicate claims,
    // non-ASCII date/gender and deep nesting before invoking it.
    let mut claims = std::collections::HashMap::new();
    validate_tlv(raw, 0, &mut claims)?;
    for tag in [0xdf22, 0xdf23, 0xdf24, 0xdf25] {
        if !claims.contains_key(&tag) {
            return Err(FailureCode::InvalidData.into());
        }
    }
    let date = claims[&0xdf24];
    if !matches!(date.len(), 7 | 8) || !date.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FailureCode::InvalidData.into());
    }
    if !matches!(claims[&0xdf25], "1" | "2" | "9") {
        return Err(FailureCode::InvalidData.into());
    }
    let info = parse_basic_info(raw).map_err(|_| CardFailure::from(FailureCode::InvalidData))?;
    if info.name.trim().is_empty()
        || info.address.trim().is_empty()
        || !valid_date(&info.birth_date)
    {
        return Err(FailureCode::InvalidData.into());
    }
    Ok(CardPreview {
        name: info.name,
        address: info.address,
        birth_date: info.birth_date,
        gender: info.gender,
        verification: "unverified".into(),
        document_type: DocumentType::MyNumberCard,
        expiry_date: None,
        backend_verifiable: true,
    })
}

pub fn valid_date(date: &str) -> bool {
    if date.len() != 10 || !date.is_ascii() {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (
        date[..4].parse::<u32>(),
        date[5..7].parse::<usize>(),
        date[8..].parse::<u32>(),
    ) else {
        return false;
    };
    if &date[4..5] != "-" || &date[7..8] != "-" || year == 0 || !(1..=12).contains(&month) {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    day >= 1 && day <= days[month - 1]
}

fn validate_tlv<'a>(
    mut bytes: &'a [u8],
    depth: usize,
    claims: &mut std::collections::HashMap<u32, &'a str>,
) -> Result<(), CardFailure> {
    if bytes.len() > MAX_EF || depth > 8 {
        return Err(FailureCode::InvalidData.into());
    }
    while !bytes.is_empty() {
        if bytes[0] == 0 || (bytes[0] == 0xff && (bytes.len() == 1 || bytes[1] == 0xff)) {
            bytes = &bytes[1..];
            continue;
        }
        let first = bytes[0];
        let mut tag = u32::from(first);
        let mut i = 1;
        if first & 31 == 31 {
            loop {
                if i >= bytes.len() || i >= 4 {
                    return Err(FailureCode::InvalidData.into());
                }
                let b = bytes[i];
                tag = (tag << 8) | u32::from(b);
                i += 1;
                if b & 128 == 0 {
                    break;
                }
            }
        }
        let Some(&len) = bytes.get(i) else {
            return Err(FailureCode::InvalidData.into());
        };
        i += 1;
        let length = if len <= 127 {
            usize::from(len)
        } else {
            let count = usize::from(len & 127);
            if count == 0 || count > 2 || i + count > bytes.len() {
                return Err(FailureCode::InvalidData.into());
            }
            let mut n = 0;
            for b in &bytes[i..i + count] {
                n = (n << 8) | usize::from(*b);
            }
            i += count;
            n
        };
        let value = bytes.get(i..i + length).ok_or(FailureCode::InvalidData)?;
        if matches!(tag, 0x30 | 0xdf20 | 0xff20) {
            validate_tlv(value, depth + 1, claims)?;
        }
        if matches!(tag, 0xdf22..=0xdf25) {
            let text = std::str::from_utf8(value)
                .map_err(|_| CardFailure::from(FailureCode::InvalidData))?;
            if text.chars().any(|c| c.is_control()) || claims.insert(tag, text).is_some() {
                return Err(FailureCode::InvalidData.into());
            }
        }
        bytes = &bytes[i + length..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    type Step = (Vec<u8>, Result<Vec<u8>, CardFailure>);
    struct Script {
        steps: VecDeque<Step>,
    }
    impl CardTransport for Script {
        fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, CardFailure> {
            let (expected, response) = self
                .steps
                .pop_front()
                .expect("unexpected APDU (or automatic retry)");
            assert_eq!(command, expected);
            response
        }
    }
    fn attributes() -> Vec<u8> {
        let mut bytes = Vec::new();
        for (tag, value) in [
            (0x22, "試験 太郎"),
            (0x23, "東京都"),
            (0x24, "19900228"),
            (0x25, "1"),
        ] {
            bytes.extend([0xdf, tag, value.len() as u8]);
            bytes.extend(value.as_bytes());
        }
        bytes
    }
    fn steps_after_pin(response: Vec<u8>) -> Script {
        Script {
            steps: VecDeque::from([
                (
                    ApduCommand::select(&file_ids::DF_INPUT_SUPPORT).to_bytes(),
                    Ok(vec![0x90, 0]),
                ),
                (vec![0, 0xa4, 2, 0x0c, 2, 0, 0x11], Ok(vec![0x90, 0])),
                (
                    vec![0, 0x20, 0, 0x80, 4, b'1', b'2', b'3', b'4'],
                    Ok(response),
                ),
            ]),
        }
    }

    #[test]
    fn reads_only_four_attributes_and_labels_result_unverified() {
        let mut script = steps_after_pin(vec![0x90, 0]);
        let mut response = attributes();
        response.extend([0x62, 0x82]);
        script.steps.extend([
            (vec![0, 0xa4, 2, 0x0c, 2, 0, 2], Ok(vec![0x90, 0])),
            (vec![0, 0xb0, 0, 0, 0], Ok(response)),
        ]);
        let result = read_mnc(&mut script, "1234").unwrap();
        assert_eq!(result.name, "試験 太郎");
        assert_eq!(result.birth_date, "1990-02-28");
        assert_eq!(result.verification, "unverified");
        assert!(script.steps.is_empty());
    }

    #[test]
    fn failed_pin_is_not_retried_and_returns_remaining_attempts() {
        let mut script = steps_after_pin(vec![0x63, 0xc2]);
        assert_eq!(
            read_mnc(&mut script, "1234").unwrap_err(),
            CardFailure {
                code: FailureCode::PinFailed,
                remaining_retries: Some(2),
            }
        );
        assert!(script.steps.is_empty());
        let mut blocked = steps_after_pin(vec![0x69, 0x83]);
        assert_eq!(
            read_mnc(&mut blocked, "1234").unwrap_err().code,
            FailureCode::PinBlocked
        );
    }

    #[test]
    fn invalid_pin_never_touches_card() {
        for pin in ["", "123", "12345", "１２３４", "12a4"] {
            let mut script = Script {
                steps: VecDeque::new(),
            };
            assert_eq!(
                read_mnc(&mut script, pin).unwrap_err().code,
                FailureCode::InvalidPin
            );
        }
    }

    #[test]
    fn malformed_or_ambiguous_claims_are_rejected_before_lenient_parser() {
        let good = attributes();
        for n in 0..good.len() {
            assert!(parse_preview(&good[..n]).is_err());
        }
        let mut duplicate = good.clone();
        duplicate.extend([0xdf, 0x22, 1, b'X']);
        assert!(parse_preview(&duplicate).is_err());
        for value in ["19900230", "1234567", "ああa"] {
            let mut data = Vec::new();
            for (tag, text) in [(0x22, "試験"), (0x23, "東京都"), (0x24, value), (0x25, "1")] {
                data.extend([0xdf, tag, text.len() as u8]);
                data.extend(text.as_bytes());
            }
            assert!(parse_preview(&data).is_err());
        }
        let mut nested = good;
        for _ in 0..10 {
            let mut next = vec![0x30, 0x82, (nested.len() >> 8) as u8, nested.len() as u8];
            next.extend(nested);
            nested = next;
        }
        assert!(parse_preview(&nested).is_err());
        assert!(parse_preview(&[0xdf, 0x22, 0x80]).is_err());
    }

    #[test]
    fn read_binary_handles_length_correction_and_get_response() {
        let mut script = Script {
            steps: VecDeque::from([
                (vec![0, 0xb0, 0, 0, 0], Ok(vec![0x6c, 2])),
                (vec![0, 0xb0, 0, 0, 2], Ok(vec![1, 0x61, 1])),
                (vec![0, 0xc0, 0, 0, 1], Ok(vec![2, 0x90, 0])),
            ]),
        };
        assert_eq!(
            exchange(&mut script, vec![0, 0xb0, 0, 0, 0]).unwrap(),
            (vec![1, 2], 0x9000)
        );
        assert!(script.steps.is_empty());
    }

    #[test]
    fn cancellation_and_truncated_native_response_stop_protocol() {
        let command = ApduCommand::select(&file_ids::DF_INPUT_SUPPORT).to_bytes();
        for response in [Err(FailureCode::Cancelled.into()), Ok(vec![0x90])] {
            let mut script = Script {
                steps: VecDeque::from([(command.clone(), response)]),
            };
            assert!(read_mnc(&mut script, "1234").is_err());
            assert!(script.steps.is_empty());
        }
    }

    #[test]
    fn endless_card_response_is_bounded() {
        let mut script = Script {
            steps: (0..16)
                .map(|_| (vec![0, 0xb0, 0, 0, 0], Ok(vec![0x6c, 0])))
                .collect(),
        };
        assert_eq!(
            exchange(&mut script, vec![0, 0xb0, 0, 0, 0])
                .unwrap_err()
                .code,
            FailureCode::InvalidResponse
        );
        assert!(script.steps.is_empty());
    }
}

const DL_AID: [u8; 16] = [0xa0, 0, 0, 2, 0x31, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn verify_pin(t: &mut impl CardTransport, pin: &str) -> Result<(), CardFailure> {
    let mut command = Zeroizing::new(vec![0, 0x20, 0, 0x80, 4]);
    command.extend_from_slice(pin.as_bytes());
    checked(t, std::mem::take(&mut *command)).map(|_| ())
}

/// Reads only signed base attributes. Change records are not represented as verified.
pub fn read_document(
    t: &mut impl CardTransport,
    kind: DocumentType,
    pin: &str,
    pin2: Option<&str>,
) -> Result<(CardPreview, crate::evidence::Evidence), CardFailure> {
    validate_pin(pin)?;
    if let Some(pin) = pin2 {
        validate_pin(pin)?;
    }
    let mut evidence = crate::evidence::Evidence::new(kind);
    match kind {
        DocumentType::MyNumberCard => {
            checked(
                t,
                ApduCommand::select(&file_ids::DF_INPUT_SUPPORT).to_bytes(),
            )?;
            select_ef(t, &file_ids::EF_INPUT_SUPPORT_PIN)?;
            verify_pin(t, pin)?;
            evidence.attributes = read_ef(t, &[0, 2])?.to_vec();
            evidence.signature = read_ef(t, &[0, 3])?.to_vec();
            let preview = parse_preview(&evidence.attributes)?;
            Ok((preview, evidence))
        }
        DocumentType::DrivingLicense => {
            for (id, value) in [(1, Some(pin)), (2, pin2)] {
                if let Some(value) = value {
                    checked(t, vec![0, 0xa4, 0, 0])?;
                    select_ef(t, &[0, id])?;
                    verify_pin(t, value)?;
                }
            }
            checked(t, ApduCommand::select(&DL_AID).to_bytes())?;
            evidence.attributes = read_ef(t, &[0, 1])?.to_vec();
            evidence.signature = read_ef(t, &[0, 7])?.to_vec();
            if pin2.is_some() {
                evidence.domicile = read_ef(t, &[0, 2])?.to_vec();
                let mut photo_aid = DL_AID;
                photo_aid[5] = 2;
                checked(t, ApduCommand::select(&photo_aid).to_bytes())?;
                evidence.photo = read_ef(t, &[0, 1])?.to_vec();
            }
            let mut preview = parse_license(&evidence.attributes)?;
            preview.backend_verifiable = pin2.is_some();
            Ok((preview, evidence))
        }
    }
}

/// Strict single-byte TLV used by NPA DF1 (including tags 1F/B1).
pub fn license_fields(
    mut bytes: &[u8],
) -> Result<std::collections::HashMap<u8, &[u8]>, CardFailure> {
    let mut fields = std::collections::HashMap::new();
    if bytes.len() > MAX_EF {
        return Err(FailureCode::InvalidData.into());
    }
    while !bytes.is_empty() {
        if matches!(bytes[0], 0 | 255) {
            // Fixed-size EFs use trailing padding, never skip embedded garbage.
            if bytes.iter().all(|b| matches!(b, 0 | 255)) {
                break;
            }
            return Err(FailureCode::InvalidData.into());
        }
        let tag = bytes[0];
        let length = *bytes.get(1).ok_or(FailureCode::InvalidData)?;
        let (start, length) = if length < 128 {
            (2, length as usize)
        } else if length == 0x82 && bytes.len() >= 4 {
            (4, u16::from_be_bytes([bytes[2], bytes[3]]) as usize)
        } else {
            return Err(FailureCode::InvalidData.into());
        };
        let value = bytes
            .get(start..start + length)
            .ok_or(FailureCode::InvalidData)?;
        if fields.insert(tag, value).is_some() {
            return Err(FailureCode::InvalidData.into());
        }
        bytes = &bytes[start + length..];
    }
    Ok(fields)
}

pub fn parse_license(raw: &[u8]) -> Result<CardPreview, CardFailure> {
    use civ_card::utils::{DateUtils, decode_jis_x0208};
    let fields = license_fields(raw)?;
    let get = |tag| {
        fields
            .get(&tag)
            .copied()
            .ok_or_else(|| CardFailure::from(FailureCode::InvalidData))
    };
    let text = |tag, max| -> Result<String, CardFailure> {
        let bytes = get(tag)?;
        // Gaiji need bitmap handling; don't silently replace names in an issued credential.
        if bytes.is_empty()
            || bytes.len() > max
            || bytes.len() % 2 != 0
            || !bytes.iter().all(|b| (0x21..=0x7e).contains(b))
        {
            return Err(FailureCode::InvalidData.into());
        }
        let value = decode_jis_x0208(bytes).trim().to_string();
        if value.is_empty() || value.contains('\u{fffd}') || value.chars().any(char::is_control) {
            return Err(FailureCode::InvalidData.into());
        }
        Ok(value)
    };
    let date = |tag| -> Result<String, CardFailure> {
        let bytes = get(tag)?;
        if bytes.len() != 7 || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(FailureCode::InvalidData.into());
        }
        let input =
            std::str::from_utf8(bytes).map_err(|_| CardFailure::from(FailureCode::InvalidData))?;
        let date = DateUtils::parse_japanese_era(input)
            .map_err(|_| CardFailure::from(FailureCode::InvalidData))?;
        if !valid_date(&date) {
            return Err(FailureCode::InvalidData.into());
        }
        Ok(date)
    };
    Ok(CardPreview {
        name: text(0x12, 72)?,
        address: text(0x17, 80)?,
        birth_date: date(0x16)?,
        gender: String::new(),
        verification: "unverified".into(),
        document_type: DocumentType::DrivingLicense,
        expiry_date: Some(date(0x1b)?),
        backend_verifiable: true,
    })
}

#[cfg(test)]
mod license_tests {
    use super::*;
    use std::collections::VecDeque;
    fn raw() -> Vec<u8> {
        let mut raw = vec![];
        for (tag, value) in [
            (0x12, &[0x30, 0x22][..]),
            (0x17, &[0x30, 0x22][..]),
            (0x16, &b"4020228"[..]),
            (0x1b, &b"5120101"[..]),
            (0x1f, &b""[..]),
        ] {
            raw.extend([tag, value.len() as u8]);
            raw.extend(value);
        }
        raw
    }
    #[test]
    fn parses_flat_single_byte_tags_and_validates_dates_names() {
        let bytes = raw();
        let p = parse_license(&bytes).unwrap();
        assert_eq!(p.birth_date, "1990-02-28");
        assert_eq!(p.expiry_date.as_deref(), Some("2030-01-01"));
        assert!(p.gender.is_empty());
        for n in 0..bytes.len() - 2 {
            assert!(parse_license(&bytes[..n]).is_err());
        }
        let mut duplicate = bytes.clone();
        duplicate.extend([0x12, 2, 0x30, 0x22]);
        assert!(parse_license(&duplicate).is_err());
        assert!(license_fields(&[0x12, 0x81, 2, 0x30, 0x22]).is_err());
        let mut gaiji = bytes;
        gaiji[2] = 255;
        assert!(parse_license(&gaiji).is_err());
    }
    struct Script(VecDeque<(Vec<u8>, Vec<u8>)>);
    impl CardTransport for Script {
        fn transmit(&mut self, c: &[u8]) -> Result<Vec<u8>, CardFailure> {
            let (want, response) = self
                .0
                .pop_front()
                .expect("unexpected APDU or automatic PIN retry");
            assert_eq!(c, want);
            Ok(response)
        }
    }
    #[test]
    fn verifies_pins_under_mf_and_reads_photo_only_with_pin2() {
        let mut steps = VecDeque::new();
        for id in [1, 2] {
            steps.push_back((vec![0, 0xa4, 0, 0], vec![0x90, 0]));
            steps.push_back((vec![0, 0xa4, 2, 0x0c, 2, 0, id], vec![0x90, 0]));
            steps.push_back((
                vec![0, 0x20, 0, 0x80, 4, b'1', b'2', b'3', b'4'],
                vec![0x90, 0],
            ));
        }
        steps.push_back((ApduCommand::select(&DL_AID).to_bytes(), vec![0x90, 0]));
        for (id, mut data) in [(1, raw()), (7, vec![0xb1, 0]), (2, vec![0x41, 0])] {
            steps.push_back((vec![0, 0xa4, 2, 0x0c, 2, 0, id], vec![0x90, 0]));
            data.extend([0x62, 0x82]);
            steps.push_back((vec![0, 0xb0, 0, 0, 0], data));
        }
        let mut photo_aid = DL_AID;
        photo_aid[5] = 2;
        steps.push_back((ApduCommand::select(&photo_aid).to_bytes(), vec![0x90, 0]));
        steps.push_back((vec![0, 0xa4, 2, 0x0c, 2, 0, 1], vec![0x90, 0]));
        steps.push_back((vec![0, 0xb0, 0, 0, 0], vec![1, 0x62, 0x82]));
        let mut t = Script(steps);
        let (p, e) =
            read_document(&mut t, DocumentType::DrivingLicense, "1234", Some("1234")).unwrap();
        assert!(t.0.is_empty());
        assert!(p.backend_verifiable);
        assert_eq!(e.photo, vec![1]);
    }
    #[test]
    fn license_pin_failure_is_single_attempt_and_invalid_pin2_never_reads() {
        let mut t = Script(VecDeque::from([
            (vec![0, 0xa4, 0, 0], vec![0x90, 0]),
            (vec![0, 0xa4, 2, 0x0c, 2, 0, 1], vec![0x90, 0]),
            (
                vec![0, 0x20, 0, 0x80, 4, b'1', b'2', b'3', b'4'],
                vec![0x63, 0xc1],
            ),
        ]));
        assert_eq!(
            read_document(&mut t, DocumentType::DrivingLicense, "1234", Some("1234"))
                .err()
                .unwrap()
                .remaining_retries,
            Some(1)
        );
        assert!(t.0.is_empty());
        assert!(
            read_document(
                &mut t,
                DocumentType::DrivingLicense,
                "1234",
                Some("invalid")
            )
            .is_err()
        );
    }
}
