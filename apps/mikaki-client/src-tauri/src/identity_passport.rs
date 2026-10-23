//! Android BAC + TD3 DG1/SOD verification with pinned offline CSCA/CRL checks.
//! Matched passport data may be saved explicitly. Communication keys stay transient.
mod authentication;
mod crypto;
pub(crate) use authentication::Report as AuthenticationReport;
#[cfg(test)]
mod tests;
use crate::identity_card::{CardFailure, CardPreview, CardTransport, DocumentType, FailureCode};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use crypto::{crypt, equal, length, mac, pad, value, Keys, Session};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Only document data, never BAC keys, counters, nonces or transport bytes.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PassportData {
    pub document_number: String,
    /// The chip's exact 88 ASCII TD3 characters, without inserted line breaks.
    pub mrz: String,
    /// Bounded EF.SOD evidence, encrypted with the document; never trusted as a root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sod: Option<String>,
}
impl Drop for PassportData {
    fn drop(&mut self) {
        self.document_number.zeroize();
        self.mrz.zeroize();
        if let Some(sod) = &mut self.sod {
            sod.zeroize();
        }
    }
}
impl PassportData {
    pub fn matches(&self, expected: &CardPreview) -> bool {
        if expected.document_type != DocumentType::Passport || self.mrz.len() != 88 {
            return false;
        }
        if self.sod.as_ref().is_some_and(|s| {
            s.len() > 10924
                || !B64.decode(s).is_ok_and(|bytes| {
                    !bytes.is_empty()
                        && bytes.len() <= authentication::MAX_SOD
                        && B64.encode(&bytes) == *s
                })
        }) {
            return false;
        }
        let Some(expiry) = &expected.expiry_date else {
            return false;
        };
        let Ok(access) = Access::new(
            self.document_number.clone(),
            expected.birth_date.clone(),
            expiry.clone(),
        ) else {
            return false;
        };
        let mut dg1 = Zeroizing::new(Vec::with_capacity(93));
        dg1.extend_from_slice(&[0x61, 91, 0x5f, 0x1f, 88]);
        dg1.extend_from_slice(self.mrz.as_bytes());
        preview(&dg1, &access).is_ok_and(|actual| actual == *expected)
    }
    pub fn authentication(&self) -> AuthenticationReport {
        let Some(sod) = &self.sod else {
            return AuthenticationReport::new(authentication::State::NotChecked);
        };
        let Ok(sod) = B64.decode(sod) else {
            return AuthenticationReport::new(authentication::State::Invalid);
        };
        let mut dg1 = Zeroizing::new(Vec::with_capacity(93));
        dg1.extend_from_slice(&[0x61, 91, 0x5f, 0x1f, 88]);
        dg1.extend_from_slice(self.mrz.as_bytes());
        authentication::verify(&sod, &dg1)
    }
}
pub(crate) struct Read {
    pub preview: CardPreview,
    pub passport: PassportData,
}

type Result<T> = std::result::Result<T, CardFailure>;
fn bad() -> CardFailure {
    FailureCode::InvalidData.into()
}
fn integrity() -> CardFailure {
    FailureCode::PassportIntegrityFailed.into()
}
fn authentication() -> CardFailure {
    FailureCode::PassportAuthenticationFailed.into()
}

pub(crate) struct Access {
    number: Zeroizing<String>,
    birth_date: Zeroizing<String>,
    expiry_date: Zeroizing<String>,
}
impl Access {
    pub fn new(number: String, birth_date: String, expiry_date: String) -> Result<Self> {
        let access = Self {
            number: Zeroizing::new(number),
            birth_date: Zeroizing::new(birth_date),
            expiry_date: Zeroizing::new(expiry_date),
        };
        if access.number.is_empty()
            || access.number.len() > 9
            || !access
                .number
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            || !date(&access.birth_date)
            || !date(&access.expiry_date)
            || access.birth_date.as_str() >= access.expiry_date.as_str()
        {
            return Err(FailureCode::InvalidPassportAccess.into());
        }
        Ok(access)
    }
    fn number_field(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(9));
        out.push_str(&self.number);
        while out.len() < 9 {
            out.push('<');
        }
        out
    }
    fn short(date: &str) -> Zeroizing<String> {
        Zeroizing::new(format!("{}{}{}", &date[2..4], &date[5..7], &date[8..10]))
    }
    fn info(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(24));
        for field in [
            self.number_field(),
            Self::short(&self.birth_date),
            Self::short(&self.expiry_date),
        ] {
            out.extend_from_slice(field.as_bytes());
            out.push(check(field.as_bytes()));
        }
        out
    }
}
fn date(date: &str) -> bool {
    let b = date.as_bytes();
    if b.len() != 10
        || b[4] != b'-'
        || b[7] != b'-'
        || !b
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return false;
    }
    let y: u32 = date[..4].parse().unwrap_or(0);
    let m: usize = date[5..7].parse().unwrap_or(0);
    let d: u32 = date[8..].parse().unwrap_or(0);
    let leap = y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    (1800..=2199).contains(&y)
        && (1..=12).contains(&m)
        && d > 0
        && d <= [
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
        ][m.saturating_sub(1).min(11)]
}
fn check(data: &[u8]) -> u8 {
    b'0' + (data
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let n = match b {
                b'0'..=b'9' => b - b'0',
                b'A'..=b'Z' => b - b'A' + 10,
                _ => 0,
            };
            n as usize * [7, 3, 1][i % 3]
        })
        .sum::<usize>()
        % 10) as u8
}

fn plain(t: &mut impl CardTransport, cmd: &[u8], auth: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut response = Zeroizing::new(t.transmit(cmd)?);
    if response.len() < 2 || response.len() > 512 {
        return Err(bad());
    }
    if !response.ends_with(&[0x90, 0]) {
        return Err(if auth {
            authentication()
        } else {
            FailureCode::UnsupportedCard.into()
        });
    }
    let size = response.len() - 2;
    response.truncate(size);
    Ok(response)
}
fn establish(t: &mut impl CardTransport, access: &Access, random: &[u8; 24]) -> Result<Session> {
    plain(
        t,
        &[0, 0xa4, 4, 0x0c, 7, 0xa0, 0, 0, 2, 0x47, 0x10, 1],
        false,
    )?;
    let challenge = plain(t, &[0, 0x84, 0, 0, 8], true)?;
    if challenge.len() != 8 {
        return Err(authentication());
    }
    let keys = Keys::from_mrz(&access.info());
    let mut payload = Zeroizing::new(random[..8].to_vec());
    payload.extend_from_slice(&challenge);
    payload.extend_from_slice(&random[8..]);
    let encrypted = crypt(&keys.enc, &payload, true)?;
    let mut cmd = Zeroizing::new(vec![0, 0x82, 0, 0, 40]);
    cmd.extend_from_slice(&encrypted);
    cmd.extend_from_slice(&mac(&keys.mac, &pad(&encrypted))?);
    cmd.push(40);
    let response = plain(t, &cmd, true)?;
    // Verify the response MAC before decrypting; both nonces bind this session.
    if response.len() != 40 || !equal(&mac(&keys.mac, &pad(&response[..32]))?, &response[32..]) {
        return Err(authentication());
    }
    let decoded = crypt(&keys.enc, &response[..32], false)?;
    if !equal(&decoded[..8], &challenge) || !equal(&decoded[8..16], &random[..8]) {
        return Err(authentication());
    }
    let mut seed = Zeroizing::new([0u8; 16]);
    for i in 0..16 {
        seed[i] = random[i + 8] ^ decoded[i + 16];
    }
    let mut ssc = [0u8; 8];
    ssc[..4].copy_from_slice(&challenge[4..]);
    ssc[4..].copy_from_slice(&random[4..8]);
    Ok(Session {
        keys: Keys::from_seed(seed.as_ref()),
        ssc: u64::from_be_bytes(ssc),
    })
}
fn secure(
    t: &mut impl CardTransport,
    s: &mut Session,
    header: [u8; 4],
    data: &[u8],
    le: Option<u8>,
) -> Result<Zeroizing<Vec<u8>>> {
    let cmd = s.wrap(header, data, le)?;
    let response = Zeroizing::new(t.transmit(&cmd)?);
    s.unwrap(&response)
}
fn secure_status(
    t: &mut impl CardTransport,
    s: &mut Session,
    header: [u8; 4],
    data: &[u8],
    le: Option<u8>,
) -> Result<(Zeroizing<Vec<u8>>, u16)> {
    let cmd = s.wrap(header, data, le)?;
    let response = Zeroizing::new(t.transmit(&cmd)?);
    s.unwrap_with_status(&response)
}
fn read_sod(t: &mut impl CardTransport, s: &mut Session) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let (data, status) = secure_status(t, s, [0, 0xa4, 2, 0x0c], &[1, 0x1d], None)?;
    if status == 0x6a82 && data.is_empty() {
        return Ok(None);
    }
    if status != 0x9000 || !data.is_empty() {
        return Err(bad());
    }
    let mut data = secure(t, s, [0, 0xb0, 0, 0], &[], Some(4))?;
    if data.len() != 4 || data[0] != 0x77 {
        return Err(bad());
    }
    let mut pos = 1;
    let total = length(&data, &mut pos)?
        .checked_add(pos)
        .filter(|n| (5..=authentication::MAX_SOD).contains(n))
        .ok_or_else(bad)?;
    while data.len() < total {
        let offset = data.len();
        let count = (total - offset).min(208) as u8;
        let part = secure(
            t,
            s,
            [0, 0xb0, (offset >> 8) as u8, offset as u8],
            &[],
            Some(count),
        )?;
        if part.len() != count as usize {
            return Err(bad());
        }
        data.extend_from_slice(&part);
    }
    Ok(Some(data))
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn read(t: &mut impl CardTransport, access: &Access) -> Result<Read> {
    use getrandom::SysRng;
    use rand_core::TryRng;
    let mut random = Zeroizing::new([0u8; 24]);
    SysRng
        .try_fill_bytes(random.as_mut())
        .map_err(|_| CardFailure::from(FailureCode::TransportError))?;
    read_with_random(t, access, &random)
}
fn read_with_random(
    t: &mut impl CardTransport,
    access: &Access,
    random: &[u8; 24],
) -> Result<Read> {
    let mut session = establish(t, access, random)?;
    if !secure(t, &mut session, [0, 0xa4, 2, 0x0c], &[1, 1], None)?.is_empty() {
        return Err(bad());
    }
    let mut data = secure(t, &mut session, [0, 0xb0, 0, 0], &[], Some(4))?;
    if data.len() != 4 || data[0] != 0x61 {
        return Err(bad());
    }
    let mut pos = 1;
    let len = length(&data, &mut pos)?;
    let total = pos
        .checked_add(len)
        .filter(|n| (5..=4096).contains(n))
        .ok_or_else(bad)?;
    while data.len() < total {
        let offset = data.len();
        let count = (total - offset).min(208) as u8;
        let part = secure(
            t,
            &mut session,
            [0, 0xb0, (offset >> 8) as u8, offset as u8],
            &[],
            Some(count),
        )?;
        if part.len() != count as usize {
            return Err(bad());
        }
        data.extend_from_slice(&part);
    }
    let preview = preview(&data, access)?;
    // The strict parser accepts exactly the TD3 DG1 structure: 5 header + 88 MRZ bytes.
    let passport = PassportData {
        document_number: access.number.to_string(),
        mrz: std::str::from_utf8(&data[5..])
            .map_err(|_| bad())?
            .to_string(),
        sod: read_sod(t, &mut session)?.map(|bytes| B64.encode(&*bytes)),
    };
    Ok(Read { preview, passport })
}
fn preview(dg1: &[u8], access: &Access) -> Result<CardPreview> {
    let mut pos = 0;
    let outer = value(dg1, &mut pos, &[0x61])?;
    if pos != dg1.len() {
        return Err(bad());
    }
    pos = 0;
    let mrz = value(outer, &mut pos, &[0x5f, 0x1f])?;
    if pos != outer.len()
        || mrz.len() != 88
        || !mrz
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'<')
        || mrz[0] != b'P'
        || !mrz[1..5]
            .iter()
            .all(|b| b.is_ascii_uppercase() || *b == b'<')
        || !mrz[5..44]
            .iter()
            .all(|b| b.is_ascii_uppercase() || *b == b'<')
    {
        return Err(bad());
    }
    let line = &mrz[44..];
    if !line[10..13]
        .iter()
        .all(|b| b.is_ascii_uppercase() || *b == b'<')
        || !line[13..19]
            .iter()
            .chain(&line[21..27])
            .all(u8::is_ascii_digit)
        || !b"MF<".contains(&line[20])
        || check(&line[..9]) != line[9]
        || check(&line[13..19]) != line[19]
        || check(&line[21..27]) != line[27]
        || !(check(&line[28..42]) == line[42]
            || (line[42] == b'<' && line[28..42].iter().all(|b| *b == b'<')))
    {
        return Err(bad());
    }
    let mut composite = Zeroizing::new(line[..10].to_vec());
    composite.extend_from_slice(&line[13..20]);
    composite.extend_from_slice(&line[21..43]);
    if check(&composite) != line[43]
        || !equal(&line[..9], access.number_field().as_bytes())
        || !equal(&line[13..19], Access::short(&access.birth_date).as_bytes())
        || !equal(&line[21..27], Access::short(&access.expiry_date).as_bytes())
    {
        return Err(bad());
    }
    let names = std::str::from_utf8(&mrz[5..44]).map_err(|_| bad())?;
    if !names.contains("<<") {
        return Err(bad());
    }
    let name = names
        .split('<')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if name.is_empty() {
        return Err(bad());
    }
    // The full years were supplied by the user; DG1 has only two-digit years.
    // No century is inferred and no issuer-signed claim is created from this input.
    Ok(CardPreview {
        name,
        address: String::new(),
        birth_date: access.birth_date.to_string(),
        gender: match line[20] {
            b'M' => "1",
            b'F' => "2",
            _ => "9",
        }
        .into(),
        verification: "unverified".into(),
        document_type: DocumentType::Passport,
        expiry_date: Some(access.expiry_date.to_string()),
        backend_verifiable: false,
    })
}
