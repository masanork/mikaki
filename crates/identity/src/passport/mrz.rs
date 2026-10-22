use super::Dg1Claims;
use zeroize::Zeroizing;

fn check(bytes: impl IntoIterator<Item = u8>) -> u8 {
    let sum = bytes
        .into_iter()
        .zip([7, 3, 1].into_iter().cycle())
        .map(|(b, w)| {
            let n = match b {
                b'0'..=b'9' => b - b'0',
                b'A'..=b'Z' => b - b'A' + 10,
                _ => 0,
            };
            u32::from(n) * w
        })
        .sum::<u32>();
    b'0' + (sum % 10) as u8
}
pub(super) fn date(raw: &[u8]) -> bool {
    if raw.len() != 6 || !raw.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let n = |i| (raw[i] - b'0') * 10 + raw[i + 1] - b'0';
    let days = match n(2) {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if n(0) % 4 == 0 => 29,
        2 => 28,
        _ => 0,
    };
    (1..=days).contains(&n(4))
}
pub(super) fn claims(dg1: &[u8]) -> Result<Dg1Claims, ()> {
    if dg1.len() != 93 || dg1[..5] != [0x61, 91, 0x5f, 0x1f, 88] {
        return Err(());
    }
    let mrz = &dg1[5..];
    let line = &mrz[44..];
    let letters = |s: &[u8]| s.iter().all(|b| b.is_ascii_uppercase() || *b == b'<');
    if !mrz
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'<')
        || mrz[0] != b'P'
        || !letters(&mrz[1..5])
        || !letters(&mrz[5..44])
        || !letters(&line[10..13])
        || !date(&line[13..19])
        || !date(&line[21..27])
        || !b"MF<".contains(&line[20])
        || check(line[..9].iter().copied()) != line[9]
        || check(line[13..19].iter().copied()) != line[19]
        || check(line[21..27].iter().copied()) != line[27]
        || !(check(line[28..42].iter().copied()) == line[42]
            || (line[42] == b'<' && line[28..42].iter().all(|b| *b == b'<')))
        || check(
            line[..10]
                .iter()
                .chain(&line[13..20])
                .chain(&line[21..43])
                .copied(),
        ) != line[43]
    {
        return Err(());
    }
    let text = |s: &[u8]| std::str::from_utf8(s).map(str::to_owned).map_err(|_| ());
    let number = std::str::from_utf8(&line[..9])
        .map_err(|_| ())?
        .trim_end_matches('<');
    if number.is_empty()
        || !number
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(());
    }
    let names = Zeroizing::new(text(&mrz[5..44])?);
    if !names.contains("<<") {
        return Err(());
    }
    let name = names
        .split('<')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if name.is_empty() {
        return Err(());
    }
    Ok(Dg1Claims {
        name_mrz: name,
        issuing_state: text(&mrz[2..5])?,
        nationality: text(&line[10..13])?,
        birth_date_mrz: text(&line[13..19])?,
        expiry_date_mrz: text(&line[21..27])?,
        sex_mrz: text(&line[20..21])?,
    })
}
