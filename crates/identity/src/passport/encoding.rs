//! Bounded canonical BER framing only. No BAC, DES, transport or platform APIs.
use subtle::ConstantTimeEq;
pub(super) fn equal(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}
pub(super) fn value<'a>(data: &'a [u8], pos: &mut usize, tag: &[u8]) -> Result<&'a [u8], ()> {
    let start = *pos;
    let header = start.checked_add(tag.len()).ok_or(())?;
    if data.get(start..header) != Some(tag) {
        return Err(());
    }
    let mut cursor = header;
    let first = *data.get(cursor).ok_or(())?;
    cursor += 1;
    let len = match first {
        0..=0x7f => first as usize,
        0x81 => {
            let n = *data.get(cursor).ok_or(())? as usize;
            cursor += 1;
            if n < 128 {
                return Err(());
            }
            n
        }
        0x82 => {
            let end = cursor.checked_add(2).ok_or(())?;
            let bytes = data.get(cursor..end).ok_or(())?;
            cursor = end;
            let n = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if !(256..=super::MAX_SOD).contains(&n) {
                return Err(());
            }
            n
        }
        _ => return Err(()),
    };
    let end = cursor.checked_add(len).ok_or(())?;
    let body = data.get(cursor..end).ok_or(())?;
    *pos = end;
    Ok(body)
}
