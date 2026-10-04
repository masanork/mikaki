//! Bounded NFC Forum Connection Handover 1.5, explicit BLE mdoc peripheral or NFC data retrieval profiles.
struct Record<'a> {
    tnf: u8,
    kind: &'a [u8],
    id: &'a [u8],
    payload: &'a [u8],
}
fn records(mut data: &[u8]) -> Result<Vec<Record<'_>>, &'static str> {
    let mut result = Vec::new();
    while !data.is_empty() {
        if result.len() == 16 || data.len() < 3 {
            return Err("invalid_handover");
        }
        let flags = data[0];
        if flags & 0x20 != 0 || (flags & 0x80 != 0) != result.is_empty() {
            return Err("invalid_handover");
        }
        let tnf = flags & 7;
        if !(1..=4).contains(&tnf) {
            return Err("invalid_handover");
        }
        let kind_len = data[1] as usize;
        let mut offset = 2;
        let payload_len = if flags & 0x10 != 0 {
            offset += 1;
            data[2] as usize
        } else {
            if data.len() < 6 {
                return Err("invalid_handover");
            }
            offset += 4;
            u32::from_be_bytes(data[2..6].try_into().map_err(|_| "invalid_handover")?) as usize
        };
        let id_len = if flags & 8 != 0 {
            let len = *data.get(offset).ok_or("invalid_handover")? as usize;
            offset += 1;
            len
        } else {
            0
        };
        let total = offset
            .checked_add(kind_len)
            .and_then(|n| n.checked_add(id_len))
            .and_then(|n| n.checked_add(payload_len))
            .ok_or("invalid_handover")?;
        if total > data.len() || kind_len == 0 {
            return Err("invalid_handover");
        }
        let kind = &data[offset..offset + kind_len];
        offset += kind_len;
        let id = &data[offset..offset + id_len];
        offset += id_len;
        if !id.is_empty() && result.iter().any(|r: &Record<'_>| r.id == id) {
            return Err("invalid_handover");
        }
        result.push(Record {
            tnf,
            kind,
            id,
            payload: &data[offset..total],
        });
        data = &data[total..];
        if (flags & 0x40 != 0) != data.is_empty() {
            return Err("invalid_handover");
        }
    }
    if result.is_empty() {
        return Err("invalid_handover");
    }
    Ok(result)
}
pub(super) fn validate_request(data: &[u8], nfc_data: bool) -> Result<(), &'static str> {
    if data.is_empty() || data.len() > 4094 {
        return Err("invalid_handover");
    }
    let outer = records(data)?;
    let hr = &outer[0];
    if hr.tnf != 1 || hr.kind != b"Hr" || !hr.id.is_empty() || hr.payload.first() != Some(&0x15) {
        return Err("invalid_handover");
    }
    let inner = records(&hr.payload[1..])?;
    let mut references = Vec::new();
    let mut collision = false;
    let mut supported = false;
    for r in inner {
        if r.tnf != 1 || !r.id.is_empty() {
            return Err("invalid_handover");
        }
        if r.kind == b"cr" {
            if collision || r.payload.len() != 2 {
                return Err("invalid_handover");
            }
            collision = true;
            continue;
        }
        if r.kind != b"ac" || r.payload.len() < 4 || r.payload[0] > 3 {
            return Err("invalid_handover");
        }
        let p = r.payload;
        let size = p[1] as usize;
        if size == 0 || p.len() < size + 3 {
            return Err("invalid_handover");
        }
        let id = &p[2..2 + size];
        if references.contains(&id) {
            return Err("invalid_handover");
        }
        references.push(id);
        let carrier = outer
            .iter()
            .skip(1)
            .find(|r| r.id == id)
            .ok_or("invalid_handover")?;
        let mut offset = size + 3;
        for _ in 0..p[size + 2] {
            let length = *p.get(offset).ok_or("invalid_handover")? as usize;
            offset += 1;
            let end = offset.checked_add(length).ok_or("invalid_handover")?;
            let auxiliary = p.get(offset..end).ok_or("invalid_handover")?;
            if length == 0 || !outer.iter().skip(1).any(|r| r.id == auxiliary) {
                return Err("invalid_handover");
            }
            offset = end;
        }
        if offset != p.len() {
            return Err("invalid_handover");
        }
        if !matches!(p[0], 1 | 2) {
            continue;
        }
        if carrier.tnf == 4 && carrier.kind == b"iso.org:18013:nfc" {
            let (command, response) = nfc_limits(carrier.payload)?;
            if nfc_data && command >= 255 && response >= 256 {
                supported = true;
            }
            continue;
        }
        if nfc_data || carrier.tnf != 2 || carrier.kind != b"application/vnd.bluetooth.le.oob" {
            continue;
        }
        let mut ad = carrier.payload;
        let mut role = None;
        while !ad.is_empty() {
            let size = ad[0] as usize;
            if size < 1 || size + 1 > ad.len() {
                return Err("invalid_handover");
            }
            if ad[1] == 0x1c {
                if size != 2 || role.is_some() || ad[2] > 3 {
                    return Err("invalid_handover");
                }
                role = Some(ad[2]);
            }
            if ad[1] == 7 && size != 17 {
                return Err("invalid_handover");
            }
            ad = &ad[size + 1..];
        }
        // LE OOB role in Hr is interpreted as an offer from the mdoc reader.
        let role = role.ok_or("invalid_handover")?;
        supported |= matches!(role, 0 | 2 | 3);
    }
    if references.is_empty() || !supported {
        return Err("unsupported_handover");
    }
    Ok(())
}

/// NFC carrier version 1: ordered, bounded unsigned command/response size TLVs.
fn nfc_limits(mut data: &[u8]) -> Result<(u32, u32), &'static str> {
    if data.first() != Some(&1) {
        return Err("invalid_handover");
    }
    data = &data[1..];
    let mut values = [0u32; 2];
    for (index, value) in values.iter_mut().enumerate() {
        let length = *data.first().ok_or("invalid_handover")? as usize;
        let max = if index == 0 { 3 } else { 4 };
        if !(2..=max).contains(&length) || data.len() < length + 1 || data[1] != index as u8 + 1 {
            return Err("invalid_handover");
        }
        for byte in &data[2..length + 1] {
            *value = (*value << 8) | *byte as u32;
        }
        if *value == 0 {
            return Err("invalid_handover");
        }
        data = &data[length + 1..];
    }
    if !data.is_empty() {
        return Err("invalid_handover");
    }
    Ok((values[0], values[1]))
}
