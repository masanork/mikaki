//! BAC primitives adapted from civ (see ORIGIN). Not used for credential crypto.
use super::{bad, integrity, Result};
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use des::{Des, TdesEde3};
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub(super) struct Keys {
    pub enc: Zeroizing<[u8; 16]>,
    pub mac: Zeroizing<[u8; 16]>,
}
impl Keys {
    pub fn from_seed(seed: &[u8]) -> Self {
        fn derive(seed: &[u8], counter: u32) -> Zeroizing<[u8; 16]> {
            let mut hash = Sha1::new();
            hash.update(seed);
            hash.update(counter.to_be_bytes());
            let mut digest = hash.finalize();
            let mut key = Zeroizing::new([0u8; 16]);
            key.copy_from_slice(&digest[..16]);
            digest.as_mut_slice().zeroize();
            for b in key.iter_mut() {
                *b &= 0xfe;
                *b |= u8::from(b.count_ones() % 2 == 0);
            }
            key
        }
        Self {
            enc: derive(seed, 1),
            mac: derive(seed, 2),
        }
    }
    pub fn from_mrz(info: &[u8]) -> Self {
        let mut hash = Sha1::digest(info);
        let keys = Self::from_seed(&hash[..16]);
        hash.as_mut_slice().zeroize();
        keys
    }
}

pub(super) fn equal(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}
pub(super) fn pad(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity((data.len() / 8 + 1) * 8));
    out.extend_from_slice(data);
    out.push(0x80);
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
    out
}
pub(super) fn crypt(key: &[u8; 16], data: &[u8], encrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    if data.is_empty() || !data.len().is_multiple_of(8) {
        return Err(integrity());
    }
    let mut expanded = Zeroizing::new([0u8; 24]);
    expanded[..16].copy_from_slice(key);
    expanded[16..].copy_from_slice(&key[..8]);
    let cipher = TdesEde3::new_from_slice(expanded.as_ref()).map_err(|_| integrity())?;
    let mut iv = Zeroizing::new([0u8; 8]);
    let mut out = Zeroizing::new(Vec::with_capacity(data.len()));
    for chunk in data.chunks_exact(8) {
        let mut block = Zeroizing::new([0u8; 8]);
        block.copy_from_slice(chunk);
        if encrypt {
            for i in 0..8 {
                block[i] ^= iv[i];
            }
            cipher.encrypt_block((&mut *block).into());
            iv.copy_from_slice(&*block);
        } else {
            cipher.decrypt_block((&mut *block).into());
            for i in 0..8 {
                block[i] ^= iv[i];
            }
            iv.copy_from_slice(chunk);
        }
        out.extend_from_slice(&*block);
    }
    Ok(out)
}
pub(super) fn decrypt_padded(key: &[u8; 16], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = crypt(key, data, false)?;
    // Method 2 padding occupies at most one block; never accept arbitrary zeros.
    for _ in 0..8 {
        match out.pop() {
            Some(0x80) => return Ok(out),
            Some(0) => (),
            _ => return Err(integrity()),
        }
    }
    Err(integrity())
}
pub(super) fn mac(key: &[u8; 16], data: &[u8]) -> Result<[u8; 8]> {
    if data.is_empty() || !data.len().is_multiple_of(8) {
        return Err(integrity());
    }
    let a = Des::new_from_slice(&key[..8]).map_err(|_| integrity())?;
    let b = Des::new_from_slice(&key[8..]).map_err(|_| integrity())?;
    let mut block = Zeroizing::new([0u8; 8]);
    for chunk in data.chunks_exact(8) {
        for i in 0..8 {
            block[i] ^= chunk[i];
        }
        a.encrypt_block((&mut *block).into());
    }
    b.decrypt_block((&mut *block).into());
    a.encrypt_block((&mut *block).into());
    Ok(*block)
}

/// Bounded canonical BER lengths. Indefinite, redundant and overflowing encodings fail.
pub(super) fn length(data: &[u8], pos: &mut usize) -> Result<usize> {
    let first = *data.get(*pos).ok_or_else(bad)?;
    *pos += 1;
    match first {
        0..=0x7f => Ok(first as usize),
        0x81 => {
            let len = *data.get(*pos).ok_or_else(bad)? as usize;
            *pos += 1;
            if len < 128 {
                Err(bad())
            } else {
                Ok(len)
            }
        }
        0x82 => {
            let bytes = data.get(*pos..*pos + 2).ok_or_else(bad)?;
            *pos += 2;
            let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if !(256..=8192).contains(&len) {
                Err(bad())
            } else {
                Ok(len)
            }
        }
        _ => Err(bad()),
    }
}
pub(super) fn value<'a>(data: &'a [u8], pos: &mut usize, tag: &[u8]) -> Result<&'a [u8]> {
    if data.get(*pos..*pos + tag.len()) != Some(tag) {
        return Err(bad());
    }
    *pos += tag.len();
    let len = length(data, pos)?;
    let value = data.get(*pos..*pos + len).ok_or_else(bad)?;
    *pos += len;
    Ok(value)
}
fn object(out: &mut Vec<u8>, tag: u8, data: &[u8]) -> Result<()> {
    if data.len() > 255 {
        return Err(bad());
    }
    out.push(tag);
    if data.len() >= 128 {
        out.push(0x81);
    }
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    Ok(())
}
pub(super) struct Session {
    pub keys: Keys,
    pub ssc: u64,
}
impl Session {
    fn next(&mut self) -> Result<[u8; 8]> {
        self.ssc = self.ssc.checked_add(1).ok_or_else(integrity)?;
        Ok(self.ssc.to_be_bytes())
    }
    pub fn wrap(
        &mut self,
        header: [u8; 4],
        data: &[u8],
        le: Option<u8>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let ssc = self.next()?;
        let mut objects = Zeroizing::new(Vec::new());
        if !data.is_empty() {
            let encrypted = crypt(&self.keys.enc, &pad(data), true)?;
            let mut contents = Zeroizing::new(vec![1]);
            contents.extend_from_slice(&encrypted);
            object(&mut objects, 0x87, &contents)?;
        }
        if let Some(le) = le {
            object(&mut objects, 0x97, &[le])?;
        }
        let header = [header[0] | 0x0c, header[1], header[2], header[3]];
        let mut input = Zeroizing::new(ssc.to_vec());
        input.extend_from_slice(&pad(&header));
        input.extend_from_slice(&objects);
        let signature = mac(&self.keys.mac, &pad(&input))?;
        object(&mut objects, 0x8e, &signature)?;
        if objects.len() > 255 {
            return Err(bad());
        }
        let mut apdu = Zeroizing::new(header.to_vec());
        apdu.push(objects.len() as u8);
        apdu.extend_from_slice(&objects);
        apdu.push(0);
        Ok(apdu)
    }
    pub fn unwrap(&mut self, response: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let (data, status) = self.unwrap_with_status(response)?;
        if status != 0x9000 {
            return Err(bad());
        }
        Ok(data)
    }
    pub fn unwrap_with_status(&mut self, response: &[u8]) -> Result<(Zeroizing<Vec<u8>>, u16)> {
        // Only this ordered grammar is accepted: [DO87] DO99 DO8E 9000.
        // Authenticate the original octets, before any decryption or status handling.
        if response.len() < 16 || response.len() > 512 || !response.ends_with(&[0x90, 0]) {
            return Err(integrity());
        }
        let data = &response[..response.len() - 2];
        let mut pos = 0;
        let encrypted = if data.first() == Some(&0x87) {
            Some(value(data, &mut pos, &[0x87]).map_err(|_| integrity())?)
        } else {
            None
        };
        let status = value(data, &mut pos, &[0x99]).map_err(|_| integrity())?;
        let signed_len = pos;
        let signature = value(data, &mut pos, &[0x8e]).map_err(|_| integrity())?;
        if pos != data.len() || status.len() != 2 || signature.len() != 8 {
            return Err(integrity());
        }
        let mut input = Zeroizing::new(self.next()?.to_vec());
        input.extend_from_slice(&data[..signed_len]);
        if !equal(&mac(&self.keys.mac, &pad(&input))?, signature) {
            return Err(integrity());
        }
        let status = u16::from_be_bytes([status[0], status[1]]);
        let plaintext = if let Some(encrypted) = encrypted {
            if encrypted.first() != Some(&1) {
                return Err(integrity());
            }
            decrypt_padded(&self.keys.enc, &encrypted[1..])?
        } else {
            Zeroizing::new(Vec::new())
        };
        Ok((plaintext, status))
    }
}
