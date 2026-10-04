//! JPKI utility functions for parsing My Number Card data.

use crate::errors::CivError;
use crate::utils::BerTlv;
use serde::Serialize;
use std::fmt;

/// Basic information from My Number Card (4 attributes).
#[derive(Debug, Default, Serialize, Clone)]
pub struct BasicInfo {
    /// Full name
    pub name: String,
    /// Address
    pub address: String,
    /// Birth date (ISO format)
    pub birth_date: String,
    /// Gender
    pub gender: String,
    /// Face photo data (Base64 encoded, if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub face_photo: Option<String>,
}

impl fmt::Display for BasicInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Name: {}\nAddress: {}\nDOB: {}\nGender: {}\nHas Photo: {}",
            self.name,
            self.address,
            self.birth_date,
            self.gender,
            self.face_photo.is_some()
        )
    }
}

/// Parse basic information from JPKI attribute data.
pub fn parse_basic_info(data: &[u8]) -> Result<BasicInfo, CivError> {
    let mut info = BasicInfo::default();
    let tlvs = parse_jpki_flat_tlv(data);

    fn collect_tags(tlvs: &[BerTlv], map: &mut std::collections::HashMap<u32, String>) {
        for tlv in tlvs {
            // Recurse into common container tags (0x30: Sequence, 0xDF20/FF20: JPKI containers)
            if tlv.tag == 0x30 || tlv.tag == 0xDF20 || tlv.tag == 0xFF20 {
                let nested = parse_jpki_flat_tlv(&tlv.value);
                collect_tags(&nested, map);
            }
            if let Ok(value) = String::from_utf8(tlv.value.clone()) {
                map.insert(tlv.tag, value);
            }
        }
    }

    let mut tag_map = std::collections::HashMap::new();
    collect_tags(&tlvs, &mut tag_map);

    // Tag DF22: Name
    if let Some(v) = tag_map.get(&0xDF22) {
        info.name = v.clone();
    }
    // Tag DF23: Address
    if let Some(v) = tag_map.get(&0xDF23) {
        info.address = v.clone();
    }
    // Tag DF24: Birth date (Japanese era or YYYYMMDD)
    if let Some(v) = tag_map.get(&0xDF24) {
        info.birth_date = parse_jpki_date(v);
    }
    // Tag DF25: Gender
    if let Some(v) = tag_map.get(&0xDF25) {
        info.gender = v.clone();
    }

    Ok(info)
}

/// Parse date from JPKI format (handles Japanese era or YYYYMMDD).
fn parse_jpki_date(s: &str) -> String {
    // Try Japanese era format first (7 chars)
    if s.len() == 7 {
        if let Ok(date) = crate::utils::DateUtils::parse_japanese_era(s) {
            return date;
        }
    }
    // Try YYYYMMDD format
    if s.len() == 8 {
        if let Ok(date) = crate::utils::DateUtils::parse_yyyymmdd(s) {
            return date;
        }
    }
    // Return as-is if parsing fails
    s.to_string()
}

/// Parse JPKI flat TLV structure (more lenient than standard BER-TLV).
pub fn parse_jpki_flat_tlv(data: &[u8]) -> Vec<BerTlv> {
    let mut tlvs = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let first_tag_byte = data[i];
        if first_tag_byte == 0x00 {
            i += 1;
            continue;
        }
        if first_tag_byte == 0xFF && (i + 1 >= data.len() || data[i + 1] == 0xFF) {
            i += 1;
            continue;
        }

        let mut tag: u32 = first_tag_byte as u32;
        i += 1;

        // Multi-byte tag handling
        if (first_tag_byte & 0x1F) == 0x1F {
            while i < data.len() {
                let next_byte = data[i];
                tag = (tag << 8) | (next_byte as u32);
                i += 1;
                if (next_byte & 0x80) == 0 {
                    break;
                }
            }
        }

        if i >= data.len() {
            break;
        }
        let first_len_byte = data[i];
        i += 1;

        let mut len: usize = 0;
        if first_len_byte <= 0x7F {
            len = first_len_byte as usize;
        } else {
            let len_bytes_count = (first_len_byte & 0x7F) as usize;
            for _ in 0..len_bytes_count {
                if i >= data.len() {
                    break;
                }
                len = (len << 8) | (data[i] as usize);
                i += 1;
            }
        }

        if i + len > data.len() {
            let remaining = data.len().saturating_sub(i);
            let value = data[i..i + remaining].to_vec();
            tlvs.push(BerTlv {
                tag,
                value,
                children: Vec::new(),
            });
            break;
        }

        let value = data[i..i + len].to_vec();
        tlvs.push(BerTlv {
            tag,
            value,
            children: Vec::new(),
        });
        i += len;
    }

    tlvs
}

/// Extract face photo from JPKI surface data.
/// Looks for tag DF27 which contains the JPEG2000 image data.
pub fn extract_face_photo(data: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    while i + 2 <= data.len() {
        let b1 = data[i];
        let b2 = data[i + 1];
        if (b1 == 0xFF && b2 == 0xFF) || (b1 == 0x00 && b2 == 0x00) {
            i += 1;
            continue;
        }

        let tag = ((b1 as u16) << 8) | (b2 as u16);
        i += 2;
        if i >= data.len() {
            break;
        }

        let mut value_len = data[i] as usize;
        i += 1;

        // Handle extended length encoding
        if value_len == 0x81 {
            if i >= data.len() {
                break;
            }
            value_len = data[i] as usize;
            i += 1;
        } else if value_len == 0x82 {
            if i + 1 >= data.len() {
                break;
            }
            value_len = ((data[i] as usize) << 8) | (data[i + 1] as usize);
            i += 2;
        } else if value_len == 0x83 {
            if i + 2 >= data.len() {
                break;
            }
            value_len =
                ((data[i] as usize) << 16) | ((data[i + 1] as usize) << 8) | (data[i + 2] as usize);
            i += 3;
        }

        if i + value_len > data.len() {
            break;
        }

        // Tag DF27 contains the face photo
        if tag == 0xDF27 {
            return Some(data[i..i + value_len].to_vec());
        }

        // Recurse into container tags
        if tag == 0xDF20 || tag == 0xFF20 || tag == 0xDF21 || tag == 0xFF21 {
            if let Some(found) = extract_face_photo(&data[i..i + value_len]) {
                return Some(found);
            }
        }

        i += value_len;
    }

    // Direct scan fallbacks for DF27
    let mut j = 0;
    while j + 3 <= data.len() {
        if data[j] == 0xDF && data[j + 1] == 0x27 {
            let mut len = data[j + 2] as usize;
            let mut k = j + 3;
            if len == 0x81 {
                if k < data.len() {
                    len = data[k] as usize;
                    k += 1;
                }
            } else if len == 0x82 && k + 1 < data.len() {
                len = ((data[k] as usize) << 8) | (data[k + 1] as usize);
                k += 2;
            }
            if k + len <= data.len() {
                return Some(data[k..k + len].to_vec());
            }
        }
        j += 1;
    }

    // Try to find JPEG2000 signature
    if let Some(offset) = data.windows(12).position(|w| {
        w == [
            0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
        ]
    }) {
        return Some(data[offset..].to_vec());
    }
    // Alternative JP2 signature
    if let Some(offset) = data.windows(2).position(|w| w == [0xFF, 0x4F]) {
        return Some(data[offset..].to_vec());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jpki_flat_tlv() {
        // Tag DF22, length 4, value "Test"
        let data = [0xDF, 0x22, 0x04, b'T', b'e', b's', b't'];
        let tlvs = parse_jpki_flat_tlv(&data);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0xDF22);
        assert_eq!(tlvs[0].as_utf8(), "Test");
    }

    #[test]
    fn test_parse_basic_info() {
        // Construct test data with DF22 (name), DF23 (address), DF24 (birth date), DF25 (gender)
        let mut data = Vec::new();
        // Name: "Taro"
        data.extend_from_slice(&[0xDF, 0x22, 0x04, b'T', b'a', b'r', b'o']);
        // Address: "Tokyo"
        data.extend_from_slice(&[0xDF, 0x23, 0x05, b'T', b'o', b'k', b'y', b'o']);
        // Birth date: "19900101"
        data.extend_from_slice(&[
            0xDF, 0x24, 0x08, b'1', b'9', b'9', b'0', b'0', b'1', b'0', b'1',
        ]);
        // Gender: "M"
        data.extend_from_slice(&[0xDF, 0x25, 0x01, b'M']);

        let info = parse_basic_info(&data).unwrap();
        assert_eq!(info.name, "Taro");
        assert_eq!(info.address, "Tokyo");
        assert_eq!(info.birth_date, "1990-01-01");
        assert_eq!(info.gender, "M");
    }

    #[test]
    fn test_extract_face_photo_with_df27() {
        // Simulate DF27 tag with image data
        let mut data = Vec::new();
        data.extend_from_slice(&[0xDF, 0x27, 0x05]); // Tag DF27, length 5
        data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]); // Image data

        let photo = extract_face_photo(&data);
        assert!(photo.is_some());
        assert_eq!(photo.unwrap(), vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_basic_info_display() {
        let info = BasicInfo {
            name: "Taro Yamada".to_string(),
            address: "Tokyo".to_string(),
            birth_date: "1990-01-01".to_string(),
            gender: "M".to_string(),
            face_photo: None,
        };
        let display = format!("{}", info);
        assert!(display.contains("Taro Yamada"));
        assert!(display.contains("Tokyo"));
    }

    #[test]
    fn test_parse_jpki_date_yyyymmdd() {
        // 8-char digits -> ISO format.
        assert_eq!(parse_jpki_date("19900101"), "1990-01-01");
    }

    #[test]
    fn test_parse_jpki_date_fallback_returns_input() {
        // Non-era, non-yyyymmdd string passes through unchanged.
        assert_eq!(parse_jpki_date("weird"), "weird");
    }

    #[test]
    fn test_parse_jpki_flat_tlv_skips_padding_ff_at_end() {
        // Trailing 0xFF with nothing after it triggers the `i + 1 >= data.len()`
        // padding-skip branch.
        let data = [0x5A, 0x01, 0x42, 0xFF];
        let tlvs = parse_jpki_flat_tlv(&data);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x5A);
    }

    #[test]
    fn test_parse_jpki_flat_tlv_skips_padding_00() {
        let data = [0x00, 0x00, 0x5A, 0x01, 0x42];
        let tlvs = parse_jpki_flat_tlv(&data);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x5A);
        assert_eq!(tlvs[0].value, vec![0x42]);
    }

    #[test]
    fn test_parse_jpki_flat_tlv_long_length_form() {
        // Extended length: 0x81 0x02 => length = 2.
        let data = [0x5A, 0x81, 0x02, b'A', b'B'];
        let tlvs = parse_jpki_flat_tlv(&data);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].value, vec![b'A', b'B']);
    }

    #[test]
    fn test_parse_jpki_flat_tlv_truncated_value_falls_into_remaining_branch() {
        // Declares length 10 but provides only 2 bytes; parser returns the
        // truncated payload and exits.
        let data = [0x5A, 0x0A, 0xAA, 0xBB];
        let tlvs = parse_jpki_flat_tlv(&data);
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].value, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_extract_face_photo_none_when_absent() {
        // Data with no DF27, no JP2 signature.
        let data = vec![0xDF, 0x22, 0x01, 0xAA];
        assert!(extract_face_photo(&data).is_none());
    }

    #[test]
    fn test_extract_face_photo_finds_jp2_signature() {
        // Plant the 12-byte JPEG2000 signature at the end.
        let mut data = vec![0x00u8; 20];
        data.extend_from_slice(&[
            0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
        ]);
        data.extend_from_slice(&[0xDE, 0xAD]);
        let photo = extract_face_photo(&data).unwrap();
        assert!(photo.starts_with(&[0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20]));
    }

    #[test]
    fn test_extract_face_photo_finds_jp2_codestream_ff4f() {
        // Minimal fallback: direct JP2 codestream SOC marker.
        let mut data = vec![0x00u8; 5];
        data.push(0xFF);
        data.push(0x4F);
        data.extend_from_slice(&[0x12, 0x34]);
        let photo = extract_face_photo(&data).unwrap();
        assert!(photo.starts_with(&[0xFF, 0x4F]));
    }

    #[test]
    fn test_extract_face_photo_nested_container() {
        // Outer DF20 wraps an inner DF27.
        let inner = vec![0xDF, 0x27, 0x02, 0xAA, 0xBB];
        let mut outer = vec![0xDF, 0x20, inner.len() as u8];
        outer.extend_from_slice(&inner);
        let photo = extract_face_photo(&outer).unwrap();
        assert_eq!(photo, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_extract_face_photo_extended_length_81() {
        // DF27 with 0x81 extended length form.
        let data = vec![0xDF, 0x27, 0x81, 0x03, 0x01, 0x02, 0x03];
        let photo = extract_face_photo(&data).unwrap();
        assert_eq!(photo, vec![0x01, 0x02, 0x03]);
    }
}
