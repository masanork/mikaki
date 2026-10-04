//! Utility functions for TLV parsing, date handling, and character encoding.

use crate::errors::CivError;

/// BER-TLV object representing a tag-length-value structure.
#[derive(Debug, Clone)]
pub struct BerTlv {
    /// Tag number (may be multi-byte)
    pub tag: u32,
    /// Raw value bytes
    pub value: Vec<u8>,
    /// Child TLVs for constructed tags
    pub children: Vec<BerTlv>,
}

impl BerTlv {
    /// Convert value to UTF-8 string (lossy)
    pub fn as_utf8(&self) -> String {
        String::from_utf8_lossy(&self.value).to_string()
    }

    /// Find a child TLV by tag, recursively
    pub fn find_tag(&self, tag: u32) -> Option<&BerTlv> {
        if self.tag == tag {
            return Some(self);
        }
        for child in &self.children {
            if let Some(found) = child.find_tag(tag) {
                return Some(found);
            }
        }
        None
    }
}

/// Parse BER-TLV data with recursive support for constructed tags.
pub fn parse_ber_tlv(data: &[u8]) -> Result<Vec<BerTlv>, CivError> {
    let mut tlvs = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let first_tag_byte = data[i];
        let mut tag: u32 = first_tag_byte as u32;
        i += 1;

        // Multi-byte tag
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
            return Err(CivError::InvalidData("TLV length truncated".to_string()));
        }

        let first_len_byte = data[i];
        i += 1;

        let len: usize;
        if first_len_byte <= 0x7F {
            len = first_len_byte as usize;
        } else {
            let len_len = (first_len_byte & 0x7F) as usize;
            if i + len_len > data.len() {
                return Err(CivError::InvalidData("TLV length truncated".to_string()));
            }
            let mut l: usize = 0;
            for _ in 0..len_len {
                l = (l << 8) | (data[i] as usize);
                i += 1;
            }
            len = l;
        }

        if i + len > data.len() {
            return Err(CivError::InvalidData(format!(
                "TLV value length {} exceeds remaining data {}",
                len,
                data.len() - i
            )));
        }

        let value = &data[i..i + len];
        let mut children = Vec::new();

        // If constructed tag (bit 6 is 1), try parsing children
        if (first_tag_byte & 0x20) != 0 && len > 0 {
            if let Ok(c) = parse_ber_tlv(value) {
                children = c;
            }
        }

        tlvs.push(BerTlv {
            tag,
            value: value.to_vec(),
            children,
        });
        i += len;
    }

    Ok(tlvs)
}

/// Specialized BER-TLV parser for JPDL (supports multi-byte tags and linear sequence).
/// More lenient than standard BER-TLV parsing.
pub fn parse_jpdl_tlv(data: &[u8]) -> Result<Vec<BerTlv>, CivError> {
    let mut tlvs = Vec::new();
    let mut i = 0;

    while i < data.len() {
        let first_tag_byte = data[i];
        if first_tag_byte == 0 || first_tag_byte == 0xFF {
            i += 1;
            continue;
        }

        let mut tag: u32 = first_tag_byte as u32;
        i += 1;

        // Support multi-byte tags (e.g., 0x5F40). JPDL treats 0x1F as single-byte.
        if (first_tag_byte & 0x1F) == 0x1F && first_tag_byte != 0x1F {
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
            // Truncated or invalid length, but let's take what we can
            let remaining = data.len() - i;
            let value = &data[i..i + remaining];
            tlvs.push(BerTlv {
                tag,
                value: value.to_vec(),
                children: Vec::new(),
            });
            break;
        }

        let value = &data[i..i + len];
        tlvs.push(BerTlv {
            tag,
            value: value.to_vec(),
            children: Vec::new(),
        });
        i += len;
    }

    Ok(tlvs)
}

/// Parse the total length of a BER-TLV object from its header.
pub fn parse_tlv_total_length(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    let mut offset = 0usize;
    let first_tag = data[offset];
    offset += 1;

    if (first_tag & 0x1F) == 0x1F {
        while offset < data.len() && (data[offset] & 0x80) != 0 {
            offset += 1;
        }
        if offset < data.len() {
            offset += 1;
        }
    }

    if offset >= data.len() {
        return None;
    }

    let len_byte = data[offset];
    offset += 1;

    let content_len = if len_byte <= 0x7F {
        len_byte as usize
    } else if len_byte == 0x81 {
        if offset >= data.len() {
            return None;
        }
        let len = data[offset] as usize;
        offset += 1;
        len
    } else if len_byte == 0x82 {
        if offset + 1 >= data.len() {
            return None;
        }
        let len = ((data[offset] as usize) << 8) | data[offset + 1] as usize;
        offset += 2;
        len
    } else if len_byte == 0x83 {
        if offset + 2 >= data.len() {
            return None;
        }
        let len = ((data[offset] as usize) << 16)
            | ((data[offset + 1] as usize) << 8)
            | data[offset + 2] as usize;
        offset += 3;
        len
    } else {
        return None;
    };

    Some(offset + content_len)
}

/// Encode length in BER format.
pub fn encode_length(len: usize) -> Vec<u8> {
    if len <= 0x7F {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, ((len >> 8) & 0xFF) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

/// Decode Raw JIS X 0208 bytes to String using Shift-JIS conversion.
pub fn decode_jis_x0208(input: &[u8]) -> String {
    let sjis_data = convert_jis_to_sjis(input);
    let (res, _, _) = encoding_rs::SHIFT_JIS.decode(&sjis_data);
    res.into_owned()
}

/// Convert JIS X 0208 encoding to Shift-JIS encoding.
pub fn convert_jis_to_sjis(input: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();
    let mut i = 0;
    while i < input.len() {
        if i + 1 < input.len() {
            let c1 = input[i];
            let c2 = input[i + 1];

            // JIS X 0208 range: 0x21-0x7E
            if (0x21..=0x7E).contains(&c1) && (0x21..=0x7E).contains(&c2) {
                let mut s1 = (c1 - 0x21) / 2;
                if s1 <= 0x1E {
                    s1 += 0x81;
                } else {
                    s1 += 0xC1;
                }

                let mut s2 = c2;
                if !c1.is_multiple_of(2) {
                    s2 += 0x1F;
                } else {
                    s2 += 0x7D;
                }
                if s2 >= 0x7F {
                    s2 += 1;
                }

                res.push(s1);
                res.push(s2);
                i += 2;
                continue;
            }
        }
        // Treat as single byte
        res.push(input[i]);
        i += 1;
    }
    res
}

/// Decode Shift-JIS bytes to String with gaiji support.
pub fn decode_shift_jis(input: &[u8]) -> String {
    crate::gaiji::decode_gaiji_string(input)
}

/// MRZ (Machine Readable Zone) utilities for Passport.
pub struct MrzUtils;

impl MrzUtils {
    /// Calculate MRZ check digit.
    pub fn calculate_check_digit(s: &str) -> u8 {
        let weights = [7, 3, 1];
        let mut sum = 0u32;
        for (i, c) in s.chars().enumerate() {
            let val = match c {
                '0'..='9' => c as u32 - '0' as u32,
                'A'..='Z' => c as u32 - 'A' as u32 + 10,
                '<' | ' ' => 0,
                _ => 0,
            };
            sum += val * weights[i % 3];
        }
        (sum % 10) as u8 + b'0'
    }

    /// Extract MRZ key material for BAC (doc number + DOB + expiry).
    pub fn extract_bac_key_material(mrz: &str) -> Option<String> {
        let lines: Vec<&str> = mrz.lines().collect();
        if lines.len() < 2 {
            return None;
        }
        let line2 = lines[1];
        if line2.len() < 28 {
            return None;
        }
        // Document number (0-9) + check digit + DOB (13-18) + check digit + expiry (21-26) + check digit
        let doc_no = &line2[0..9];
        let doc_check = &line2[9..10];
        let dob = &line2[13..19];
        let dob_check = &line2[19..20];
        let expiry = &line2[21..27];
        let expiry_check = &line2[27..28];

        Some(format!(
            "{}{}{}{}{}{}",
            doc_no, doc_check, dob, dob_check, expiry, expiry_check
        ))
    }
}

/// Date parsing utilities for Smart Cards.
pub struct DateUtils;

impl DateUtils {
    /// Parse YYMMDD format (used in Passport MRZ).
    pub fn parse_yymmdd(s: &str) -> Result<String, CivError> {
        if s.len() != 6 {
            return Err(CivError::InvalidData("Invalid date length".to_string()));
        }
        let year_short: i32 = s[0..2]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid year".to_string()))?;
        let month: i32 = s[2..4]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid month".to_string()))?;
        let day: i32 = s[4..6]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid day".to_string()))?;

        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return Err(CivError::InvalidData("Invalid date components".to_string()));
        }

        let mut year = 2000 + year_short;
        let current_year = current_year_utc();
        if year > current_year {
            year -= 100;
        }

        Ok(format!("{:04}-{:02}-{:02}", year, month, day))
    }

    /// Parse YYMMDD as expiration date (prefer near-future dates).
    pub fn parse_yymmdd_expiration(s: &str) -> Result<String, CivError> {
        if s.len() != 6 {
            return Err(CivError::InvalidData("Invalid date length".to_string()));
        }
        let year_short: i32 = s[0..2]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid year".to_string()))?;
        let month: i32 = s[2..4]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid month".to_string()))?;
        let day: i32 = s[4..6]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid day".to_string()))?;

        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return Err(CivError::InvalidData("Invalid date components".to_string()));
        }

        let mut year = 2000 + year_short;
        let current_year = current_year_utc();
        if year < current_year - 10 {
            year += 100;
        }
        if year > current_year + 30 {
            year -= 100;
        }

        Ok(format!("{:04}-{:02}-{:02}", year, month, day))
    }

    /// Parse YYYYMMDD format (used in JPKI/Drivers License).
    pub fn parse_yyyymmdd(s: &str) -> Result<String, CivError> {
        if s.len() != 8 {
            return Err(CivError::InvalidData("Invalid date length".to_string()));
        }
        let year: u32 = s[0..4]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid year".to_string()))?;
        let month: u32 = s[4..6]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid month".to_string()))?;
        let day: u32 = s[6..8]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid day".to_string()))?;

        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return Err(CivError::InvalidData("Invalid date components".to_string()));
        }

        Ok(format!("{:04}-{:02}-{:02}", year, month, day))
    }

    /// Parse Japanese Era date format (used in Drivers License / JPKI).
    /// Format: [Era(1)] YYMMDD
    /// Eras: 1: Meiji, 2: Taisho, 3: Showa, 4: Heisei, 5: Reiwa
    pub fn parse_japanese_era(s: &str) -> Result<String, CivError> {
        if s.len() != 7 {
            return Err(CivError::InvalidData(
                "Invalid Japanese era date length".to_string(),
            ));
        }
        let era = &s[0..1];
        let year_short: u32 = s[1..3]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid year".to_string()))?;
        let month: u32 = s[3..5]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid month".to_string()))?;
        let day: u32 = s[5..7]
            .parse()
            .map_err(|_| CivError::InvalidData("Invalid day".to_string()))?;

        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return Err(CivError::InvalidData("Invalid date components".to_string()));
        }

        let era_base = match era {
            "1" => 1867, // Meiji
            "2" => 1911, // Taisho
            "3" => 1925, // Showa
            "4" => 1988, // Heisei
            "5" => 2018, // Reiwa
            _ => return Err(CivError::InvalidData(format!("Unknown era code: {}", era))),
        };

        Ok(format!(
            "{:04}-{:02}-{:02}",
            era_base + year_short,
            month,
            day
        ))
    }

    /// Format date as Japanese era format for display.
    pub fn format_japanese_era(gengou_date: &str) -> String {
        if gengou_date.len() != 7 {
            return gengou_date.to_string();
        }
        let era = &gengou_date[0..1];
        let yy = &gengou_date[1..3];
        let mm = &gengou_date[3..5];
        let dd = &gengou_date[5..7];

        let era_name = match era {
            "1" => "明治",
            "2" => "大正",
            "3" => "昭和",
            "4" => "平成",
            "5" => "令和",
            _ => return gengou_date.to_string(),
        };

        format!("{}{}年{}月{}日", era_name, yy, mm, dd)
    }
}

/// Get current year in UTC.
fn current_year_utc() -> i32 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = secs / 86_400;

    // Civil days from Unix epoch using algorithm from Howard Hinnant
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    year as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ber_tlv_basic() {
        let data = [0x01, 0x02, 0xAA, 0xBB];
        let tlvs = parse_ber_tlv(&data).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x01);
        assert_eq!(tlvs[0].value, &[0xAA, 0xBB]);
    }

    #[test]
    fn test_parse_ber_tlv_error() {
        let data = [0x01, 0x05, 0xAA]; // Length 5 but only 1 byte data
        assert!(parse_ber_tlv(&data).is_err());
    }

    #[test]
    fn test_parse_ber_tlv_recursive() {
        // Tag 0x30 (Sequence), Len 5, Value [Tag 0x01, Len 1, Val 0xAA, Tag 0x02, Len 0]
        let data = [0x30, 0x05, 0x01, 0x01, 0xAA, 0x02, 0x00];
        let tlvs = parse_ber_tlv(&data).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x30);
        assert_eq!(tlvs[0].children.len(), 2);
        assert_eq!(tlvs[0].children[0].tag, 0x01);
        assert_eq!(tlvs[0].children[1].tag, 0x02);
    }

    #[test]
    fn test_mrz_check_digit() {
        assert_eq!(MrzUtils::calculate_check_digit("12345678"), b'8');
        assert_eq!(MrzUtils::calculate_check_digit("HA672242"), b'6');
    }

    #[test]
    fn test_date_parsing_yyyymmdd() {
        assert_eq!(DateUtils::parse_yyyymmdd("19900101").unwrap(), "1990-01-01");
        assert_eq!(DateUtils::parse_yyyymmdd("20231231").unwrap(), "2023-12-31");
        assert!(DateUtils::parse_yyyymmdd("20231301").is_err());
        assert!(DateUtils::parse_yyyymmdd("ABCD1234").is_err());
    }

    #[test]
    fn test_date_parsing_yymmdd() {
        assert_eq!(DateUtils::parse_yymmdd("900101").unwrap(), "1990-01-01");
        assert_eq!(DateUtils::parse_yymmdd("200101").unwrap(), "2020-01-01");
        assert!(DateUtils::parse_yymmdd("901301").is_err());
    }

    #[test]
    fn test_japanese_era_parsing() {
        assert_eq!(
            DateUtils::parse_japanese_era("4010101").unwrap(),
            "1989-01-01"
        ); // Heisei
        assert_eq!(
            DateUtils::parse_japanese_era("5010501").unwrap(),
            "2019-05-01"
        ); // Reiwa
        assert!(DateUtils::parse_japanese_era("6010101").is_err());
    }

    #[test]
    fn test_japanese_era_format() {
        assert_eq!(
            DateUtils::format_japanese_era("4010115"),
            "平成01年01月15日"
        );
        assert_eq!(
            DateUtils::format_japanese_era("5060501"),
            "令和06年05月01日"
        );
    }

    #[test]
    fn test_encode_length() {
        assert_eq!(encode_length(0), vec![0x00]);
        assert_eq!(encode_length(127), vec![0x7F]);
        assert_eq!(encode_length(128), vec![0x81, 0x80]);
        assert_eq!(encode_length(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_jis_to_sjis_conversion() {
        // Test a simple kanji conversion
        // JIS X 0208: 0x3B 0x7A = 字
        let jis_data = [0x3B, 0x7A];
        let sjis = convert_jis_to_sjis(&jis_data);
        assert!(!sjis.is_empty());
    }

    #[test]
    fn test_ber_tlv_as_utf8() {
        let tlv = BerTlv {
            tag: 0x01,
            value: b"Hello".to_vec(),
            children: vec![],
        };
        assert_eq!(tlv.as_utf8(), "Hello");
    }

    #[test]
    fn test_parse_jpdl_tlv() {
        // Simple TLV: tag 0x12, length 0x02, value [0xAA, 0xBB]
        let data = [0x12, 0x02, 0xAA, 0xBB];
        let tlvs = parse_jpdl_tlv(&data).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].tag, 0x12);
        assert_eq!(tlvs[0].value, vec![0xAA, 0xBB]);
    }
}
