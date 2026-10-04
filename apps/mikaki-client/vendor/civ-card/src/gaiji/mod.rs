//! Japanese external character (gaiji) handling.

use once_cell::sync::Lazy;
use std::collections::HashMap;

/// Gaiji mapping table for NPA characters.
static GAIJI_MAP: Lazy<HashMap<u16, char>> = Lazy::new(|| {
    let mut map = HashMap::new();
    // Add common gaiji mappings
    // These are placeholder mappings - actual NPA gaiji codes would go here
    map.insert(0x8740, '\u{2460}'); // Circled digit one
    map.insert(0x8741, '\u{2461}'); // Circled digit two
                                    // ... more mappings would be added
    map
});

/// Convert Shift-JIS bytes with gaiji to UTF-8 string.
pub fn decode_with_gaiji(bytes: &[u8]) -> String {
    // First try standard Shift-JIS decoding
    let (cow, _, had_errors) = encoding_rs::SHIFT_JIS.decode(bytes);

    if !had_errors {
        return cow.to_string();
    }

    // If there were errors, try to handle gaiji
    let mut result = String::new();
    let mut i = 0;

    while i < bytes.len() {
        if i + 1 < bytes.len() {
            let code = ((bytes[i] as u16) << 8) | (bytes[i + 1] as u16);
            if let Some(&ch) = GAIJI_MAP.get(&code) {
                result.push(ch);
                i += 2;
                continue;
            }
        }

        // Try standard decoding for this byte
        let (decoded, _, _) = encoding_rs::SHIFT_JIS.decode(&bytes[i..i + 1]);
        result.push_str(&decoded);
        i += 1;
    }

    result
}

/// Convert UTF-8 string to Shift-JIS with gaiji handling.
pub fn encode_with_gaiji(text: &str) -> Vec<u8> {
    let (cow, _, _) = encoding_rs::SHIFT_JIS.encode(text);
    cow.to_vec()
}

/// Alias for decode_with_gaiji for compatibility.
pub fn decode_gaiji_string(bytes: &[u8]) -> String {
    decode_with_gaiji(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_shift_jis() {
        let bytes = encoding_rs::SHIFT_JIS.encode("テスト").0;
        let decoded = decode_with_gaiji(&bytes);
        assert_eq!(decoded, "テスト");
    }

    #[test]
    fn test_decode_gaiji_string_alias_matches_decode_with_gaiji() {
        let bytes = encoding_rs::SHIFT_JIS.encode("ABC").0;
        assert_eq!(decode_gaiji_string(&bytes), decode_with_gaiji(&bytes));
    }

    #[test]
    fn test_encode_with_gaiji_roundtrips_ascii() {
        let bytes = encode_with_gaiji("hello");
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn test_encode_decode_roundtrip_japanese() {
        let text = "こんにちは";
        let encoded = encode_with_gaiji(text);
        let decoded = decode_with_gaiji(&encoded);
        assert_eq!(decoded, text);
    }

    #[test]
    fn test_decode_with_gaiji_hits_mapped_code() {
        // GAIJI_MAP has 0x8740 -> '①'. Must trigger the error path in encoding_rs
        // so the lookup branch runs, so combine with a trailing invalid byte.
        // The bytes 0x87 0x40 on their own decode successfully as Shift-JIS
        // (they map to a Unicode PUA), so add an invalid byte to force the
        // had_errors branch.
        let bytes = vec![0x87, 0x40, 0xFD];
        let decoded = decode_with_gaiji(&bytes);
        // The output should contain our mapped circled-1 character.
        assert!(decoded.contains('\u{2460}'));
    }

    #[test]
    fn test_decode_with_gaiji_unknown_bytes_fall_through() {
        // An invalid Shift-JIS byte not in the gaiji map exercises the
        // single-byte fallback branch.
        let bytes = vec![0xFD];
        let decoded = decode_with_gaiji(&bytes);
        // Whatever the fallback produces, it must be non-empty and not panic.
        assert!(!decoded.is_empty());
    }
}
