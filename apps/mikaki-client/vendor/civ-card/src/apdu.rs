//! ISO 7816-4 APDU encoding and decoding.

/// ISO 7816-4 class byte
pub const CLA_ISO: u8 = 0x00;

/// ISO 7816-4 instruction codes
pub const INS_SELECT_FILE: u8 = 0xA4;
pub const INS_READ_BINARY: u8 = 0xB0;
pub const INS_VERIFY: u8 = 0x20;
pub const INS_COMPUTE_DIGITAL_SIGNATURE: u8 = 0x2A;
pub const INS_GET_RESPONSE: u8 = 0xC0;
pub const INS_EXTERNAL_AUTHENTICATE: u8 = 0x82;
pub const INS_GET_CHALLENGE: u8 = 0x84;

/// ISO 7816-4 GET DATA instruction (used for card metadata, CPLC, etc.)
pub const INS_GET_DATA: u8 = 0xCA;

/// VERIFY P2 (key reference) for the Input Support AP 4-digit secret PIN
/// (券面事項入力補助用暗証番号). Selected via EF_INPUT_SUPPORT_PIN first.
pub const P2_VERIFY_PIN: u8 = 0x80;

/// VERIFY P2 (key reference) for 照合番号B in the Input Support AP.
///
/// 照合番号B is the non-secret 14-digit value printed on the card face
/// (生年月日6 + 有効期限4 + セキュリティコード4). Verifying it unlocks the
/// basic-4-info file (EF_ATTRIBUTES / EF 0002) as text, without the secret
/// 4-digit PIN. Unlike the PIN, this VERIFY requires **no** prior EF SELECT —
/// P2=0x95 directly designates the 照合番号B key reference within the AP.
pub const P2_VERIFY_NUMBER_B: u8 = 0x95;

/// VERIFY P2 (key reference) for the マイナ免許証 (MyNa-Menkyo) AP PIN.
/// The 4-digit numeric PIN protects WEF02 and WEF03 within the Jpdlmnc AP.
pub const P2_VERIFY_JPDLMNC: u8 = 0x82;

/// GlobalPlatform GET STATUS instruction
pub const INS_GET_STATUS: u8 = 0xF2;

/// ISO 7816-4 GENERAL AUTHENTICATE (used for PACE rounds)
pub const INS_GENERAL_AUTHENTICATE: u8 = 0x86;
/// ISO 7816-4 MANAGE SECURITY ENVIRONMENT (MSE:Set AT for PACE)
pub const INS_MSE: u8 = 0x22;

/// File IDs for various Japanese IC cards (JPKI, JPDL)
pub mod file_ids {
    /// JPKI Authentication Application DF (My Number Card)
    pub const DF_JPKI: [u8; 10] = [0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01];

    /// JPKI Input Support Application DF
    pub const DF_INPUT_SUPPORT: [u8; 10] =
        [0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08];

    /// JPKI Surface (Face Photo) Application DF
    pub const DF_SURFACE: [u8; 10] = [0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x02];

    /// Authentication PIN EF (in DF_JPKI)
    pub const EF_AUTH_PIN: [u8; 2] = [0x00, 0x18];

    /// Digital Signature PIN EF (in DF_JPKI)
    pub const EF_SIGN_PIN: [u8; 2] = [0x00, 0x1B];

    /// Authentication Private Key EF (in DF_JPKI)
    pub const EF_AUTH_KEY: [u8; 2] = [0x00, 0x17];

    /// Digital Signature Private Key EF (in DF_JPKI)
    pub const EF_SIGN_KEY: [u8; 2] = [0x00, 0x1A];

    /// Authentication Certificate EF (in DF_JPKI)
    pub const EF_AUTH_CERT: [u8; 2] = [0x00, 0x0A];

    /// Digital Signature Certificate EF (in DF_JPKI)
    pub const EF_SIGN_CERT: [u8; 2] = [0x00, 0x01];

    /// Digital Signature CA (intermediate) Certificate EF (in DF_JPKI).
    ///
    /// Per J-LIS 公的個人認証サービス仕様書, the DF_JPKI application
    /// exposes the intermediate CA that issued `EF_SIGN_CERT` at file
    /// identifier `0x0002`. Reading it requires no PIN — CA
    /// certificates are public material. Used by
    /// `JpkiAsync::read_sign_cert_chain` / FR-019 (civ ships the full
    /// chain; consumer holds only the J-LIS root).
    pub const EF_SIGN_CA_CERT: [u8; 2] = [0x00, 0x02];

    /// Authentication CA (intermediate) Certificate EF (in DF_JPKI).
    /// Analogous to EF_SIGN_CA_CERT for the auth cert; returned by
    /// `JpkiAsync::read_auth_cert_chain`.
    pub const EF_AUTH_CA_CERT: [u8; 2] = [0x00, 0x0B];

    /// Input Support PIN EF (in DF_INPUT_SUPPORT)
    pub const EF_INPUT_SUPPORT_PIN: [u8; 2] = [0x00, 0x11];

    /// My Number EF (in DF_INPUT_SUPPORT)
    pub const EF_MYNUMBER: [u8; 2] = [0x00, 0x01];

    /// Attributes (Basic Info) EF (in DF_INPUT_SUPPORT)
    pub const EF_ATTRIBUTES: [u8; 2] = [0x00, 0x02];

    /// Surface PIN EF (in DF_SURFACE) - My Number used as PIN
    pub const EF_SURFACE_PIN: [u8; 2] = [0x00, 0x13];

    /// Surface Basic Info + Photo EF (in DF_SURFACE) - Contains FF20 container (DF21-DF2A)
    pub const EF_SURFACE_DATA: [u8; 2] = [0x00, 0x02];

    /// Face Photo EF (in DF_SURFACE) - Same as EF_SURFACE_DATA (EF 0002)
    pub const EF_FACE_PHOTO: [u8; 2] = [0x00, 0x02];

    /// Surface Issuer Info EF (in DF_SURFACE) - Contains FF30 container (DF31-DF35)
    pub const EF_SURFACE_ISSUER: [u8; 2] = [0x00, 0x03];

    /// Surface CV Certificate EF (in DF_SURFACE) - Contains 7F21 (5F4E body + 5F37 signature)
    pub const EF_SURFACE_CV_CERT: [u8; 2] = [0x00, 0x04];

    /// Surface Additional Data EF (in DF_SURFACE) - Contains FF40 container (DF41-DF43)
    pub const EF_SURFACE_ADDITIONAL: [u8; 2] = [0x00, 0x05];

    /// Signature Image EF (in DF_SURFACE)
    pub const EF_SIGNATURE_IMAGE: [u8; 2] = [0x00, 0x03];

    /// Face Text EF (in DF_SURFACE)
    pub const EF_FACE_TEXT: [u8; 2] = [0x00, 0x01];

    // ── マイナ免許証 (MyNa-Menkyo / Jpdlmnc) ─────────────────────────────

    /// Jpdlmnc Instance AID (16 bytes, starts with 0x06)
    /// Reference: 運転免許証及び運転免許証作成システム等仕様書 section 2
    pub const DF_JPDLMNC: [u8; 16] = [
        0xA0, 0x00, 0x00, 0x02, 0x31, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];

    /// Jpdlmnc IEF01: PIN (4 digits)
    pub const IEF_JPDLMNC_PIN: [u8; 2] = [0x00, 0x06];

    /// Jpdlmnc WEF01: PIN Setting status (C1 tag: 01 = PIN set, 00 = not set)
    pub const WEF_JPDLMNC_PIN_STATUS: [u8; 2] = [0x00, 0x1A];

    /// Jpdlmnc WEF02: License and Driver History Information (BER-TLV, tags C2–107)
    pub const WEF_JPDLMNC_LICENSE_INFO: [u8; 2] = [0x00, 0x1B];

    /// Jpdlmnc WEF03: Electronic Signature over WEF02 (SHA-256 + RSA-2048 PKCS#1 v1.5)
    pub const WEF_JPDLMNC_SIGNATURE: [u8; 2] = [0x00, 0x1C];
}

/// APDU command structure.
#[derive(Debug, Clone)]
pub struct ApduCommand {
    /// Class byte
    pub cla: u8,
    /// Instruction byte
    pub ins: u8,
    /// Parameter 1
    pub p1: u8,
    /// Parameter 2
    pub p2: u8,
    /// Command data
    pub data: Vec<u8>,
    /// Expected response length (Le)
    pub le: Option<u16>,
}

impl ApduCommand {
    /// Create a new APDU command.
    pub fn new(cla: u8, ins: u8, p1: u8, p2: u8) -> Self {
        Self {
            cla,
            ins,
            p1,
            p2,
            data: Vec::new(),
            le: None,
        }
    }

    /// Create a SELECT command.
    pub fn select(aid: &[u8]) -> Self {
        Self {
            cla: 0x00,
            ins: 0xA4,
            p1: 0x04,
            p2: 0x00,
            data: aid.to_vec(),
            le: None,
        }
    }

    /// Create a READ BINARY command.
    pub fn read_binary(p1: u8, p2: u8, le: u16) -> Self {
        Self {
            cla: 0x00,
            ins: 0xB0,
            p1,
            p2,
            data: Vec::new(),
            le: Some(le),
        }
    }

    /// Create a READ BINARY command with extended length.
    pub fn read_binary_extended(p1: u8, p2: u8, le: u16) -> Self {
        Self {
            cla: 0x00,
            ins: 0xB0,
            p1,
            p2,
            data: Vec::new(),
            le: Some(le),
        }
    }

    /// Create a VERIFY command.
    pub fn verify(p2: u8, pin: &[u8]) -> Self {
        Self {
            cla: 0x00,
            ins: 0x20,
            p1: 0x00,
            p2,
            data: pin.to_vec(),
            le: None,
        }
    }

    /// Create a GET RESPONSE command.
    pub fn get_response(le: u8) -> Self {
        Self {
            cla: 0x00,
            ins: 0xC0,
            p1: 0x00,
            p2: 0x00,
            data: Vec::new(),
            le: Some(le as u16),
        }
    }

    /// Set command data.
    pub fn with_data(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }

    /// Set expected response length.
    pub fn with_le(mut self, le: u16) -> Self {
        self.le = Some(le);
        self
    }

    /// Parse from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 4 {
            return Err("APDU too short");
        }
        let cla = bytes[0];
        let ins = bytes[1];
        let p1 = bytes[2];
        let p2 = bytes[3];

        if bytes.len() == 4 {
            // No data, no Le
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: None,
            });
        }

        if bytes.len() == 5 {
            // Le only
            let le = if bytes[4] == 0 { 256 } else { bytes[4] as u16 };
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data: Vec::new(),
                le: Some(le),
            });
        }

        let lc = bytes[4] as usize;
        if lc == 0 {
            // Extended length
            if bytes.len() < 7 {
                return Err("Extended APDU too short");
            }
            let ext_len = ((bytes[5] as usize) << 8) | (bytes[6] as usize);
            if bytes.len() < 7 + ext_len {
                return Err("Extended APDU data too short");
            }
            let data = bytes[7..7 + ext_len].to_vec();
            let le = if bytes.len() > 7 + ext_len {
                let le_start = 7 + ext_len;
                if bytes.len() >= le_start + 2 {
                    let le_val = ((bytes[le_start] as u16) << 8) | (bytes[le_start + 1] as u16);
                    Some(le_val) // 0 means 65536 in extended APDU
                } else if bytes.len() == le_start + 1 {
                    let le_val = bytes[le_start] as u16;
                    Some(if le_val == 0 { 256 } else { le_val })
                } else {
                    None
                }
            } else {
                None
            };
            return Ok(Self {
                cla,
                ins,
                p1,
                p2,
                data,
                le,
            });
        }

        // Short length
        if bytes.len() < 5 + lc {
            return Err("APDU data too short");
        }
        let data = bytes[5..5 + lc].to_vec();
        let le = if bytes.len() > 5 + lc {
            let le_val = bytes[5 + lc] as u16;
            Some(if le_val == 0 { 256 } else { le_val })
        } else {
            None
        };

        Ok(Self {
            cla,
            ins,
            p1,
            p2,
            data,
            le,
        })
    }

    /// Convert to bytes for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.cla, self.ins, self.p1, self.p2];

        let is_extended = self.data.len() > 255 || self.le.is_some_and(|le| le > 256);

        if is_extended {
            // Extended length APDU
            if !self.data.is_empty() {
                bytes.push(0x00); // Extended length marker
                bytes.push((self.data.len() >> 8) as u8);
                bytes.push((self.data.len() & 0xFF) as u8);
                bytes.extend(&self.data);
            }
            if let Some(le) = self.le {
                if self.data.is_empty() {
                    bytes.push(0x00); // Extended length marker
                }
                bytes.push((le >> 8) as u8);
                bytes.push((le & 0xFF) as u8);
            }
        } else {
            // Short length APDU
            if !self.data.is_empty() {
                bytes.push(self.data.len() as u8);
                bytes.extend(&self.data);
            }
            if let Some(le) = self.le {
                if le == 256 {
                    bytes.push(0x00);
                } else {
                    bytes.push(le as u8);
                }
            }
        }

        bytes
    }
}

/// APDU response structure.
#[derive(Debug, Clone)]
pub struct ApduResponse {
    /// Response data
    data: Vec<u8>,
    /// Status word 1
    sw1: u8,
    /// Status word 2
    sw2: u8,
}

impl ApduResponse {
    /// Parse response from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 2 {
            return Self {
                data: Vec::new(),
                sw1: 0x6F,
                sw2: 0x00,
            };
        }

        let sw_start = bytes.len() - 2;
        Self {
            data: bytes[..sw_start].to_vec(),
            sw1: bytes[sw_start],
            sw2: bytes[sw_start + 1],
        }
    }

    /// Get response data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get SW1 (Status Word 1).
    pub fn sw1(&self) -> u8 {
        self.sw1
    }

    /// Get SW2 (Status Word 2).
    pub fn sw2(&self) -> u8 {
        self.sw2
    }

    /// Get status word as u16.
    pub fn status_word(&self) -> u16 {
        ((self.sw1 as u16) << 8) | (self.sw2 as u16)
    }

    /// Check if response indicates success (9000).
    pub fn is_success(&self) -> bool {
        self.sw1 == 0x90 && self.sw2 == 0x00
    }

    /// Check if response indicates more data available (61XX).
    pub fn has_more_data(&self) -> bool {
        self.sw1 == 0x61
    }

    /// Get the amount of remaining data if more is available.
    pub fn remaining_data_length(&self) -> Option<u8> {
        if self.has_more_data() {
            Some(self.sw2)
        } else {
            None
        }
    }

    /// Check if response indicates wrong length (6CXX).
    pub fn is_wrong_length(&self) -> bool {
        self.sw1 == 0x6C
    }

    /// Get correct length if wrong length response.
    pub fn correct_length(&self) -> Option<u8> {
        if self.is_wrong_length() {
            Some(self.sw2)
        } else {
            None
        }
    }

    /// Check if PIN is blocked (6983).
    pub fn is_pin_blocked(&self) -> bool {
        self.sw1 == 0x69 && self.sw2 == 0x83
    }

    /// Check if wrong PIN was entered (63CX).
    pub fn is_wrong_pin(&self) -> bool {
        self.sw1 == 0x63 && (self.sw2 & 0xF0) == 0xC0
    }

    /// Get remaining PIN retries if wrong PIN.
    pub fn remaining_retries(&self) -> Option<u8> {
        if self.is_wrong_pin() {
            Some(self.sw2 & 0x0F)
        } else {
            None
        }
    }
}

/// Convenience type alias
pub type Apdu = ApduCommand;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_command() {
        let cmd = ApduCommand::select(&[0xA0, 0x00, 0x00, 0x00, 0x01]);
        let bytes = cmd.to_bytes();
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0xA4);
    }

    #[test]
    fn test_response_success() {
        let response = ApduResponse::from_bytes(&[0x01, 0x02, 0x90, 0x00]);
        assert!(response.is_success());
        assert_eq!(response.data(), &[0x01, 0x02]);
    }
}
