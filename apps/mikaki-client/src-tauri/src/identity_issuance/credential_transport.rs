//! Native transport envelope; credential authenticity is checked by the caller.
use mikaki_identity::issuance_encryption::WalletEncryption;
use serde_json::Value;

pub(super) fn decode_success(
    content_type: &str,
    wire: &[u8],
    encryption: Option<&WalletEncryption>,
) -> Result<Value, String> {
    let media = content_type.split(';').next().unwrap_or("").trim();
    let value = if let Some(encryption) = encryption {
        if !media.eq_ignore_ascii_case("application/jwt") {
            return Err("invalid_response".into());
        }
        let compact = std::str::from_utf8(wire).map_err(|_| "invalid_response")?;
        let plain = encryption
            .decrypt_response(compact)
            .map_err(|_| "invalid_response")?;
        serde_json::from_slice(&plain).map_err(|_| "invalid_response")?
    } else {
        if !media.eq_ignore_ascii_case("application/json") || wire.len() > 48 * 1024 {
            return Err("invalid_response".into());
        }
        serde_json::from_slice(wire).map_err(|_| "invalid_response")?
    };
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn encrypted_native_envelope_checks_media_binding_and_independent_compression() {
        let f: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../crates/identity/tests/fixtures/wallet-jwe.json"
        )))
        .unwrap();
        for v in f["vectors"].as_array().unwrap() {
            let metadata = json!({"credential_request_encryption":{"jwks":{"keys":[f["requestJwk"]]},"enc_values_supported":[v["enc"]],"encryption_required":false},"credential_response_encryption":{"alg_values_supported":["ECDH-ES"],"enc_values_supported":[v["enc"]],"encryption_required":false,"zip_values_supported":["DEF"]}});
            let wallet = WalletEncryption::from_metadata(&metadata, [0x22; 32], "native-fixture")
                .unwrap()
                .unwrap();
            let bytes = v["jwe"].as_str().unwrap().as_bytes();
            assert_eq!(
                decode_success("Application/JWT; charset=utf-8", bytes, Some(&wallet)).unwrap(),
                f["payload"]
            );
            assert!(decode_success("application/json", bytes, Some(&wallet)).is_err());
            assert!(decode_success(
                "application/jwt",
                f["payload"].to_string().as_bytes(),
                Some(&wallet)
            )
            .is_err());
            assert!(decode_success("application/jwt", bytes, None).is_err());
        }
    }
    #[test]
    fn plain_native_envelope_remains_bounded_and_rejects_wrong_content_type() {
        assert_eq!(
            decode_success("application/json", b"{}", None).unwrap(),
            json!({})
        );
        assert!(decode_success("text/html", b"{}", None).is_err());
        assert!(decode_success("application/json", &vec![b' '; 48 * 1024 + 1], None).is_err());
    }
}
