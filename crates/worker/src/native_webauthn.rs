//! Android WebView app mode uses the APK signing-key origin, not a browser origin.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn android_origin(fingerprint: &str) -> Option<String> {
    let parts = fingerprint.split(':').collect::<Vec<_>>();
    if parts.len() != 32
        || parts
            .iter()
            .any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    let bytes = parts
        .iter()
        .map(|p| u8::from_str_radix(p, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    Some(format!(
        "android:apk-key-hash:{}",
        URL_SAFE_NO_PAD.encode(bytes)
    ))
}

fn select_origin(
    issuer: &str,
    fingerprint: Option<&str>,
    client_data: &str,
    max_bytes: usize,
) -> String {
    let selected = (|| {
        let expected = android_origin(fingerprint?)?;
        if client_data.len() > max_bytes {
            return None;
        }
        let decoded = URL_SAFE_NO_PAD.decode(client_data).ok()?;
        let json = std::str::from_utf8(&decoded).ok()?;
        mikaki_webauthn::strict_json(json, max_bytes, 16).ok()?;
        let value: serde_json::Value = serde_json::from_str(json).ok()?;
        (value.get("origin")?.as_str()? == expected).then_some(expected)
    })();
    // This selects a pinned policy, not a verified response. The normal WebAuthn
    // verifier must still check signature, challenge, RP ID, UV and replay state.
    selected.unwrap_or_else(|| issuer.to_owned())
}

#[cfg(target_arch = "wasm32")]
pub(super) fn origin(
    env: &worker::Env,
    issuer: &str,
    client_data: &str,
    max_bytes: usize,
) -> String {
    let fingerprint = env
        .var("MIKAKI_ANDROID_SHA256_CERT_FINGERPRINT")
        .ok()
        .map(|v| v.to_string());
    select_origin(issuer, fingerprint.as_deref(), client_data, max_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_pinned_apk_can_select_a_native_origin() {
        let fingerprint = ["AB"; 32].join(":");
        let expected = android_origin(&fingerprint).unwrap();
        let encode = |origin: &str| {
            URL_SAFE_NO_PAD.encode(serde_json::json!({"origin": origin}).to_string())
        };
        let issuer = "https://auth.example";
        assert_eq!(
            select_origin(issuer, Some(&fingerprint), &encode(&expected), 4096),
            expected
        );
        for origin in [
            issuer,
            "https://evil.example",
            "android:apk-key-hash:untrusted",
        ] {
            assert_eq!(
                select_origin(issuer, Some(&fingerprint), &encode(origin), 4096),
                issuer
            );
        }
        assert_eq!(
            select_origin(issuer, None, &encode(&expected), 4096),
            issuer
        );
        assert_eq!(
            select_origin(issuer, Some("AB:CD"), &encode(&expected), 4096),
            issuer
        );
        assert!(android_origin(&["+1"; 32].join(":")).is_none());
        assert_eq!(
            select_origin(issuer, Some(&fingerprint), &encode(&expected), 8),
            issuer
        );
        let duplicate = URL_SAFE_NO_PAD.encode(format!(
            r#"{{"origin":"https://evil.example","origin":"{expected}"}}"#
        ));
        assert_eq!(
            select_origin(issuer, Some(&fingerprint), &duplicate, 4096),
            issuer
        );
    }
}
