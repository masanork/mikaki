//! OS association documents for the signed mobile native client.

const APP_ID: &str = "app.tossa.mikaki";
const CALLBACK_PATH: &str = "/oidc/native/callback";

fn apple_document(team_id: &str) -> Option<serde_json::Value> {
    if team_id.len() != 10
        || !team_id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return None;
    }
    Some(serde_json::json!({
        "applinks": {
            "details": [{
                "appIDs": [format!("{team_id}.{APP_ID}")],
                "components": [{"/": CALLBACK_PATH}]
            }]
        }
    }))
}

fn android_document(fingerprint: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = fingerprint.split(':').collect();
    if parts.len() != 32
        || !parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(serde_json::json!([{
        "relation": ["delegate_permission/common.handle_all_urls"],
        "target": {
            "namespace": "android_app",
            "package_name": APP_ID,
            "sha256_cert_fingerprints": [fingerprint.to_ascii_uppercase()]
        }
    }]))
}

#[cfg(target_arch = "wasm32")]
pub fn apple_for_env(env: &worker::Env) -> worker::Result<worker::Response> {
    let document = env
        .var("MIKAKI_IOS_TEAM_ID")
        .ok()
        .and_then(|value| apple_document(&value.to_string()));
    association_response(document)
}

#[cfg(target_arch = "wasm32")]
pub fn android_for_env(env: &worker::Env) -> worker::Result<worker::Response> {
    let document = env
        .var("MIKAKI_ANDROID_SHA256_CERT_FINGERPRINT")
        .ok()
        .and_then(|value| android_document(&value.to_string()));
    association_response(document)
}

#[cfg(target_arch = "wasm32")]
fn association_response(document: Option<serde_json::Value>) -> worker::Result<worker::Response> {
    match document {
        Some(document) => worker::Response::builder()
            .with_header("Cache-Control", "public, max-age=300")?
            .from_json(&document),
        None => worker::Response::error("not found", 404),
    }
}

#[cfg(test)]
mod tests {
    use super::{android_document, apple_document};

    #[test]
    fn apple_association_is_exact() {
        let document = apple_document("ABCDEFGHIJ").unwrap();
        assert_eq!(
            document["applinks"]["details"][0]["appIDs"][0],
            "ABCDEFGHIJ.app.tossa.mikaki"
        );
        assert_eq!(
            document["applinks"]["details"][0]["components"][0]["/"],
            "/oidc/native/callback"
        );
        assert!(apple_document("PLACEHOLDER").is_none());
        assert!(apple_document("abcdefghij").is_none());
    }

    #[test]
    fn android_association_uses_release_signing_fingerprint() {
        let fingerprint = ["ab"; 32].join(":");
        let document = android_document(&fingerprint).unwrap();
        assert_eq!(
            document[0]["target"]["sha256_cert_fingerprints"][0],
            ["AB"; 32].join(":")
        );
        assert_eq!(document[0]["target"]["package_name"], "app.tossa.mikaki");
        assert!(android_document("AB:CD").is_none());
    }
}
