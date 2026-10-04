//! OS association documents for the signed mobile native client.

const APP_ID: &str = "app.tossa.mikaki";
const CALLBACK_PATH: &str = "/oidc/native/callback";
const ISSUANCE_CALLBACK_PATH: &str = "/identity/issuance/callback";

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
                "components": [{"/": CALLBACK_PATH}, {"/": ISSUANCE_CALLBACK_PATH}]
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

// A callback in the browser means the OS did not open the verified app link.
// Never render or forward the one-use authorization code or state from its URL.
#[cfg(target_arch = "wasm32")]
pub fn callback_fallback() -> worker::Result<worker::Response> {
    Ok(worker::Response::builder()
        .with_status(303)
        .with_header("Location", "/native-link-help")?
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .fixed(Vec::new()))
}

#[cfg(target_arch = "wasm32")]
pub fn callback_help() -> worker::Result<worker::Response> {
    const PAGE: &str = r#"<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>アプリに戻れませんでした · mikaki</title>
<style>
:root{font-family:system-ui,-apple-system,sans-serif;color-scheme:light dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f5f1;color:#173c59}
main{box-sizing:border-box;width:min(100%,32rem);padding:3rem 1.5rem}
.brand{display:flex;align-items:center;gap:.65rem;font-weight:750;font-size:1.5rem;letter-spacing:-.04em}.brand-mark{display:block;width:2rem;height:2rem;border-radius:24%;background:linear-gradient(135deg,#173c59,#081b2d)}.brand-mark svg{display:block;width:100%;height:100%}
.card{margin-top:2rem;padding:2rem;border:1px solid #dce5eb;border-radius:1.25rem;background:#fff;box-shadow:0 12px 36px #173c5910}
.eyebrow{color:#357daf;font-size:.75rem;font-weight:750;letter-spacing:.12em}
h1{font-size:clamp(1.75rem,6vw,2.25rem);line-height:1.3;letter-spacing:-.04em}
p,li{line-height:1.7}ol{padding-left:1.4rem}.note{font-size:.9rem;color:#526a7b}
@media(prefers-color-scheme:dark){body{background:#081b2d;color:#e2f3ff}.card{background:#102d44;border-color:#315872;box-shadow:none}.eyebrow{color:#7ac8e9}.note{color:#b8d9e9}}
</style></head><body><main><div class="brand"><span class="brand-mark">{{brand_mark}}</span>mikaki</div><div class="card">
<p class="eyebrow">RETURN TO APP</p><h1>アプリに戻れませんでした</h1>
<p>この認証はアプリに届いていません。ブラウザを閉じて、mikakiアプリの待機画面で「キャンセルして戻る」を選んでください。</p>
<ol><li>Androidの設定で「アプリ」→「mikaki」→「デフォルトで開く」を開きます。</li>
<li>対応するリンクを開く設定を有効にし、<strong>mikaki-native.tossa.app</strong>を許可します。</li>
<li>mikakiアプリからログインをやり直します。</li></ol>
<p class="note">iPhoneでは、アプリを開いて認証をやり直してください。問題が続く場合はアプリのインストールとリンク設定を確認してください。</p>
<p lang="en" class="note">The sign-in did not reach the app. Cancel the pending sign-in in mikaki, enable its supported links in Android settings, then try again.</p>
</div></main></body></html>"#;
    Ok(worker::Response::builder()
        .with_header("Content-Type", "text/html; charset=utf-8")?
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'",
        )?
        .with_header("X-Content-Type-Options", "nosniff")?
        .fixed(
            PAGE.replace(
                "{{brand_mark}}",
                include_str!("../../../branding/mikaki-mark.svg"),
            )
            .into_bytes(),
        ))
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
        assert_eq!(
            document["applinks"]["details"][0]["components"][1]["/"],
            "/identity/issuance/callback"
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
