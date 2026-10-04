//! RFC 9449 proof construction. On mobile the signing key stays in the OS keystore.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::Signature;
#[cfg(test)]
use p256::ecdsa::{signature::Signer, SigningKey};
#[cfg(any(target_os = "android", target_os = "ios"))]
use p256::ecdsa::{signature::Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "android", target_os = "ios"))]
use tauri_plugin_native_dpop::NativeDpopExt;

pub const ISSUER: &str = "https://auth.mikaki.org";
// Protocol identifiers stay aligned with the disabled native Vault grant schema.
// These identifiers are not fetch destinations; requests use ISSUER below.
pub const RESOURCE: &str = "https://auth.mikaki.org/vault-api/";
pub const DETAIL_TYPE: &str = "https://auth.mikaki.org/authorization-details/vault-read-v1";

pub struct DpopKey {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    app: tauri::AppHandle,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    x: String,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    y: String,
    #[cfg(all(test, not(any(target_os = "android", target_os = "ios"))))]
    software: SigningKey,
}

impl DpopKey {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn generate(app: &tauri::AppHandle) -> Result<Self, String> {
        let public = app.native_dpop().public_key()?;
        for coordinate in [&public.x, &public.y] {
            if URL_SAFE_NO_PAD
                .decode(coordinate)
                .map_or(true, |bytes| bytes.len() != 32)
            {
                return Err("invalid OS DPoP public key".into());
            }
        }
        Ok(Self {
            app: app.clone(),
            x: public.x,
            y: public.y,
        })
    }

    #[cfg(all(test, not(any(target_os = "android", target_os = "ios"))))]
    pub fn generate_for_test() -> Self {
        Self {
            software: SigningKey::random(&mut OsRng),
        }
    }

    pub fn proof(
        &self,
        method: &str,
        url: &str,
        access_token: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<String, String> {
        let target = url::Url::parse(url).map_err(|_| "invalid DPoP target")?;
        if !matches!(method, "GET" | "POST")
            || target.origin().ascii_serialization() != ISSUER
            || !target.username().is_empty()
            || target.password().is_some()
            || target.query().is_some()
            || target.fragment().is_some()
            || !((method == "POST" && target.path() == "/token")
                || (method == "GET"
                    && matches!(
                        target.path(),
                        "/vault-api/attributes/name" | "/vault-api/attributes/owner_note"
                    )))
        {
            return Err("invalid DPoP target".into());
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let (x, y) = (self.x.clone(), self.y.clone());
        #[cfg(all(test, not(any(target_os = "android", target_os = "ios"))))]
        let (x, y) = {
            let point = self.software.verifying_key().to_encoded_point(false);
            (
                URL_SAFE_NO_PAD.encode(point.x().ok_or("invalid DPoP key")?),
                URL_SAFE_NO_PAD.encode(point.y().ok_or("invalid DPoP key")?),
            )
        };
        let header = json!({
            "alg": "ES256", "typ": "dpop+jwt",
            "jwk": {"kty": "EC", "crv": "P-256",
                    "x": x, "y": y}
        });
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?
            .as_secs();
        let mut jti = [0u8; 32];
        OsRng.fill_bytes(&mut jti);
        let mut payload = json!({
            "jti": URL_SAFE_NO_PAD.encode(jti), "iat": issued_at,
            "htm": method, "htu": url,
        });
        if let Some(token) = access_token {
            payload["ath"] =
                Value::String(URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())));
        }
        if let Some(nonce) = nonce {
            if nonce.is_empty() || nonce.len() > 128 {
                return Err("invalid DPoP nonce".into());
            }
            payload["nonce"] = Value::String(nonce.to_owned());
        }
        let encoded_header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).map_err(|_| "DPoP encoding failed")?);
        let encoded_payload = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).map_err(|_| "DPoP encoding failed")?);
        let input = format!("{encoded_header}.{encoded_payload}");
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let signature = {
            let der = URL_SAFE_NO_PAD
                .decode(self.app.native_dpop().sign(&input)?)
                .map_err(|_| "invalid OS DPoP signature")?;
            let signature = Signature::from_der(&der).map_err(|_| "invalid OS DPoP signature")?;
            let mut point = [4u8; 65];
            point[1..33].copy_from_slice(
                &URL_SAFE_NO_PAD
                    .decode(&self.x)
                    .map_err(|_| "invalid OS DPoP key")?,
            );
            point[33..65].copy_from_slice(
                &URL_SAFE_NO_PAD
                    .decode(&self.y)
                    .map_err(|_| "invalid OS DPoP key")?,
            );
            VerifyingKey::from_sec1_bytes(&point)
                .map_err(|_| "invalid OS DPoP key")?
                .verify(input.as_bytes(), &signature)
                .map_err(|_| "OS DPoP key changed")?;
            signature
        };
        #[cfg(all(test, not(any(target_os = "android", target_os = "ios"))))]
        let signature: Signature = self.software.sign(input.as_bytes());
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

pub fn detail(attribute: &str) -> Result<String, String> {
    if !matches!(attribute, "name" | "owner_note") {
        return Err("unsupported Vault attribute".into());
    }
    Ok(json!([{
        "type": DETAIL_TYPE,
        "locations": [RESOURCE],
        "actions": ["read_ciphertext"],
        "attribute": attribute,
    }])
    .to_string())
}

#[cfg(all(test, not(any(target_os = "android", target_os = "ios"))))]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn proof_has_fresh_jti_and_binds_method_url_and_access_token() {
        let key = DpopKey::generate_for_test();
        let one = key
            .proof("POST", &format!("{ISSUER}/token"), None, None)
            .unwrap();
        let two = key
            .proof("POST", &format!("{ISSUER}/token"), None, None)
            .unwrap();
        assert_ne!(one, two);
        let parts: Vec<_> = one.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["htu"], format!("{ISSUER}/token"));
        let input = format!("{}.{}", parts[0], parts[1]);
        let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        key.software
            .verifying_key()
            .verify(input.as_bytes(), &signature)
            .unwrap();
        let resource = key
            .proof(
                "GET",
                &format!("{ISSUER}/vault-api/attributes/name"),
                Some("opaque"),
                None,
            )
            .unwrap();
        let parts: Vec<_> = resource.split('.').collect();
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            payload["ath"],
            URL_SAFE_NO_PAD.encode(Sha256::digest(b"opaque"))
        );
        assert!(key
            .proof("POST", "https://evil.example/token", None, None)
            .is_err());
        assert!(key
            .proof("GET", &format!("{ISSUER}/token"), None, None)
            .is_err());
        let detail: Value = serde_json::from_str(&detail("name").unwrap()).unwrap();
        assert_eq!(detail[0]["locations"][0], RESOURCE);
        assert_eq!(detail[0]["type"], DETAIL_TYPE);
    }
}
