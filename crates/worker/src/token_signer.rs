//! OP signing through non-extractable runtime keys. Claim construction and key
//! selection remain in mikaki-oidc and the existing D1 authorization predicates.
use wasm_bindgen::JsCast as _;

pub(super) enum WorkerTokenSigner {
    Es256 {
        key: mikaki_oidc::P256RuntimeKey,
        crypto_key: web_sys::CryptoKey,
    },
    Rs256 {
        key: mikaki_oidc::RsaPrivateTokenKey,
        crypto_key: web_sys::CryptoKey,
    },
}

fn unavailable() -> worker::Error {
    worker::Error::RustError("server_error".into())
}

fn subtle() -> worker::Result<web_sys::SubtleCrypto> {
    js_sys::Reflect::get(&js_sys::global(), &"crypto".into())
        .map_err(|_| unavailable())?
        .dyn_into::<web_sys::Crypto>()
        .map(|crypto| crypto.subtle())
        .map_err(|_| unavailable())
}

impl WorkerTokenSigner {
    async fn import_key(encoded: &str, algorithm: &str) -> worker::Result<web_sys::CryptoKey> {
        let subtle = subtle()?;
        let algorithm = js_sys::JSON::parse(algorithm)
            .map_err(|_| unavailable())?
            .dyn_into::<js_sys::Object>()
            .map_err(|_| unavailable())?;
        let jwk = js_sys::JSON::parse(encoded)
            .map_err(|_| unavailable())?
            .dyn_into::<js_sys::Object>()
            .map_err(|_| unavailable())?;
        let usage = js_sys::Array::new();
        usage.push(&"sign".into());
        let operation = subtle.import_key_with_object("jwk", &jwk, &algorithm, false, &usage);
        let imported = match operation {
            Ok(promise) => wasm_bindgen_futures::JsFuture::from(promise).await,
            Err(error) => Err(error),
        };
        // JSON strings are immutable in JS; remove the private members from the
        // temporary object on either outcome rather than retaining a second JWK.
        for name in ["d", "p", "q", "dp", "dq", "qi"] {
            let _ = js_sys::Reflect::delete_property(&jwk, &name.into());
        }
        let key = imported
            .map_err(|_| unavailable())?
            .dyn_into::<web_sys::CryptoKey>()
            .map_err(|_| unavailable())?;
        if key.extractable() {
            return Err(unavailable());
        }
        Ok(key)
    }

    pub(super) async fn from_secret(input: &str) -> worker::Result<Self> {
        #[derive(serde::Deserialize)]
        struct Kind {
            kty: String,
        }
        if input.len() > 8192 {
            return Err(unavailable());
        }
        // Inspect only kty here. The strict branch parser checks every member;
        // this dispatch must not allocate another copy of all private scalars.
        let kind: Kind = serde_json::from_str(input).map_err(|_| unavailable())?;
        match kind.kty.as_str() {
            "EC" => {
                let (key, encoded) = mikaki_oidc::P256RuntimeKey::prepare_private_jwk(input)
                    .map_err(|_| unavailable())?;
                let crypto_key =
                    Self::import_key(&encoded, r#"{"name":"ECDSA","namedCurve":"P-256"}"#).await?;
                Ok(Self::Es256 { key, crypto_key })
            }
            "RSA" => {
                let key = mikaki_oidc::RsaPrivateTokenKey::from_private_jwk(input)
                    .map_err(|_| unavailable())?;
                let encoded = zeroize::Zeroizing::new(
                    key.webcrypto_private_jwk_json()
                        .map_err(|_| unavailable())?,
                );
                let crypto_key = Self::import_key(
                    &encoded,
                    r#"{"name":"RSASSA-PKCS1-v1_5","hash":{"name":"SHA-256"}}"#,
                )
                .await?;
                Ok(Self::Rs256 { key, crypto_key })
            }
            _ => Err(unavailable()),
        }
    }

    pub(super) fn kid(&self) -> &str {
        match self {
            Self::Es256 { key, .. } => key.kid(),
            Self::Rs256 { key, .. } => key.kid(),
        }
    }

    pub(super) fn algorithm(&self) -> &'static str {
        match self {
            Self::Es256 { .. } => "ES256",
            Self::Rs256 { .. } => "RS256",
        }
    }

    pub(super) fn matches_public_jwk(&self, jwk: &str) -> bool {
        match self {
            Self::Es256 { key, .. } => key.matches_public_jwk(jwk),
            Self::Rs256 { key, .. } => key.matches_public_jwk(jwk),
        }
    }

    async fn sign(&self, input: &[u8]) -> worker::Result<Vec<u8>> {
        let subtle = subtle()?;
        let (promise, length) = match self {
            Self::Es256 { crypto_key, .. } => {
                let algorithm = js_sys::JSON::parse(r#"{"name":"ECDSA","hash":"SHA-256"}"#)
                    .map_err(|_| unavailable())?
                    .dyn_into::<js_sys::Object>()
                    .map_err(|_| unavailable())?;
                (
                    subtle.sign_with_object_and_u8_array(&algorithm, crypto_key, input),
                    64,
                )
            }
            Self::Rs256 { key, crypto_key } => (
                subtle.sign_with_str_and_u8_array("RSASSA-PKCS1-v1_5", crypto_key, input),
                key.modulus_bytes(),
            ),
        };
        let value = wasm_bindgen_futures::JsFuture::from(promise.map_err(|_| unavailable())?)
            .await
            .map_err(|_| unavailable())?;
        let signature = js_sys::Uint8Array::new(&value).to_vec();
        if signature.len() != length {
            return Err(unavailable());
        }
        Ok(signature)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn sign_id_token(
        &self,
        issuer: &str,
        subject: &str,
        audience: &str,
        sid: &str,
        nonce: Option<&str>,
        auth_time: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> worker::Result<String> {
        let input = mikaki_oidc::IdTokenSigningInput::new(
            self.algorithm(),
            self.kid(),
            issuer,
            subject,
            audience,
            sid,
            nonce,
            auth_time,
            issued_at,
            expires_at,
        )
        .map_err(|_| unavailable())?;
        let signature = self.sign(input.as_bytes()).await?;
        input.finish(&signature).map_err(|_| unavailable())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn sign_logout_token(
        &self,
        issuer: &str,
        audience: &str,
        subject: &str,
        sid: &str,
        jti: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> worker::Result<String> {
        let input = mikaki_oidc::LogoutTokenSigningInput::new(
            self.algorithm(),
            self.kid(),
            issuer,
            audience,
            subject,
            sid,
            jti,
            issued_at,
            expires_at,
        )
        .map_err(|_| unavailable())?;
        let signature = self.sign(input.as_bytes()).await?;
        input.finish(&signature).map_err(|_| unavailable())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn sign_userinfo(
        &self,
        issuer: &str,
        subject: &str,
        audience: &str,
        issued_at: u64,
        expires_at: u64,
        linked: &serde_json::Value,
    ) -> worker::Result<String> {
        let input = mikaki_oidc::UserInfoSigningInput::new(
            self.algorithm(),
            self.kid(),
            issuer,
            subject,
            audience,
            issued_at,
            expires_at,
            linked,
        )
        .map_err(|_| unavailable())?;
        let signature = self.sign(input.as_bytes()).await?;
        input.finish(&signature).map_err(|_| unavailable())
    }
}
