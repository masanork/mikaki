//! Crypto primitives run in Workers Web Crypto. The native test backend is an
//! independent RustCrypto reference and is absent from release dependencies.
use zeroize::Zeroizing;

#[cfg(target_arch = "wasm32")]
mod backend {
    use super::*;
    use js_sys::Uint8Array;
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(module = "/src/native_crypto.js")]
    extern "C" {
        #[wasm_bindgen(catch, js_name = nativeSha256)]
        async fn digest(input: &[u8]) -> Result<Uint8Array, JsValue>;
        #[wasm_bindgen(catch, js_name = nativePublicKey)]
        async fn derive_public(seed: &[u8]) -> Result<Uint8Array, JsValue>;
        #[wasm_bindgen(catch, js_name = nativeOpenHpke)]
        async fn hpke(
            seed: &[u8],
            enc: &[u8],
            info: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Uint8Array, JsValue>;
        #[wasm_bindgen(catch, js_name = nativeDecryptAes)]
        async fn aes(
            key: &[u8],
            nonce: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
        ) -> Result<Uint8Array, JsValue>;
    }

    fn take(value: Uint8Array) -> Zeroizing<Vec<u8>> {
        let bytes = Zeroizing::new(value.to_vec());
        value.fill(0, 0, value.length());
        bytes
    }

    pub async fn sha256(input: &[u8]) -> Option<[u8; 32]> {
        digest(input).await.ok()?.to_vec().try_into().ok()
    }
    pub async fn public_key(seed: &[u8; 64]) -> Option<Vec<u8>> {
        Some(derive_public(seed).await.ok()?.to_vec())
    }
    pub async fn open_hpke(
        seed: &[u8; 64],
        enc: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        Some(take(hpke(seed, enc, info, aad, ciphertext).await.ok()?))
    }
    pub async fn decrypt(
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        Some(take(aes(key, nonce, aad, ciphertext).await.ok()?))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod backend {
    use super::*;
    use aes_gcm::{
        Aes256Gcm, KeyInit as _, Nonce,
        aead::{Aead as _, Payload},
    };
    use hpke::{
        Deserializable as _, Kem as _, OpModeR, Serializable as _, aead::AesGcm256,
        kdf::HkdfSha256, kem::MlKem768,
    };
    use sha2::{Digest as _, Sha256};

    pub async fn sha256(input: &[u8]) -> Option<[u8; 32]> {
        Some(Sha256::digest(input).into())
    }
    pub async fn public_key(seed: &[u8; 64]) -> Option<Vec<u8>> {
        let private = <MlKem768 as hpke::Kem>::PrivateKey::from_bytes(seed).ok()?;
        Some(MlKem768::sk_to_pk(&private).to_bytes().to_vec())
    }
    pub async fn open_hpke(
        seed: &[u8; 64],
        enc: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        let private = <MlKem768 as hpke::Kem>::PrivateKey::from_bytes(seed).ok()?;
        let encapsulated = <MlKem768 as hpke::Kem>::EncappedKey::from_bytes(enc).ok()?;
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, MlKem768>(
            &OpModeR::Base,
            &private,
            &encapsulated,
            info,
        )
        .ok()?;
        Some(Zeroizing::new(receiver.open(ciphertext, aad).ok()?))
    }
    pub async fn decrypt(
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        Some(Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::try_from(nonce).ok()?,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .ok()?,
        ))
    }
}

pub use backend::*;

#[cfg(all(test, not(target_arch = "wasm32")))]
pub fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    use std::task::{Context, Poll, Waker};
    match std::pin::pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the host reference backend must not perform asynchronous I/O"),
    }
}
