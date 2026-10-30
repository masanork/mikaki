//! Private primitive boundary. Only the protocol verifiers may turn successful
//! verification into an authenticated capability; no unchecked finish API is public.
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

#[cfg(test)]
mod tests;

pub(crate) struct Es256Verification {
    public_key: Vec<u8>,
    signature: [u8; 64],
    message: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct InvalidEs256Signature;

impl Es256Verification {
    pub(crate) fn new(
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> Result<Self, InvalidEs256Signature> {
        // Both encodings are allowed by the registered client-key schema.
        if !matches!(
            (public_key.len(), public_key.first()),
            (33, Some(2 | 3)) | (65, Some(4))
        ) {
            return Err(InvalidEs256Signature);
        }
        let signature: [u8; 64] = signature.try_into().map_err(|_| InvalidEs256Signature)?;
        // Preserve RustCrypto's strict P1363 scalar acceptance, including high-S.
        // Public integer bounds are checked here; curve/signature math belongs to
        // the selected provider. DER and zero/out-of-range scalars fail closed.
        const ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        if signature
            .as_chunks::<32>()
            .0
            .iter()
            .any(|scalar| scalar.iter().all(|byte| *byte == 0) || scalar >= &ORDER)
        {
            return Err(InvalidEs256Signature);
        }
        Ok(Self {
            public_key: public_key.to_vec(),
            signature,
            message: message.to_vec(),
        })
    }

    pub(crate) fn verify_reference(self) -> Result<(), InvalidEs256Signature> {
        let key =
            VerifyingKey::from_sec1_bytes(&self.public_key).map_err(|_| InvalidEs256Signature)?;
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| InvalidEs256Signature)?;
        key.verify(&self.message, &signature)
            .map_err(|_| InvalidEs256Signature)
    }

    // The async protocol path is shared by both targets. Host qualification
    // uses the independent reference provider; Wasm always uses Web Crypto and
    // never retries with RustCrypto after a native error.
    pub(crate) async fn verify_async(self) -> Result<(), InvalidEs256Signature> {
        #[cfg(target_arch = "wasm32")]
        {
            self.verify_native().await
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            self.verify_reference()
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn verify_native(self) -> Result<(), InvalidEs256Signature> {
        use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

        #[wasm_bindgen(module = "/src/native_es256.ts")]
        extern "C" {
            #[wasm_bindgen(catch, js_name = nativeVerifyEs256)]
            async fn verify(
                public_key: &[u8],
                signature: &[u8],
                message: &[u8],
            ) -> Result<JsValue, JsValue>;
        }
        let valid = verify(&self.public_key, &self.signature, &self.message)
            .await
            .map_err(|_| InvalidEs256Signature)?;
        if valid.as_bool() != Some(true) {
            return Err(InvalidEs256Signature);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn ready<T>(future: impl std::future::Future<Output = T>) -> T {
    use std::task::{Context, Poll, Waker};
    match std::pin::pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the host reference provider must not perform asynchronous I/O"),
    }
}
