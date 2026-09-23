//! ES256/RS256 custom-provider probe for jsonwebtoken.
//! This is not production code; private-key signing is deliberately disabled.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation,
    crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils},
    decode,
    errors::Result,
    jwk::{AlgorithmParameters, Jwk},
};
use p256::ecdsa::{Signature, VerifyingKey};
use rsa::{
    RsaPublicKey,
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs1v15::VerifyingKey as RsaVerifyingKey,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use signature::{Error, Signer, Verifier};
use std::sync::OnceLock;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize)]
struct ProbeClaims {
    #[serde(rename = "sub")]
    _sub: String,
    #[serde(rename = "iss")]
    _iss: String,
    #[serde(rename = "aud")]
    _aud: Value,
    #[serde(rename = "exp")]
    _exp: u64,
}

struct Es256Verifier(VerifyingKey);

impl Verifier<Vec<u8>> for Es256Verifier {
    fn verify(&self, message: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        let signature = Signature::from_slice(signature).map_err(|_| Error::new())?;
        self.0.verify(message, &signature).map_err(|_| Error::new())
    }
}

impl JwtVerifier for Es256Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256
    }
}

struct Rs256Verifier(RsaPublicKey);

impl Verifier<Vec<u8>> for Rs256Verifier {
    fn verify(&self, message: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        let signature =
            rsa::pkcs1v15::Signature::try_from(signature.as_slice()).map_err(|_| Error::new())?;
        RsaVerifyingKey::<Sha256>::new(self.0.clone())
            .verify(message, &signature)
            .map_err(|_| Error::new())
    }
}

impl JwtVerifier for Rs256Verifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::RS256
    }
}

struct DisabledSigner(Algorithm);

impl Signer<Vec<u8>> for DisabledSigner {
    fn try_sign(&self, _: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        Err(Error::new())
    }
}

impl JwtSigner for DisabledSigner {
    fn algorithm(&self) -> Algorithm {
        self.0
    }
}

fn disabled_signer(
    algorithm: &Algorithm,
    _: &jsonwebtoken::EncodingKey,
) -> Result<Box<dyn JwtSigner>> {
    Ok(Box::new(DisabledSigner(*algorithm)))
}

fn verifier_factory(
    algorithm: &Algorithm,
    decoding_key: &DecodingKey,
) -> Result<Box<dyn JwtVerifier>> {
    match algorithm {
        Algorithm::ES256 => {
            let public_key = VerifyingKey::from_sec1_bytes(decoding_key.try_get_as_bytes()?)
                .map_err(|_| Error::new())?;
            Ok(Box::new(Es256Verifier(public_key)))
        }
        Algorithm::RS256 => {
            let public_key = RsaPublicKey::from_pkcs1_der(decoding_key.try_get_as_bytes()?)
                .map_err(|_| Error::new())?;
            Ok(Box::new(Rs256Verifier(public_key)))
        }
        _ => Err(Error::new().into()),
    }
}

static CUSTOM_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: disabled_signer,
    verifier_factory,
    key_utils: KeyUtils::new_unimplemented(),
};

static PROVIDER_INIT: OnceLock<()> = OnceLock::new();

fn install_provider() {
    PROVIDER_INIT.get_or_init(|| {
        let _ = CUSTOM_PROVIDER.install_default();
    });
}

fn decoding_key(algorithm: Algorithm, public_jwk_json: &str) -> Option<DecodingKey> {
    let jwk = serde_json::from_str::<Jwk>(public_jwk_json).ok()?;
    match (&algorithm, &jwk.algorithm) {
        (Algorithm::RS256, AlgorithmParameters::RSA(params)) => {
            let modulus = URL_SAFE_NO_PAD.decode(&params.n).ok()?;
            let exponent = URL_SAFE_NO_PAD.decode(&params.e).ok()?;
            let public_key = RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&modulus),
                rsa::BigUint::from_bytes_be(&exponent),
            )
            .ok()?;
            let der = public_key.to_pkcs1_der().ok()?;
            Some(DecodingKey::from_rsa_der(der.as_bytes()))
        }
        (Algorithm::ES256, _) => DecodingKey::from_jwk(&jwk).ok(),
        _ => None,
    }
}

#[wasm_bindgen(start)]
pub fn initialize_wasm() {
    install_provider();
}

#[wasm_bindgen]
pub fn verify_es256(token: &str, public_jwk_json: &str) -> bool {
    verify_with_algorithm(token, public_jwk_json, Algorithm::ES256)
}

#[wasm_bindgen]
pub fn verify_rs256(token: &str, public_jwk_json: &str) -> bool {
    verify_with_algorithm(token, public_jwk_json, Algorithm::RS256)
}

fn verify_with_algorithm(token: &str, public_jwk_json: &str, algorithm: Algorithm) -> bool {
    install_provider();
    let Some(key) = decoding_key(algorithm, public_jwk_json) else {
        return false;
    };
    let mut validation = Validation::new(algorithm);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    decode::<Value>(token, &key, &validation).is_ok()
}

fn verify_claims_with_algorithm(
    token: &str,
    public_jwk_json: &str,
    algorithm: Algorithm,
    issuer: &str,
    audience: &str,
) -> bool {
    install_provider();
    let Some(key) = decoding_key(algorithm, public_jwk_json) else {
        return false;
    };
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.leeway = 0;
    decode::<ProbeClaims>(token, &key, &validation).is_ok()
}

#[wasm_bindgen]
pub fn verify_es256_claims(
    token: &str,
    public_jwk_json: &str,
    issuer: &str,
    audience: &str,
) -> bool {
    verify_claims_with_algorithm(token, public_jwk_json, Algorithm::ES256, issuer, audience)
}

#[wasm_bindgen]
pub fn verify_rs256_claims(
    token: &str,
    public_jwk_json: &str,
    issuer: &str,
    audience: &str,
) -> bool {
    verify_claims_with_algorithm(token, public_jwk_json, Algorithm::RS256, issuer, audience)
}
