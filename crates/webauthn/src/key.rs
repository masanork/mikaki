//! Bounded COSE public keys and verification; identical on native and Wasm.
use super::*;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdKey};
use rsa::{BoxedUint, RsaPublicKey, pkcs1v15, pss};

pub(super) enum PublicKey {
    Es256(VerifyingKey),
    Es384(p384::ecdsa::VerifyingKey),
    Es512(p521::ecdsa::VerifyingKey),
    Es256k(k256::ecdsa::VerifyingKey),
    Ed25519(EdKey),
    Rsa { key: RsaPublicKey, alg: i32 },
}
impl PublicKey {
    pub(super) fn parse(value: &Value) -> Result<Self> {
        let integer = |label| -> Result<i32> {
            let n = key_field(value, label)?
                .as_integer()
                .ok_or(Invalid::PublicKey)?;
            i32::try_from(i128::from(n)).map_err(|_| Invalid::PublicKey)
        };
        let bytes = |label| {
            key_field(value, label)?
                .as_bytes()
                .ok_or(Invalid::PublicKey)
        };
        match (integer(1)?, integer(3)?) {
            (2, -7) => {
                require(integer(-1)? == 1 && key_field(value, -4).is_err())?;
                let (x, y) = (bytes(-2)?, bytes(-3)?);
                require(x.len() == 32 && y.len() == 32)?;
                let mut point = vec![4];
                point.extend(x);
                point.extend(y);
                Ok(Self::Es256(
                    VerifyingKey::from_sec1_bytes(&point).map_err(|_| Invalid::PublicKey)?,
                ))
            }
            (2, alg @ (-35 | -36 | -47)) => {
                let (curve, size) = match alg {
                    -35 => (2, 48),
                    -36 => (3, 66),
                    _ => (8, 32),
                };
                require(integer(-1)? == curve && key_field(value, -4).is_err())?;
                let (x, y) = (bytes(-2)?, bytes(-3)?);
                require(x.len() == size && y.len() == size)?;
                let mut point = vec![4];
                point.extend(x);
                point.extend(y);
                Ok(match alg {
                    -35 => Self::Es384(
                        p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                            .map_err(|_| Invalid::PublicKey)?,
                    ),
                    -36 => Self::Es512(
                        p521::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                            .map_err(|_| Invalid::PublicKey)?,
                    ),
                    _ => Self::Es256k(
                        k256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                            .map_err(|_| Invalid::PublicKey)?,
                    ),
                })
            }
            (1, -8) => {
                require(integer(-1)? == 6 && key_field(value, -4).is_err())?;
                let key = EdKey::from_bytes(
                    bytes(-2)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| Invalid::PublicKey)?,
                )
                .map_err(|_| Invalid::PublicKey)?;
                require(!key.is_weak())?;
                Ok(Self::Ed25519(key))
            }
            (3, alg @ (-257 | -258 | -259 | -65535 | -37 | -38 | -39)) => {
                // No private RSA parameters. Bound work before constructing big integers.
                for label in -9..=-3 {
                    require(key_field(value, label).is_err())?;
                }
                let (n, e) = (bytes(-1)?, bytes(-2)?);
                require((256..=512).contains(&n.len()) && n[0] >= 128 && n[n.len() - 1] & 1 == 1)?;
                require(!e.is_empty() && e.len() <= 4 && e[0] != 0)?;
                let key = RsaPublicKey::new(
                    BoxedUint::from_be_slice_vartime(n),
                    BoxedUint::from_be_slice_vartime(e),
                )
                .map_err(|_| Invalid::PublicKey)?;
                Ok(Self::Rsa { key, alg })
            }
            _ => Err(Invalid::PublicKey),
        }
    }
    // Called after certificate::verify has checked the SPKI algorithm and curve.
    pub(super) fn matches_spki(
        &self,
        spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    ) -> Result<bool> {
        use der::Encode;
        use rsa::pkcs8::DecodePublicKey;
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or(Invalid::Certificate)?;
        Ok(match self {
            Self::Es256(k) => k.to_sec1_point(false).as_bytes() == bytes,
            Self::Es384(k) => k.to_sec1_point(false).as_bytes() == bytes,
            Self::Es512(k) => k.to_sec1_point(false).as_bytes() == bytes,
            Self::Es256k(k) => k.to_sec1_point(false).as_bytes() == bytes,
            Self::Ed25519(k) => k.as_bytes() == bytes,
            Self::Rsa { key, .. } => {
                *key == RsaPublicKey::from_public_key_der(
                    &spki.to_der().map_err(|_| Invalid::Certificate)?,
                )
                .map_err(|_| Invalid::Certificate)?
            }
        })
    }
    pub(super) fn algorithm(&self) -> i32 {
        match self {
            Self::Es256(_) => -7,
            Self::Es384(_) => -35,
            Self::Es512(_) => -36,
            Self::Es256k(_) => -47,
            Self::Ed25519(_) => -8,
            Self::Rsa { alg, .. } => *alg,
        }
    }
    pub(super) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            Self::Es256(key) => {
                ensure(signature.len() <= 80, Invalid::Limit)?;
                let signature = Signature::from_der(signature).map_err(|_| Invalid::Signature)?;
                key.verify(message, &signature)
                    .map_err(|_| Invalid::Signature)
            }
            Self::Es384(key) => {
                ensure(signature.len() <= 112, Invalid::Limit)?;
                key.verify(
                    message,
                    &p384::ecdsa::Signature::from_der(signature).map_err(|_| Invalid::Signature)?,
                )
                .map_err(|_| Invalid::Signature)
            }
            Self::Es512(key) => {
                ensure(signature.len() <= 144, Invalid::Limit)?;
                key.verify(
                    message,
                    &p521::ecdsa::Signature::from_der(signature).map_err(|_| Invalid::Signature)?,
                )
                .map_err(|_| Invalid::Signature)
            }
            Self::Es256k(key) => {
                ensure(signature.len() <= 80, Invalid::Limit)?;
                let sig =
                    k256::ecdsa::Signature::from_der(signature).map_err(|_| Invalid::Signature)?;
                // WebAuthn ECDSA accepts either S representative; k256 expects low-S.
                key.verify(message, &sig.normalize_s())
                    .map_err(|_| Invalid::Signature)
            }
            Self::Ed25519(key) => {
                let signature =
                    EdSignature::from_slice(signature).map_err(|_| Invalid::Signature)?;
                key.verify_strict(message, &signature)
                    .map_err(|_| Invalid::Signature)
            }
            Self::Rsa { key, alg } => {
                ensure(signature.len() <= 512, Invalid::Limit)?;
                match alg {
                    -39..=-37 => {
                        let sig =
                            pss::Signature::try_from(signature).map_err(|_| Invalid::Signature)?;
                        // COSE fixes MGF1 to the message hash and salt length to its output size.
                        match alg {
                            -37 => {
                                pss::VerifyingKey::<Sha256>::new(key.clone()).verify(message, &sig)
                            }
                            -38 => pss::VerifyingKey::<sha2::Sha384>::new(key.clone())
                                .verify(message, &sig),
                            _ => pss::VerifyingKey::<sha2::Sha512>::new(key.clone())
                                .verify(message, &sig),
                        }
                        .map_err(|_| Invalid::Signature)
                    }
                    _ => {
                        let sig = pkcs1v15::Signature::try_from(signature)
                            .map_err(|_| Invalid::Signature)?;
                        match alg {
                            -257 => pkcs1v15::VerifyingKey::<Sha256>::new(key.clone())
                                .verify(message, &sig),
                            -258 => pkcs1v15::VerifyingKey::<sha2::Sha384>::new(key.clone())
                                .verify(message, &sig),
                            -259 => pkcs1v15::VerifyingKey::<sha2::Sha512>::new(key.clone())
                                .verify(message, &sig),
                            -65535 => pkcs1v15::VerifyingKey::<sha1::Sha1>::new(key.clone())
                                .verify(message, &sig),
                            _ => return Err(Invalid::Algorithm),
                        }
                        .map_err(|_| Invalid::Signature)
                    }
                }
            }
        }
    }
}

fn require(ok: bool) -> Result<()> {
    ensure(ok, Invalid::PublicKey)
}
