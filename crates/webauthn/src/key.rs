//! Bounded COSE public keys and verification; identical on native and Wasm.
use super::*;
use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdKey};
use rsa::{BoxedUint, RsaPublicKey, pkcs1v15};

pub(super) enum PublicKey {
    Es256(VerifyingKey),
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
            (3, alg @ (-257 | -65535)) => {
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
    pub(super) fn algorithm(&self) -> i32 {
        match self {
            Self::Es256(_) => -7,
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
            Self::Ed25519(key) => {
                let signature =
                    EdSignature::from_slice(signature).map_err(|_| Invalid::Signature)?;
                key.verify_strict(message, &signature)
                    .map_err(|_| Invalid::Signature)
            }
            Self::Rsa { key, alg } => {
                ensure(signature.len() <= 512, Invalid::Limit)?;
                let signature =
                    pkcs1v15::Signature::try_from(signature).map_err(|_| Invalid::Signature)?;
                if *alg == -257 {
                    pkcs1v15::VerifyingKey::<Sha256>::new(key.clone())
                        .verify(message, &signature)
                        .map_err(|_| Invalid::Signature)
                } else {
                    pkcs1v15::VerifyingKey::<sha1::Sha1>::new(key.clone())
                        .verify(message, &signature)
                        .map_err(|_| Invalid::Signature)
                }
            }
        }
    }
}

fn require(ok: bool) -> Result<()> {
    ensure(ok, Invalid::PublicKey)
}
