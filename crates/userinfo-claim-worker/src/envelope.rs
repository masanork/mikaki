//! Strict candidate ML-KEM-768 HPKE recipient wrap decoder.
//! A future claim operation must supply every binding from trusted D1 state.

use aes_gcm::{
    Aes256Gcm, KeyInit as _, Nonce,
    aead::{Aead as _, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hpke::{
    Deserializable as _, Kem as _, OpModeR, Serializable as _, aead::AesGcm256, kdf::HkdfSha256,
    kem::MlKem768,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const SUITE: [u8; 6] = [0, 0x41, 0, 1, 0, 2];
const DOMAIN: &[u8] = b"mikaki-vault-recipient-envelope-v1-draft04";
const FRAME_BYTES: usize = 1187;
const ENC_END: usize = 1139;

#[derive(Clone, Copy)]
pub struct UserInfoBinding<'a> {
    pub origin: &'a str,
    pub account_id: &'a str,
    pub revision: u64,
    pub ciphertext: &'a [u8],
}

fn context(parts: &[&[u8]]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    for part in parts {
        output.extend_from_slice(&u16::try_from(part.len()).ok()?.to_be_bytes());
        output.extend_from_slice(part);
    }
    Some(output)
}

/// Returns a data key only for the exact recipient key, ciphertext, and trusted Vault context.
/// It does not authorize release; live Grant and ClaimRelease checks are required separately.
pub fn open_userinfo_data_key(
    seed: &[u8; 64],
    public_key: &[u8],
    key_id: &str,
    generation: u64,
    frame: &[u8],
    binding: &UserInfoBinding<'_>,
) -> Option<Zeroizing<[u8; 32]>> {
    if generation == 0
        || binding.revision == 0
        || binding.origin.is_empty()
        || binding.account_id.is_empty()
        || binding.ciphertext.is_empty()
        || public_key.len() != 1184
        || frame.len() != FRAME_BYTES
        || &frame[..4] != b"MKVE"
        || frame[4] != VERSION
        || frame[5..11] != SUITE
        || frame[43..51] != generation.to_be_bytes()
    {
        return None;
    }
    let private_key = <MlKem768 as hpke::Kem>::PrivateKey::from_bytes(seed).ok()?;
    let derived_public = MlKem768::sk_to_pk(&private_key);
    let derived_public_bytes = derived_public.to_bytes();
    if derived_public_bytes.as_slice() != public_key {
        return None;
    }
    let expected_key_id: [u8; 32] = Sha256::digest(public_key).into();
    if key_id != URL_SAFE_NO_PAD.encode(expected_key_id) || frame[11..43] != expected_key_id {
        return None;
    }
    let info = context(&[
        DOMAIN,
        &[VERSION],
        &SUITE,
        b"userinfo",
        &expected_key_id,
        &generation.to_be_bytes(),
    ])?;
    let digest: [u8; 32] = Sha256::digest(binding.ciphertext).into();
    let aad = context(&[
        binding.origin.as_bytes(),
        binding.account_id.as_bytes(),
        b"name",
        &binding.revision.to_be_bytes(),
        b"userinfo",
        b"oidc.userinfo.name",
        &digest,
    ])?;
    let encapsulated =
        <MlKem768 as hpke::Kem>::EncappedKey::from_bytes(&frame[51..ENC_END]).ok()?;
    let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, MlKem768>(
        &OpModeR::Base,
        &private_key,
        &encapsulated,
        &info,
    )
    .ok()?;
    let plaintext = Zeroizing::new(receiver.open(&frame[ENC_END..], &aad).ok()?);
    Some(Zeroizing::new(plaintext.as_slice().try_into().ok()?))
}

/// Validates that the wrapped key decrypts the exact owner ciphertext.
/// Only a boolean result may cross the claim Worker service boundary.
pub fn validates_name_ciphertext(
    data_key: &[u8; 32],
    origin: &str,
    revision: u64,
    ciphertext: &[u8],
) -> bool {
    if ciphertext.len() < 1 + 12 + 16 || ciphertext.len() > 24 * 1024 || ciphertext[0] != 1 {
        return false;
    }
    let Some(aad) = context(&[
        b"mikaki-vault-attribute-content",
        b"1",
        origin.as_bytes(),
        b"name",
        revision.to_string().as_bytes(),
    ]) else {
        return false;
    };
    let Ok(aead) = Aes256Gcm::new_from_slice(data_key) else {
        return false;
    };
    let Ok(nonce) = Nonce::try_from(&ciphertext[1..13]) else {
        return false;
    };
    let Ok(plaintext) = aead.decrypt(
        &nonce,
        Payload {
            msg: &ciphertext[13..],
            aad: &aad,
        },
    ) else {
        return false;
    };
    let plaintext = Zeroizing::new(plaintext);
    !plaintext.is_empty() && std::str::from_utf8(&plaintext).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::{DecapsulationKey, Seed, kem::KeyExport};

    #[test]
    fn checked_in_noble_frame_opens_only_for_its_vault_binding() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../design/probes/pqc/hpke-envelope-fixture.json"
        ))
        .unwrap();
        let seed: [u8; 64] = URL_SAFE_NO_PAD
            .decode(fixture["seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let public_key = DecapsulationKey::<ml_kem::MlKem768>::from_seed(Seed::from(seed))
            .encapsulation_key()
            .to_bytes();
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(public_key));
        let frame = URL_SAFE_NO_PAD
            .decode(fixture["frame"].as_str().unwrap())
            .unwrap();
        let binding = UserInfoBinding {
            origin: "https://mikaki.example",
            account_id: "test-account-1",
            revision: 9,
            ciphertext: b"test-vault-ciphertext",
        };
        assert_eq!(
            **open_userinfo_data_key(&seed, &public_key, &key_id, 1, &frame, &binding)
                .as_ref()
                .unwrap(),
            [0x51; 32]
        );
        let changed = UserInfoBinding {
            revision: 10,
            ..binding
        };
        assert!(open_userinfo_data_key(&seed, &public_key, &key_id, 1, &frame, &changed).is_none());
        let changed = UserInfoBinding {
            ciphertext: b"other-vault-ciphertext",
            ..binding
        };
        assert!(open_userinfo_data_key(&seed, &public_key, &key_id, 1, &frame, &changed).is_none());
        let changed = UserInfoBinding {
            account_id: "other-account",
            ..binding
        };
        assert!(open_userinfo_data_key(&seed, &public_key, &key_id, 1, &frame, &changed).is_none());
        assert!(open_userinfo_data_key(&seed, &public_key, &key_id, 2, &frame, &binding).is_none());
        let mut changed_seed = seed;
        changed_seed[0] ^= 1;
        assert!(
            open_userinfo_data_key(&changed_seed, &public_key, &key_id, 1, &frame, &binding)
                .is_none()
        );
        let mut changed_frame = frame.clone();
        changed_frame[51] ^= 1;
        assert!(
            open_userinfo_data_key(&seed, &public_key, &key_id, 1, &changed_frame, &binding)
                .is_none()
        );
    }

    #[test]
    fn data_key_must_open_exact_owner_ciphertext() {
        let key = [0x51; 32];
        let nonce = [0x91; 12];
        let aad = context(&[
            b"mikaki-vault-attribute-content",
            b"1",
            b"https://mikaki.example",
            b"name",
            b"9",
        ])
        .unwrap();
        let aead = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_value = Nonce::try_from(nonce.as_slice()).unwrap();
        let encrypted = aead
            .encrypt(
                &nonce_value,
                Payload {
                    msg: b"Saved name",
                    aad: &aad,
                },
            )
            .unwrap();
        let mut ciphertext = vec![1];
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(&encrypted);
        assert!(validates_name_ciphertext(
            &key,
            "https://mikaki.example",
            9,
            &ciphertext
        ));
        assert!(!validates_name_ciphertext(
            &key,
            "https://other.example",
            9,
            &ciphertext
        ));
        assert!(!validates_name_ciphertext(
            &key,
            "https://mikaki.example",
            10,
            &ciphertext
        ));
        ciphertext[13] ^= 1;
        assert!(!validates_name_ciphertext(
            &key,
            "https://mikaki.example",
            9,
            &ciphertext
        ));
    }
}
