//! Draft-only Vault recipient wrapping exercise. No wire format or production keys.

use hpke::kem::MlKem768;
use hpke::rand_core::SeedableRng;
use hpke::{Kem as _, OpModeR, OpModeS, aead::AesGcm256, kdf::HkdfSha256};
use rand_chacha::ChaCha20Rng;

type RecipientKem = MlKem768;

fn context(parts: &[&[u8]]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    for part in parts {
        let length = u16::try_from(part.len()).ok()?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(part);
    }
    Some(output)
}

pub fn self_test() -> bool {
    let mut rng = ChaCha20Rng::from_seed([0x50; 32]);
    let (private_key, public_key) = RecipientKem::gen_keypair_with_rng(&mut rng);
    let origin = b"https://mikaki.example";
    let attribute = b"name";
    let recipient = b"userinfo";
    let key_id = b"test-key-1";
    let revision = 9_u64.to_be_bytes();
    let info = match context(&[
        b"mikaki-vault-recipient-hpke-probe",
        b"draft-ietf-hpke-pq-04",
        recipient,
        key_id,
    ]) {
        Some(value) => value,
        None => return false,
    };
    let aad = match context(&[origin, attribute, &revision, recipient, key_id]) {
        Some(value) => value,
        None => return false,
    };
    let (encapped, mut sender) = match hpke::setup_sender_with_rng::<
        AesGcm256,
        HkdfSha256,
        RecipientKem,
    >(&OpModeS::Base, &public_key, &info, &mut rng)
    {
        Ok(value) => value,
        Err(_) => return false,
    };
    let data_key = [0x51; 32];
    let ciphertext = match sender.seal(&data_key, &aad) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let open = |info: &[u8], aad: &[u8], ciphertext: &[u8]| {
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, RecipientKem>(
            &OpModeR::Base,
            &private_key,
            &encapped,
            info,
        )
        .ok()?;
        receiver.open(ciphertext, aad).ok()
    };
    if open(&info, &aad, &ciphertext).as_deref() != Some(&data_key) {
        return false;
    }
    let wrong_revision = 10_u64.to_be_bytes();
    let Some(wrong_revision_aad) =
        context(&[origin, attribute, &wrong_revision, recipient, key_id])
    else {
        return false;
    };
    let Some(wrong_attribute_aad) = context(&[origin, b"email", &revision, recipient, key_id])
    else {
        return false;
    };
    let Some(wrong_key_info) = context(&[
        b"mikaki-vault-recipient-hpke-probe",
        b"draft-ietf-hpke-pq-04",
        recipient,
        b"test-key-2",
    ]) else {
        return false;
    };
    let mut changed = ciphertext.clone();
    changed[0] ^= 1;
    open(&info, &wrong_revision_aad, &ciphertext).is_none()
        && open(&info, &wrong_attribute_aad, &ciphertext).is_none()
        && open(&wrong_key_info, &aad, &ciphertext).is_none()
        && open(&info, &aad, &changed).is_none()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod draft05_tests {
    use super::*;
    use hpke::{Deserializable, Serializable, aead::AesGcm128};
    use serde_json::Value;

    fn decode(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn official_draft05_mlkem768_base_vector_opens() {
        let vector: Value =
            serde_json::from_str(include_str!("../hpke-pq-draft05-vector.json")).unwrap();
        assert_eq!(vector["kem_id"], 65);
        assert_eq!(vector["kdf_id"], 1);
        assert_eq!(vector["aead_id"], 1);
        assert_eq!(vector["mode"], 0);
        let bytes = |field: &str| decode(vector[field].as_str().unwrap());
        let sk = <RecipientKem as hpke::Kem>::PrivateKey::from_bytes(&bytes("skRm")).unwrap();
        assert_eq!(
            RecipientKem::sk_to_pk(&sk).to_bytes().as_slice(),
            bytes("pkRm")
        );
        let enc = <RecipientKem as hpke::Kem>::EncappedKey::from_bytes(&bytes("enc")).unwrap();
        let mut receiver = hpke::setup_receiver::<AesGcm128, HkdfSha256, RecipientKem>(
            &OpModeR::Base,
            &sk,
            &enc,
            &bytes("info"),
        )
        .unwrap();
        let encryption = &vector["encryptions"][0];
        let field = |name: &str| decode(encryption[name].as_str().unwrap());
        assert_eq!(
            receiver.open(&field("ct"), &field("aad")).unwrap(),
            field("pt")
        );
    }
}
