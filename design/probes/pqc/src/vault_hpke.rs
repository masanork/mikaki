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
