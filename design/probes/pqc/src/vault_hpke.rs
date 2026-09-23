//! Draft-only Vault recipient wrapping and candidate frame exercise. No production keys.

use hpke::kem::MlKem768;
use hpke::rand_core::SeedableRng;
use hpke::{
    Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _, aead::AesGcm256,
    kdf::HkdfSha256,
};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest as _, Sha256};

type RecipientKem = MlKem768;
const FORMAT_VERSION: [u8; 1] = [1];
const SUITE_IDS: [u8; 6] = [0, 0x41, 0, 1, 0, 2];
const PROBE_DOMAIN: &[u8] = b"mikaki-vault-recipient-envelope-v1-draft04";
const FRAME_MAGIC: &[u8; 4] = b"MKVE";
const ENC_LEN: usize = 1088;
const CT_LEN: usize = 48;
const FRAME_LEN: usize = 4 + 1 + 6 + 32 + 8 + ENC_LEN + CT_LEN;

fn encode_frame(enc: &[u8], ct: &[u8], key_id: &[u8; 32], generation: u64) -> Option<Vec<u8>> {
    if enc.len() != ENC_LEN || ct.len() != CT_LEN || generation == 0 {
        return None;
    }
    let mut frame = Vec::with_capacity(FRAME_LEN);
    frame.extend_from_slice(FRAME_MAGIC);
    frame.extend_from_slice(&FORMAT_VERSION);
    frame.extend_from_slice(&SUITE_IDS);
    frame.extend_from_slice(key_id);
    frame.extend_from_slice(&generation.to_be_bytes());
    frame.extend_from_slice(enc);
    frame.extend_from_slice(ct);
    Some(frame)
}

fn decode_frame<'a>(
    frame: &'a [u8],
    expected_key_id: &[u8; 32],
    expected_generation: u64,
) -> Option<(&'a [u8], &'a [u8])> {
    if frame.len() != FRAME_LEN
        || &frame[..4] != FRAME_MAGIC
        || frame[4] != FORMAT_VERSION[0]
        || frame[5..11] != SUITE_IDS
        || frame[11..43] != *expected_key_id
        || frame[43..51] != expected_generation.to_be_bytes()
        || expected_generation == 0
    {
        return None;
    }
    Some((&frame[51..51 + ENC_LEN], &frame[51 + ENC_LEN..]))
}

fn context(parts: &[&[u8]]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    for part in parts {
        let length = u16::try_from(part.len()).ok()?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(part);
    }
    Some(output)
}

// Public, deterministic fixture seed. This must never be used for a real recipient.
const FIXTURE_SEED: [u8; 64] = [0x71; 64];
const FIXTURE_DATA_KEY: [u8; 32] = [0x51; 32];

fn fixture_context(key_id: &[u8; 32]) -> Option<(Vec<u8>, Vec<u8>)> {
    let generation = 1_u64.to_be_bytes();
    let revision = 9_u64.to_be_bytes();
    let blob_digest: [u8; 32] = Sha256::digest(b"test-vault-ciphertext").into();
    let info = context(&[
        PROBE_DOMAIN,
        &FORMAT_VERSION,
        &SUITE_IDS,
        b"userinfo",
        key_id,
        &generation,
    ])?;
    let aad = context(&[
        b"https://mikaki.example",
        b"test-account-1",
        b"name",
        &revision,
        b"userinfo",
        b"oidc.userinfo.name",
        &blob_digest,
    ])?;
    Some((info, aad))
}

pub fn fixture_frame() -> Option<Vec<u8>> {
    let private_key = <RecipientKem as hpke::Kem>::PrivateKey::from_bytes(&FIXTURE_SEED).ok()?;
    let public_key = RecipientKem::sk_to_pk(&private_key);
    let key_id: [u8; 32] = Sha256::digest(public_key.to_bytes()).into();
    let (info, aad) = fixture_context(&key_id)?;
    let mut rng = ChaCha20Rng::from_seed([0x50; 32]);
    let (encapped, mut sender) =
        hpke::setup_sender_with_rng::<AesGcm256, HkdfSha256, RecipientKem>(
            &OpModeS::Base,
            &public_key,
            &info,
            &mut rng,
        )
        .ok()?;
    let ciphertext = sender.seal(&FIXTURE_DATA_KEY, &aad).ok()?;
    encode_frame(encapped.to_bytes().as_slice(), &ciphertext, &key_id, 1)
}

pub fn fixture_opens(frame: &[u8]) -> bool {
    let Ok(private_key) = <RecipientKem as hpke::Kem>::PrivateKey::from_bytes(&FIXTURE_SEED) else {
        return false;
    };
    let public_key = RecipientKem::sk_to_pk(&private_key);
    let key_id: [u8; 32] = Sha256::digest(public_key.to_bytes()).into();
    let Some((enc, ciphertext)) = decode_frame(frame, &key_id, 1) else {
        return false;
    };
    let Ok(enc) = <RecipientKem as hpke::Kem>::EncappedKey::from_bytes(enc) else {
        return false;
    };
    let Some((info, aad)) = fixture_context(&key_id) else {
        return false;
    };
    let Ok(mut receiver) = hpke::setup_receiver::<AesGcm256, HkdfSha256, RecipientKem>(
        &OpModeR::Base,
        &private_key,
        &enc,
        &info,
    ) else {
        return false;
    };
    matches!(receiver.open(ciphertext, &aad), Ok(data_key) if data_key == FIXTURE_DATA_KEY)
}

#[cfg(test)]
#[test]
fn public_seed_fixture_round_trips() {
    let frame = fixture_frame().expect("public fixture must seal");
    assert_eq!(frame.len(), FRAME_LEN);
    assert!(fixture_opens(&frame));
    let mut changed = frame;
    changed[51 + ENC_LEN] ^= 1;
    assert!(!fixture_opens(&changed));
}

pub fn self_test() -> bool {
    let mut rng = ChaCha20Rng::from_seed([0x50; 32]);
    let (private_key, public_key) = RecipientKem::gen_keypair_with_rng(&mut rng);
    let origin = b"https://mikaki.example";
    let account = b"test-account-1";
    let attribute = b"name";
    let recipient = b"userinfo";
    let key_id: [u8; 32] = Sha256::digest(public_key.to_bytes()).into();
    let purpose = b"oidc.userinfo.name";
    let blob_digest: [u8; 32] = Sha256::digest(b"test-vault-ciphertext").into();
    let generation = 1_u64.to_be_bytes();
    let revision = 9_u64.to_be_bytes();
    let info = match context(&[
        PROBE_DOMAIN,
        &FORMAT_VERSION,
        &SUITE_IDS,
        recipient,
        &key_id,
        &generation,
    ]) {
        Some(value) => value,
        None => return false,
    };
    let aad = match context(&[
        origin,
        account,
        attribute,
        &revision,
        recipient,
        purpose,
        &blob_digest,
    ]) {
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
    let generation_number = u64::from_be_bytes(generation);
    let Some(frame) = encode_frame(
        encapped.to_bytes().as_slice(),
        &ciphertext,
        &key_id,
        generation_number,
    ) else {
        return false;
    };
    let Some((received_enc, received_ct)) = decode_frame(&frame, &key_id, generation_number) else {
        return false;
    };
    let Ok(received_enc) = <RecipientKem as hpke::Kem>::EncappedKey::from_bytes(received_enc)
    else {
        return false;
    };
    let open = |info: &[u8], aad: &[u8], ciphertext: &[u8]| {
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, RecipientKem>(
            &OpModeR::Base,
            &private_key,
            &received_enc,
            info,
        )
        .ok()?;
        receiver.open(ciphertext, aad).ok()
    };
    if open(&info, &aad, received_ct).as_deref() != Some(&data_key) {
        return false;
    }
    let wrong_revision = 10_u64.to_be_bytes();
    let Some(wrong_revision_aad) = context(&[
        origin,
        account,
        attribute,
        &wrong_revision,
        recipient,
        purpose,
        &blob_digest,
    ]) else {
        return false;
    };
    let Some(wrong_account_aad) = context(&[
        origin,
        b"test-account-2",
        attribute,
        &revision,
        recipient,
        purpose,
        &blob_digest,
    ]) else {
        return false;
    };
    let Some(wrong_attribute_aad) = context(&[
        origin,
        account,
        b"email",
        &revision,
        recipient,
        purpose,
        &blob_digest,
    ]) else {
        return false;
    };
    let Some(wrong_purpose_aad) = context(&[
        origin,
        account,
        attribute,
        &revision,
        recipient,
        b"oidc.id_token.name",
        &blob_digest,
    ]) else {
        return false;
    };
    let wrong_blob_digest: [u8; 32] = Sha256::digest(b"other-vault-ciphertext").into();
    let Some(wrong_blob_aad) = context(&[
        origin,
        account,
        attribute,
        &revision,
        recipient,
        purpose,
        &wrong_blob_digest,
    ]) else {
        return false;
    };
    let mut wrong_key_id = key_id;
    wrong_key_id[0] ^= 1;
    let Some(wrong_key_info) = context(&[
        PROBE_DOMAIN,
        &FORMAT_VERSION,
        &SUITE_IDS,
        recipient,
        &wrong_key_id,
        &generation,
    ]) else {
        return false;
    };
    let wrong_generation = 2_u64.to_be_bytes();
    let Some(wrong_generation_info) = context(&[
        PROBE_DOMAIN,
        &FORMAT_VERSION,
        &SUITE_IDS,
        recipient,
        &key_id,
        &wrong_generation,
    ]) else {
        return false;
    };
    let mut changed = ciphertext.clone();
    changed[0] ^= 1;
    let mut changed_header = frame.clone();
    changed_header[4] ^= 1;
    let mut changed_suite = frame.clone();
    changed_suite[10] ^= 1;
    let mut changed_enc = frame.clone();
    changed_enc[51] ^= 1;
    let mut changed_ct = frame.clone();
    changed_ct[51 + ENC_LEN] ^= 1;
    let open_frame = |frame: &[u8]| {
        let (enc, ct) = decode_frame(frame, &key_id, generation_number)?;
        let enc = <RecipientKem as hpke::Kem>::EncappedKey::from_bytes(enc).ok()?;
        let mut receiver = hpke::setup_receiver::<AesGcm256, HkdfSha256, RecipientKem>(
            &OpModeR::Base,
            &private_key,
            &enc,
            &info,
        )
        .ok()?;
        receiver.open(ct, &aad).ok()
    };
    open(&info, &wrong_revision_aad, &ciphertext).is_none()
        && open(&info, &wrong_account_aad, &ciphertext).is_none()
        && open(&info, &wrong_attribute_aad, &ciphertext).is_none()
        && open(&info, &wrong_purpose_aad, &ciphertext).is_none()
        && open(&info, &wrong_blob_aad, &ciphertext).is_none()
        && open(&wrong_key_info, &aad, &ciphertext).is_none()
        && open(&wrong_generation_info, &aad, &ciphertext).is_none()
        && open(&info, &aad, &changed).is_none()
        && decode_frame(&frame[..FRAME_LEN - 1], &key_id, generation_number).is_none()
        && decode_frame(
            &[frame.as_slice(), &[0]].concat(),
            &key_id,
            generation_number,
        )
        .is_none()
        && decode_frame(&changed_header, &key_id, generation_number).is_none()
        && decode_frame(&changed_suite, &key_id, generation_number).is_none()
        && decode_frame(&frame, &wrong_key_id, generation_number).is_none()
        && decode_frame(&frame, &key_id, generation_number + 1).is_none()
        && encode_frame(
            &frame[51..51 + ENC_LEN - 1],
            &ciphertext,
            &key_id,
            generation_number,
        )
        .is_none()
        && encode_frame(
            encapped.to_bytes().as_slice(),
            &ciphertext[..CT_LEN - 1],
            &key_id,
            generation_number,
        )
        .is_none()
        && encode_frame(encapped.to_bytes().as_slice(), &ciphertext, &key_id, 0).is_none()
        && open_frame(&changed_enc).is_none()
        && open_frame(&changed_ct).is_none()
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
