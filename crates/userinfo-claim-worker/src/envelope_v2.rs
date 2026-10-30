//! Strict record-v2 ML-KEM-768 HPKE recipient wrap decoder.
//! Claim operations must supply every binding from trusted live D1 state.

#[cfg(any(test, target_arch = "wasm32"))]
use crate::crypto;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(any(test, target_arch = "wasm32"))]
use zeroize::Zeroizing;

#[cfg(any(test, target_arch = "wasm32"))]
const VERSION: u8 = 2;
#[cfg(any(test, target_arch = "wasm32"))]
const SUITE: [u8; 6] = [0, 0x41, 0, 1, 0, 2];
#[cfg(any(test, target_arch = "wasm32"))]
const DOMAIN: &[u8] = b"mikaki-vault-record-recipient-envelope-v2-draft04";
#[cfg(any(test, target_arch = "wasm32"))]
const FRAME_BYTES: usize = 1187;
#[cfg(any(test, target_arch = "wasm32"))]
const ENC_END: usize = 1139;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecordSource {
    pub storage_version: u8,
    pub origin: String,
    pub owner_id: String,
    pub vault_id: String,
    pub collection_id: String,
    pub record_id: String,
    pub kind: String,
    pub revision: u64,
    pub ciphertext_sha256: String,
}
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecordAuthority {
    pub key_generation: u64,
    pub owner_key_revision: u64,
}
impl RecordSource {
    pub fn valid(&self) -> bool {
        let identifier = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        let origin = url::Url::parse(&self.origin).ok().is_some_and(|u| {
            u.scheme() == "https" && u.origin().ascii_serialization() == self.origin
        });
        let digest = URL_SAFE_NO_PAD
            .decode(&self.ciphertext_sha256)
            .ok()
            .is_some_and(|b| b.len() == 32 && URL_SAFE_NO_PAD.encode(b) == self.ciphertext_sha256);
        self.storage_version == 2
            && origin
            && identifier(&self.owner_id)
            && identifier(&self.vault_id)
            && self.collection_id == "personal"
            && self.record_id == "name"
            && self.kind == "name"
            && (1..=9_007_199_254_740_991).contains(&self.revision)
            && digest
    }
}
impl RecordAuthority {
    pub fn valid(&self) -> bool {
        (1..=9_007_199_254_740_991).contains(&self.key_generation)
            && (1..=9_007_199_254_740_991).contains(&self.owner_key_revision)
    }
}
pub struct RecordBinding<'a> {
    pub source: &'a RecordSource,
    pub authority: &'a RecordAuthority,
    pub ciphertext: &'a [u8],
}

#[cfg(any(test, target_arch = "wasm32"))]
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
#[cfg(any(test, target_arch = "wasm32"))]
pub async fn open_record_data_key(
    seed: &[u8; 64],
    public_key: &[u8],
    key_id: &str,
    generation: u64,
    frame: &[u8],
    binding: &RecordBinding<'_>,
) -> Option<Zeroizing<[u8; 32]>> {
    if generation == 0
        || generation > 9_007_199_254_740_991
        || !binding.source.valid()
        || !binding.authority.valid()
        || URL_SAFE_NO_PAD.encode(crypto::sha256(binding.ciphertext).await?)
            != binding.source.ciphertext_sha256
        || binding.ciphertext.len() < 29
        || binding.ciphertext.len() > 24 * 1024
        || binding.ciphertext[0] != 2
        || public_key.len() != 1184
        || frame.len() != FRAME_BYTES
        || &frame[..4] != b"MKVR"
        || frame[4] != VERSION
        || frame[5..11] != SUITE
        || frame[43..51] != generation.to_be_bytes()
    {
        return None;
    }
    if crypto::public_key(seed).await?.as_slice() != public_key {
        return None;
    }
    let expected_key_id = crypto::sha256(public_key).await?;
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
    let digest = crypto::sha256(binding.ciphertext).await?;
    let source = binding.source;
    let aad = context(&[
        b"2",
        source.origin.as_bytes(),
        source.owner_id.as_bytes(),
        source.vault_id.as_bytes(),
        source.collection_id.as_bytes(),
        source.record_id.as_bytes(),
        source.kind.as_bytes(),
        &source.revision.to_be_bytes(),
        &digest,
        &binding.authority.key_generation.to_be_bytes(),
        &binding.authority.owner_key_revision.to_be_bytes(),
        b"userinfo",
        b"oidc.userinfo.name",
    ])?;
    let plaintext =
        crypto::open_hpke(seed, &frame[51..ENC_END], &info, &aad, &frame[ENC_END..]).await?;
    Some(Zeroizing::new(plaintext.as_slice().try_into().ok()?))
}

/// This record profile has no version-1 fallback and never receives an owner wrapper.
#[cfg(any(test, target_arch = "wasm32"))]
pub async fn decrypt_record_name(
    data_key: &[u8; 32],
    source: &RecordSource,
    ciphertext: &[u8],
) -> Option<Zeroizing<String>> {
    if !source.valid()
        || ciphertext.len() < 29
        || ciphertext.len() > 24 * 1024
        || ciphertext[0] != 2
        || URL_SAFE_NO_PAD.encode(crypto::sha256(ciphertext).await?) != source.ciphertext_sha256
    {
        return None;
    }
    let aad = context(&[
        b"mikaki-vault-record-content",
        b"2",
        source.origin.as_bytes(),
        source.owner_id.as_bytes(),
        source.vault_id.as_bytes(),
        source.collection_id.as_bytes(),
        source.record_id.as_bytes(),
        source.kind.as_bytes(),
        source.revision.to_string().as_bytes(),
    ])?;
    let plaintext = crypto::decrypt(data_key, &ciphertext[1..13], &aad, &ciphertext[13..]).await?;
    if plaintext.is_empty() || plaintext.len() > 1024 {
        return None;
    }
    let name = std::str::from_utf8(&plaintext).ok()?;
    // Same UTF-16 code-unit bound as the saved-name editor, without normalization.
    if name.encode_utf16().count() > 256 {
        return None;
    }
    Some(Zeroizing::new(name.to_owned()))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use aes_gcm::{
        Aes256Gcm, KeyInit as _, Nonce,
        aead::{Aead as _, Payload},
    };
    use sha2::{Digest as _, Sha256};

    fn open_record_data_key(
        seed: &[u8; 64],
        public: &[u8],
        key_id: &str,
        generation: u64,
        frame: &[u8],
        binding: &RecordBinding<'_>,
    ) -> Option<Zeroizing<[u8; 32]>> {
        crypto::ready(super::open_record_data_key(
            seed, public, key_id, generation, frame, binding,
        ))
    }
    fn decrypt_record_name(
        key: &[u8; 32],
        source: &RecordSource,
        ciphertext: &[u8],
    ) -> Option<Zeroizing<String>> {
        crypto::ready(super::decrypt_record_name(key, source, ciphertext))
    }
    #[test]
    fn independent_noble_record_fixture_and_v1_isolation() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../design/probes/pqc/record-userinfo-fixture.json"
        ))
        .unwrap();
        let seed: [u8; 64] = URL_SAFE_NO_PAD
            .decode(fixture["seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let public = URL_SAFE_NO_PAD
            .decode(fixture["recipient"]["public_key"].as_str().unwrap())
            .unwrap();
        let key_id = fixture["recipient"]["key_id"].as_str().unwrap();
        let source: RecordSource = serde_json::from_value(fixture["source"].clone()).unwrap();
        let authority: RecordAuthority =
            serde_json::from_value(fixture["authority"].clone()).unwrap();
        let frame = URL_SAFE_NO_PAD
            .decode(fixture["frame"].as_str().unwrap())
            .unwrap();
        let ciphertext = URL_SAFE_NO_PAD
            .decode(fixture["ciphertext"].as_str().unwrap())
            .unwrap();
        let open = |s: &RecordSource, a: &RecordAuthority, f: &[u8], c: &[u8]| {
            open_record_data_key(
                &seed,
                &public,
                key_id,
                1,
                f,
                &RecordBinding {
                    source: s,
                    authority: a,
                    ciphertext: c,
                },
            )
        };
        let key = open(&source, &authority, &frame, &ciphertext).unwrap();
        assert_eq!(
            decrypt_record_name(&key, &source, &ciphertext)
                .unwrap()
                .as_str(),
            fixture["name"].as_str().unwrap()
        );
        for field in [
            "origin",
            "owner_id",
            "vault_id",
            "collection_id",
            "record_id",
            "kind",
            "revision",
            "ciphertext_sha256",
            "storage_version",
        ] {
            let mut changed = fixture["source"].clone();
            changed[field] = match field {
                "origin" => serde_json::json!("https://other.example"),
                "revision" => serde_json::json!(10),
                "storage_version" => serde_json::json!(1),
                "ciphertext_sha256" => serde_json::json!(URL_SAFE_NO_PAD.encode([0; 32])),
                _ => serde_json::json!("other"),
            };
            let changed = serde_json::from_value(changed).unwrap();
            assert!(
                open(&changed, &authority, &frame, &ciphertext).is_none(),
                "source {field}"
            );
            assert!(
                decrypt_record_name(&key, &changed, &ciphertext).is_none(),
                "content source {field}"
            );
        }
        for field in ["key_generation", "owner_key_revision"] {
            let mut changed = fixture["authority"].clone();
            changed[field] = serde_json::json!(2);
            assert!(
                open(
                    &source,
                    &serde_json::from_value(changed).unwrap(),
                    &frame,
                    &ciphertext
                )
                .is_none()
            );
        }
        for offset in [0, 4, 5, 11, 43, 51, 1186] {
            let mut changed = frame.clone();
            changed[offset] ^= 1;
            assert!(
                open(&source, &authority, &changed, &ciphertext).is_none(),
                "frame byte {offset}"
            );
        }
        assert!(open(&source, &authority, &frame[..1186], &ciphertext).is_none());
        assert!(
            open(
                &source,
                &authority,
                &[frame.clone(), vec![0]].concat(),
                &ciphertext
            )
            .is_none()
        );
        // Retired v1 headers cannot enter the record-only decoder.
        let mut legacy_frame = frame.clone();
        legacy_frame[..4].copy_from_slice(b"MKVE");
        legacy_frame[4] = 1;
        assert!(open(&source, &authority, &legacy_frame, &ciphertext).is_none());
        let mut legacy_ciphertext = ciphertext.clone();
        legacy_ciphertext[0] = 1;
        assert!(open(&source, &authority, &frame, &legacy_ciphertext).is_none());
        assert!(decrypt_record_name(&key, &source, &legacy_ciphertext).is_none());
        let mut changed = ciphertext.clone();
        changed[13] ^= 1;
        assert!(open(&source, &authority, &frame, &changed).is_none());
    }
    #[test]
    fn strict_source_and_name_utf16_limits() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../design/probes/pqc/record-userinfo-fixture.json"
        ))
        .unwrap();
        let source: RecordSource = serde_json::from_value(fixture["source"].clone()).unwrap();
        assert!(source.valid());
        for origin in [
            "http://mikaki.example",
            "https://mikaki.example/",
            "https://u@mikaki.example",
            "https://mikaki.example?x=1",
        ] {
            let mut s = source.clone();
            s.origin = origin.into();
            assert!(!s.valid());
        }
        let mut extra = fixture["source"].clone();
        extra["key_envelope"] = serde_json::json!("never permitted");
        assert!(serde_json::from_value::<RecordSource>(extra).is_err());
        let encrypt = |bytes: &[u8]| {
            let mut s = source.clone();
            let key = [0x51; 32];
            let nonce = [7; 12];
            let aad = context(&[
                b"mikaki-vault-record-content",
                b"2",
                s.origin.as_bytes(),
                s.owner_id.as_bytes(),
                s.vault_id.as_bytes(),
                s.collection_id.as_bytes(),
                s.record_id.as_bytes(),
                s.kind.as_bytes(),
                s.revision.to_string().as_bytes(),
            ])
            .unwrap();
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            let encrypted = cipher
                .encrypt(
                    &Nonce::try_from(nonce.as_slice()).unwrap(),
                    Payload {
                        msg: bytes,
                        aad: &aad,
                    },
                )
                .unwrap();
            let body = [vec![2], nonce.to_vec(), encrypted].concat();
            s.ciphertext_sha256 = URL_SAFE_NO_PAD.encode(Sha256::digest(&body));
            decrypt_record_name(&key, &s, &body)
        };
        assert!(encrypt("山".repeat(256).as_bytes()).is_some());
        assert!(encrypt("😀".repeat(128).as_bytes()).is_some());
        assert!(encrypt("😀".repeat(129).as_bytes()).is_none());
        assert!(encrypt(&[0xff]).is_none());
        assert!(encrypt(&[]).is_none());
    }
}
