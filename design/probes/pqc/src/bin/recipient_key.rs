//! Offline key generation and proof of possession for the future UserInfo
//! recipient. Never writes a secret to stdout or D1.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ml_kem::{DecapsulationKey, MlKem768, Seed, kem::KeyExport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

#[cfg(not(unix))]
compile_error!("recipient_key requires Unix file permission support");

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicRecord {
    key_id: String,
    service_id: String,
    algorithm: String,
    public_key: String,
    secret_ref: String,
    generation: u64,
}

fn public_record(
    seed: &[u8; 64],
    secret_ref: &str,
    generation: u64,
) -> Result<PublicRecord, String> {
    if !secret_ref.starts_with("VAULT_USERINFO_MLKEM_")
        || secret_ref.len() > 128
        || !secret_ref
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        || generation == 0
    {
        return Err("invalid secret reference or generation".into());
    }
    let key = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
    let public = key.encapsulation_key().to_bytes();
    Ok(PublicRecord {
        key_id: URL_SAFE_NO_PAD.encode(Sha256::digest(public)),
        service_id: "userinfo".into(),
        algorithm: "ML-KEM-768".into(),
        public_key: URL_SAFE_NO_PAD.encode(public),
        secret_ref: secret_ref.into(),
        generation,
    })
}

fn read_seed(path: &Path) -> Result<Zeroizing<[u8; 64]>, String> {
    let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("private seed file is accessible by group or others".into());
    }
    if metadata.len() > 100 {
        return Err("private seed file is too large".into());
    }
    let mut text = Zeroizing::new(String::new());
    File::open(path)
        .and_then(|mut file| file.read_to_string(&mut text))
        .map_err(|e| e.to_string())?;
    let value = text.trim_end_matches('\n');
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| "invalid private seed")?,
    );
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err("noncanonical private seed".into());
    }
    let seed = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "invalid private seed length")?;
    Ok(Zeroizing::new(seed))
}

fn verify(private_path: &Path, public_path: &Path) -> Result<(), String> {
    let seed = read_seed(private_path)?;
    let record: PublicRecord =
        serde_json::from_slice(&fs::read(public_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let expected = public_record(&seed, &record.secret_ref, record.generation)?;
    if record.service_id != expected.service_id
        || record.algorithm != expected.algorithm
        || record.key_id != expected.key_id
        || record.public_key != expected.public_key
    {
        return Err("recipient public/private key mismatch".into());
    }
    Ok(())
}

fn generate(
    private_path: &Path,
    public_path: &Path,
    secret_ref: &str,
    generation: u64,
) -> Result<(), String> {
    if private_path == public_path || public_path.exists() {
        return Err("output paths must be distinct and unused".into());
    }
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let private_parent = private_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if private_parent.starts_with(repository) {
        return Err("private seed file must be outside the repository".into());
    }
    let mut seed = Zeroizing::new([0_u8; 64]);
    getrandom::fill(&mut seed[..]).map_err(|e| e.to_string())?;
    let record = public_record(&seed, secret_ref, generation)?;
    let mut private = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(private_path)
        .map_err(|e| e.to_string())?;
    let private_text = Zeroizing::new(format!("{}\n", URL_SAFE_NO_PAD.encode(*seed)));
    private
        .write_all(private_text.as_bytes())
        .and_then(|()| private.sync_all())
        .map_err(|e| e.to_string())?;
    let mut public = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(public_path)
        .map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(&mut public, &record).map_err(|e| e.to_string())?;
    public
        .write_all(b"\n")
        .and_then(|()| public.sync_all())
        .map_err(|e| e.to_string())?;
    verify(private_path, public_path)?;
    println!(
        "created recipient key {} (private seed only in {})",
        record.key_id,
        private_path.display()
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    match args.as_slice() {
        [_, command, private, public, secret_ref, generation] if command == "generate" => {
            let generation = generation.parse::<u64>()?;
            generate(Path::new(private), Path::new(public), secret_ref, generation)
                .map_err(io::Error::other)?;
        }
        [_, command, private, public] if command == "verify" => {
            verify(Path::new(private), Path::new(public)).map_err(io::Error::other)?;
            println!("recipient key pair matches");
        }
        _ => return Err("usage: recipient_key generate <private-seed-file> <public-json-file> <secret-ref> <generation> | verify <private-seed-file> <public-json-file>".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{Deserializable, Kem as _, Serializable, kem::MlKem768 as HpkeMlKem768};

    #[test]
    fn public_record_is_derived_from_seed_and_identifier_changes_with_seed() {
        let first = public_record(&[0x71; 64], "VAULT_USERINFO_MLKEM_A", 1).unwrap();
        let second = public_record(&[0x72; 64], "VAULT_USERINFO_MLKEM_A", 1).unwrap();
        assert_ne!(first.key_id, second.key_id);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(&first.public_key).unwrap().len(),
            1184
        );
        assert_eq!(first.key_id.len(), 43);
        let hpke_private =
            <HpkeMlKem768 as hpke::Kem>::PrivateKey::from_bytes(&[0x71; 64]).unwrap();
        assert_eq!(
            HpkeMlKem768::sk_to_pk(&hpke_private).to_bytes().as_slice(),
            URL_SAFE_NO_PAD.decode(&first.public_key).unwrap()
        );
    }

    #[test]
    fn generated_seed_is_owner_only_and_matches_public_record() {
        let dir =
            std::env::temp_dir().join(format!("mikaki-recipient-key-test-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let private = dir.join("seed.txt");
        let public = dir.join("public.json");
        generate(&private, &public, "VAULT_USERINFO_MLKEM_TEST", 1).unwrap();
        assert_eq!(
            fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o600
        );
        verify(&private, &public).unwrap();
        assert!(generate(&private, &public, "VAULT_USERINFO_MLKEM_TEST", 1).is_err());
        fs::remove_file(private).unwrap();
        fs::remove_file(public).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
