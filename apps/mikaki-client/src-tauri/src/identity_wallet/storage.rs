//! Typed bounded storage codec, also exercised on the host without Android/Keystore.
use super::*;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;
pub(super) const MAX_BYTES: usize = 384000;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub version: u8,
    pub haip: Option<bool>,
    pub id: String,
    pub credential: String,
    #[serde(default = "default_format")]
    pub format: String,
    pub issuer_key: PublicJwk,
    pub issuer_kid: String,
    pub holder: PublicJwk,
    pub expires_at: u64,
}
fn default_format() -> String {
    "dc+sd-jwt".into()
}
impl Drop for Record {
    fn drop(&mut self) {
        self.credential.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    version: u8,
    receipts: Vec<Record>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Stored {
    Inventory(Inventory),
    Single(Record),
}
pub(super) fn encode(records: &[Record], configured: bool) -> Result<Zeroizing<Vec<u8>>, String> {
    #[derive(Serialize)]
    struct Envelope<'a> {
        version: u8,
        receipts: &'a [Record],
    }
    let plain = Zeroizing::new(
        serde_json::to_vec(&Envelope {
            version: 3,
            receipts: records,
        })
        .map_err(|_| "wallet_storage_unavailable")?,
    );
    decode(&plain, configured)?;
    Ok(plain)
}
pub(super) fn decode(bytes: &[u8], configured: bool) -> Result<(Vec<Record>, bool), String> {
    if bytes.len() > MAX_BYTES {
        return Err("wallet_invalid".into());
    }
    let (records, migrate) =
        match serde_json::from_slice::<Stored>(bytes).map_err(|_| "wallet_invalid")? {
            Stored::Single(record) => (vec![record], true),
            Stored::Inventory(inventory) if inventory.version == 3 => (inventory.receipts, false),
            _ => return Err("wallet_invalid".into()),
        };
    if records.is_empty() || records.len() > 8 {
        return Err("wallet_invalid".into());
    }
    let mut ids = std::collections::HashSet::new();
    let mut credentials = std::collections::HashSet::new();
    for record in &records {
        restoration_profile(record.version, record.haip, configured)?;
        if (!migrate && record.version != 2)
            || record.id.len() != 32
            || !record
                .id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !ids.insert(record.id.as_str())
            || !credentials.insert(record.credential.as_str())
            || record.credential.is_empty()
            || record.credential.len() > 43000
            || !matches!(record.format.as_str(), "dc+sd-jwt" | "mso_mdoc")
        {
            return Err("wallet_invalid".into());
        }
    }
    Ok((records, migrate))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(id: u8) -> Value {
        let key = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        json!({"version":2,"haip":true,"id":format!("{id:032x}"),"credential":format!("fixture-{id}"),"format":"dc+sd-jwt","issuer_key":PublicJwk::from_key(key.verifying_key()),"issuer_kid":"issuer","holder":PublicJwk::from_key(key.verifying_key()),"expires_at":2000})
    }
    #[test]
    fn identity_inventory_codec_migrates_legacy_and_preserves_all_v3_slots() {
        let single = record(1);
        let (records, migrate) = decode(&serde_json::to_vec(&single).unwrap(), true).unwrap();
        assert!(migrate);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].credential, "fixture-1");
        assert_eq!(records[0].expires_at, 2000);
        assert_eq!(records[0].issuer_kid, "issuer");
        assert_eq!(records[0].holder, records[0].issuer_key);
        let mut old = single.clone();
        old["version"] = json!(1);
        old.as_object_mut().unwrap().remove("haip");
        assert!(decode(&serde_json::to_vec(&old).unwrap(), true).is_err());
        assert!(decode(&serde_json::to_vec(&old).unwrap(), false).unwrap().1);
        let values: Vec<_> = (1..=8).map(record).collect();
        let (records, migrate) = decode(
            &serde_json::to_vec(&json!({"version":3,"receipts":values})).unwrap(),
            true,
        )
        .unwrap();
        assert!(!migrate);
        let encoded = encode(&records, true).unwrap();
        assert!(!decode(&encoded, true).unwrap().1);
        assert_eq!(records.len(), 8);
        assert_eq!(records[7].credential, "fixture-8");
    }
    #[test]
    fn identity_inventory_codec_rejects_duplicates_downgrades_and_out_of_bounds_records() {
        for value in [
            json!({"version":3,"receipts":[]}),
            json!({"version":4,"receipts":[record(1)]}),
            json!({"version":3,"receipts":[record(1),record(1)]}),
            json!({"version":3,"receipts":(1..=9).map(record).collect::<Vec<_>>()}),
        ] {
            assert!(decode(&serde_json::to_vec(&value).unwrap(), true).is_err());
        }
        for field in ["id", "credential", "version", "haip", "format"] {
            let mut value = record(1);
            value[field] = match field {
                "version" => json!(1),
                "haip" => json!(null),
                "id" => json!("../holder"),
                "format" => json!("unknown"),
                _ => json!("x".repeat(43001)),
            };
            assert!(decode(
                &serde_json::to_vec(&json!({"version":3,"receipts":[value]})).unwrap(),
                true
            )
            .is_err());
        }
        let encoded = serde_json::to_string(&record(1)).unwrap();
        let ambiguous = encoded.replacen("{", "{\"haip\":false,", 1);
        assert!(decode(ambiguous.as_bytes(), true).is_err());
        let duplicate_version = format!("{{\"version\":3,\"version\":3,\"receipts\":[{encoded}]}}");
        assert!(decode(duplicate_version.as_bytes(), true).is_err());
        assert!(decode(&vec![b' '; MAX_BYTES + 1], true).is_err());
        assert!(decode(encoded.as_bytes(), false).is_err());
    }
}
