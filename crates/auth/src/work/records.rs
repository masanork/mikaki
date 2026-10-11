//! Versioned trusted-storage codecs. No domain type implements Deserialize.
//! Decoding checks structure/digests, never authenticates a principal or supplies
//! current permission. The primary-store adapter supplies current mutable state.
use super::*;
use serde::de::DeserializeOwned;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    version: u32,
    kind: String,
    data: T,
}

pub(super) fn encode<T: Serialize>(kind: &str, data: &T) -> Result<String, Denied> {
    let text = serde_json::to_string(&Record {
        version: 1,
        kind: kind.into(),
        data,
    })
    .map_err(|_| Denied::InvalidInput)?;
    if text.len() > 32768 {
        return Err(Denied::InvalidInput);
    }
    Ok(text)
}

pub(super) fn decode<T: DeserializeOwned>(kind: &str, text: &str) -> Result<T, Denied> {
    if text.len() > 32768 {
        return Err(Denied::InvalidInput);
    }
    let record: Record<T> = serde_json::from_str(text).map_err(|_| Denied::InvalidInput)?;
    if record.version != 1 || record.kind != kind {
        return Err(Denied::InvalidInput);
    }
    Ok(record.data)
}

pub(super) fn state(revision: u64, revoked: bool) -> Result<(), Denied> {
    // v1 has only initial state and one idempotent irreversible revocation.
    if (revision, revoked) != (1, false) && (revision, revoked) != (2, true) {
        return Err(Denied::InvalidInput);
    }
    Ok(())
}

pub(super) fn producer(producer: &delegation::ProducerRevision) -> Result<(), Denied> {
    // Revisions captured at review may include a revoked retained producer.
    stored_number(producer.grant_revision(), false)?;
    stored_number(producer.run_revision(), false)
}
