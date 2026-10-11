use super::super::records::{decode, encode};
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRequest {
    input: RequestInput,
    owner: Id,
    owner_epoch: u64,
    policy_revision: u64,
    digest: Digest,
}

impl WorkRequest {
    pub fn authority_record(&self) -> Result<String, Denied> {
        encode("request", self)
    }

    /// Decode ONLY an immutable row from the trusted primary store. This is not
    /// consent or authentication; live checks still precede every operation.
    pub fn restore_authority_record(text: &str) -> Result<Self, Denied> {
        let raw: StoredRequest = decode("request", text)?;
        raw.input.validate_shape()?;
        stored_number(raw.owner_epoch, true)?;
        stored_number(raw.policy_revision, false)?;
        let request = raw
            .input
            .bind(raw.owner, raw.owner_epoch, raw.policy_revision);
        if request.digest != raw.digest {
            return Err(Denied::ReviewMismatch);
        }
        Ok(request)
    }

    pub fn input(&self) -> &RequestInput {
        &self.input
    }
    pub fn owner_id(&self) -> &str {
        &self.owner.0
    }
    pub fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }
    pub fn policy_generation(&self) -> u64 {
        self.policy_revision
    }
}
