//! Consume a verified proposal only in the same D1 transaction as the owner write.
use worker::Request;

pub(crate) struct Approval {
    pub proposal_id: String,
    pub request_hash: String,
}

impl Approval {
    pub fn read(request: &Request) -> worker::Result<Option<Self>> {
        let id = request.headers().get("X-Attribute-Proposal")?;
        let hash = request.headers().get("X-Proposal-Hash")?;
        let valid = |value: &str| {
            value.len() == 43
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        };
        Ok(match (id, hash) {
            (Some(proposal_id), Some(request_hash))
                if valid(&proposal_id) && valid(&request_hash) =>
            {
                Some(Self {
                    proposal_id,
                    request_hash,
                })
            }
            _ => None,
        })
    }
}
