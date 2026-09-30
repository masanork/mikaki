//! Consume a verified proposal only in the same D1 transaction as the owner write.
use wasm_bindgen::JsValue;
use worker::{D1Database, D1PreparedStatement, Request};

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
    pub fn method(&self) -> String {
        format!("APPROVED/{}/{}", self.proposal_id, self.request_hash)
    }
}

pub(crate) struct Commit<'a> {
    pub approval: &'a Approval,
    pub account: &'a str,
    pub session_hash: &'a str,
    pub operation: &'a str,
    pub candidate_hash: &'a str,
    pub origin: &'a str,
    pub base_revision: i64,
    pub result_revision: i64,
    pub mutation_hash: &'a str,
}

impl Commit<'_> {
    pub async fn ready(&self, db: &D1Database) -> worker::Result<bool> {
        Ok(db.prepare("SELECT 1 AS valid FROM agent_attribute_proposal p JOIN agent_attribute_commit ac ON ac.proposal_id=p.proposal_id \
          WHERE p.proposal_id=?1 AND p.request_hash=?2 AND p.attribute_id='owner_note' AND p.base_revision=?3 \
          AND p.state='approved' AND p.expires_at>unixepoch() AND ac.account_id=?4 AND ac.operation_id=?5 \
          AND ac.candidate_sha256=?6 AND ac.origin=?7 AND ac.result_revision IS NULL")
          .bind(&self.identity())?.first::<serde_json::Value>(None).await?.is_some())
    }

    fn identity(&self) -> [JsValue; 7] {
        [
            JsValue::from_str(&self.approval.proposal_id),
            JsValue::from_str(&self.approval.request_hash),
            JsValue::from_f64(self.base_revision as f64),
            JsValue::from_str(self.account),
            JsValue::from_str(self.operation),
            JsValue::from_str(self.candidate_hash),
            JsValue::from_str(self.origin),
        ]
    }

    pub fn consume(&self, db: &D1Database) -> worker::Result<D1PreparedStatement> {
        let mut values = self.identity().to_vec();
        values.push(JsValue::from_str(self.session_hash));
        db.prepare("UPDATE agent_attribute_proposal SET state='committed',payload=NULL \
          WHERE proposal_id=?1 AND request_hash=?2 AND base_revision=?3 AND attribute_id='owner_note' \
          AND state='approved' AND expires_at>unixepoch() \
          AND EXISTS(SELECT 1 FROM agent_attribute_commit ac WHERE ac.proposal_id=?1 AND ac.account_id=?4 \
            AND ac.operation_id=?5 AND ac.candidate_sha256=?6 AND ac.origin=?7 AND ac.result_revision IS NULL) \
          AND EXISTS(SELECT 1 FROM agent_grant g \
            JOIN agent_attribute_capability cap ON cap.grant_id=g.grant_id \
            JOIN agent_recipient_key rk ON rk.key_id=g.recipient_key_id AND rk.state='active' \
            JOIN account_security a ON a.account_id=g.account_id AND a.active=1 AND a.epoch=g.owner_epoch \
            JOIN credential c ON c.credential_id=g.credential_id AND c.account_id=g.account_id AND c.active=1 \
            JOIN vault_attribute_head src ON src.account_id=g.account_id AND src.attribute_id='name' \
              AND src.deleted=0 AND src.revision=g.source_revision \
            WHERE g.grant_id=agent_attribute_proposal.grant_id AND g.account_id=?4 AND g.revoked=0 \
              AND g.revision=agent_attribute_proposal.grant_revision AND g.expires_at>unixepoch() \
              AND cap.attribute_id='owner_note' AND cap.base_revision=?3 AND cap.grant_revision=g.revision \
              AND cap.expires_at>unixepoch() \
              AND EXISTS(SELECT 1 FROM json_each(g.operations) WHERE value='propose')) \
          AND COALESCE((SELECT revision FROM vault_attribute_head WHERE account_id=?4 AND attribute_id='owner_note'),0)=?3 \
          AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
            JOIN account_security a ON a.account_id=ss.account_id AND a.active=1 AND a.epoch=ss.epoch \
            JOIN credential c ON c.credential_id=ss.credential_id AND c.account_id=ss.account_id AND c.active=1 \
            WHERE sx.secret_hash=?8 AND ss.account_id=?4 AND ss.revoked=0 AND ss.expires_at>unixepoch())")
            .bind(&values)
    }

    pub fn finish(&self, db: &D1Database) -> worker::Result<Vec<D1PreparedStatement>> {
        Ok(vec![
            db.prepare("UPDATE agent_attribute_commit SET result_revision=?1 WHERE proposal_id=?2 AND account_id=?3 \
              AND operation_id=?4 AND result_revision IS NULL AND EXISTS(SELECT 1 FROM vault_attribute_mutation \
              WHERE account_id=?3 AND operation_id=?4 AND request_hash=?5 AND result_revision=?1 AND deleted=0)")
              .bind(&[JsValue::from_f64(self.result_revision as f64), JsValue::from_str(&self.approval.proposal_id),
                JsValue::from_str(self.account), JsValue::from_str(self.operation), JsValue::from_str(self.mutation_hash)])?,
            db.prepare("INSERT INTO agent_attribute_commit_guard VALUES(?1, \
              EXISTS(SELECT 1 FROM vault_attribute_mutation m JOIN agent_attribute_commit ac \
                ON ac.account_id=m.account_id AND ac.operation_id=m.operation_id \
                JOIN agent_attribute_proposal p ON p.proposal_id=ac.proposal_id \
              WHERE m.account_id=?2 AND m.operation_id=?1 AND m.request_hash=?3 AND m.attribute_id='owner_note' \
                AND m.deleted=0 AND m.result_revision=?4 AND ac.result_revision=?4 AND p.state='committed'))")
              .bind(&[JsValue::from_str(self.operation), JsValue::from_str(self.account),
                JsValue::from_str(self.mutation_hash), JsValue::from_f64(self.result_revision as f64)])?,
            db.prepare("DELETE FROM agent_attribute_commit_guard WHERE operation_id=?1")
              .bind(&[JsValue::from_str(self.operation)])?,
        ])
    }
}
