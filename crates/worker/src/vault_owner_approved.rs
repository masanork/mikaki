//! A verified v2 proposal is consumed only with its exact owner-record mutation.
use wasm_bindgen::JsValue;
use worker::{D1Database, D1PreparedStatement};

use crate::vault_approved::Approval;
use crate::vault_http::Owner;

pub(crate) async fn retry_owner(db: &D1Database, owner: &Owner) -> worker::Result<bool> {
    Ok(db
        .prepare(include_str!("../sql/select-owner-record-retry-owner.sql"))
        .bind(&[
            JsValue::from_str(&owner.secret_hash),
            JsValue::from_str(&owner.account_id),
            JsValue::from_str(&owner.credential_id),
        ])?
        .first::<serde_json::Value>(None)
        .await?
        .is_some())
}

pub(crate) struct Commit<'a> {
    pub approval: &'a Approval,
    pub account: &'a str,
    pub session_hash: &'a str,
    pub credential: &'a str,
    pub operation: &'a str,
    pub candidate_hash: &'a str,
    pub candidate: &'a str,
    pub origin: &'a str,
    pub vault: &'a str,
    pub key_generation: i64,
    pub owner_key_revision: i64,
    pub base_revision: i64,
    pub result_revision: i64,
    pub mutation_hash: &'a str,
}

impl Commit<'_> {
    fn identity(&self) -> Vec<JsValue> {
        vec![
            JsValue::from_str(&self.approval.proposal_id),
            JsValue::from_str(&self.approval.request_hash),
            JsValue::from_f64(self.base_revision as f64),
            JsValue::from_str(self.account),
            JsValue::from_str(self.operation),
            JsValue::from_str(self.candidate_hash),
            JsValue::from_str(self.origin),
            JsValue::from_str(self.session_hash),
            JsValue::from_str(self.credential),
            JsValue::from_str(self.vault),
            JsValue::from_f64(self.key_generation as f64),
            JsValue::from_f64(self.owner_key_revision as f64),
            JsValue::from_str(self.candidate),
        ]
    }

    pub async fn ready(&self, db: &D1Database) -> worker::Result<bool> {
        Ok(db
            .prepare(include_str!("../sql/select-owner-record-approval.sql"))
            .bind(&self.identity())?
            .first::<serde_json::Value>(None)
            .await?
            .is_some())
    }

    pub fn consume(&self, db: &D1Database) -> worker::Result<D1PreparedStatement> {
        db.prepare(format!(
            "UPDATE agent_attribute_proposal SET state='committed',payload=NULL \
             WHERE proposal_id=?1 AND EXISTS({})",
            include_str!("../sql/select-owner-record-approval.sql")
        ))
        .bind(&self.identity())
    }

    pub fn finish(&self, db: &D1Database) -> worker::Result<Vec<D1PreparedStatement>> {
        let mut values = self.identity();
        values.push(JsValue::from_f64(self.result_revision as f64));
        values.push(JsValue::from_str(self.mutation_hash));
        Ok(vec![
            db.prepare(include_str!("../sql/finish-owner-record-approval.sql"))
                .bind(&values)?,
            db.prepare(include_str!("../sql/guard-owner-record-approval.sql"))
                .bind(&values)?,
            db.prepare("DELETE FROM agent_attribute_commit_guard WHERE operation_id=?1")
                .bind(&[JsValue::from_str(self.operation)])?,
        ])
    }
}
