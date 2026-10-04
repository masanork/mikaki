//! Durable DPoP replay acceptance. No process-local authorization state.
use mikaki_oidc::VerifiedDpopProof;
use serde::Deserialize;
use wasm_bindgen::JsValue;
use worker::d1::{D1Database, D1PreparedStatement};

#[derive(Deserialize)]
struct Receipt {
    accepted_by: String,
}

#[derive(Deserialize)]
struct NonceRow {
    nonce: String,
}

#[derive(Deserialize)]
pub(super) struct VaultAccountRow {
    pub account_id: String,
}

#[derive(Clone, Copy)]
pub(super) enum NonceScope {
    AuthorizationServer,
    ResourceServer,
}

impl NonceScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationServer => "as",
            Self::ResourceServer => "rs",
        }
    }
}

/// Return the current challenge. Creating a new nonce and selecting the winner
/// occur in one D1 transaction; another isolate's concurrent winner is safe.
pub(super) async fn current_nonce(
    db: &D1Database,
    scope: NonceScope,
    random: &mut impl mikaki_oidc::CryptographicRandom,
) -> worker::Result<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut bytes = [0u8; 32];
    random
        .fill(&mut bytes)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let candidate = URL_SAFE_NO_PAD.encode(bytes);
    bytes.fill(0);
    let scope = JsValue::from_str(scope.as_str());
    let results = db.batch(vec![
        db.prepare("DELETE FROM dpop_nonce WHERE accept_until<=CAST(strftime('%s','now') AS INTEGER)"),
        db.prepare("INSERT INTO dpop_nonce(scope,nonce,challenge_until,accept_until) \
            SELECT ?1,?2,CAST(strftime('%s','now') AS INTEGER)+60,CAST(strftime('%s','now') AS INTEGER)+120 \
            WHERE NOT EXISTS (SELECT 1 FROM dpop_nonce WHERE scope=?1 \
              AND challenge_until>CAST(strftime('%s','now') AS INTEGER)) \
            AND (SELECT count(*) FROM dpop_nonce WHERE scope=?1)<4")
            .bind(&[scope.clone(), JsValue::from_str(&candidate)])?,
        db.prepare("SELECT nonce FROM dpop_nonce WHERE scope=?1 \
            AND challenge_until>CAST(strftime('%s','now') AS INTEGER) \
            ORDER BY challenge_until DESC,nonce LIMIT 1").bind(&[scope])?,
    ]).await?;
    results[2]
        .results::<NonceRow>()?
        .into_iter()
        .next()
        .map(|row| row.nonce)
        .ok_or_else(|| worker::Error::RustError("server_error".into()))
}

pub(super) async fn accepts_nonce(
    db: &D1Database,
    scope: NonceScope,
    nonce: Option<&str>,
) -> worker::Result<bool> {
    let Some(nonce) = nonce else {
        return Ok(false);
    };
    Ok(db
        .prepare(
            "SELECT 1 AS accepted FROM dpop_nonce WHERE scope=?1 AND nonce=?2 \
        AND accept_until>CAST(strftime('%s','now') AS INTEGER)",
        )
        .bind(&[JsValue::from_str(scope.as_str()), JsValue::from_str(nonce)])?
        .first::<i64>(Some("accepted"))
        .await?
        .is_some())
}

fn values(proof: &VerifiedDpopProof, operation: &str) -> Vec<JsValue> {
    vec![
        JsValue::from_str(proof.thumbprint()),
        JsValue::from_str(proof.jti_hash()),
        JsValue::from_str(operation),
        JsValue::from_str(&proof.retain_until().to_string()),
        JsValue::from_str(&proof.issued_at().to_string()),
    ]
}

fn cleanup(db: &D1Database) -> D1PreparedStatement {
    // Strictly less: a proof is still valid exactly at its inclusive deadline.
    db.prepare(
        "DELETE FROM dpop_proof_use WHERE rowid IN (SELECT rowid FROM dpop_proof_use WHERE retain_until < CAST(strftime('%s','now') AS INTEGER) ORDER BY retain_until LIMIT 1000)",
    )
}

const ACCEPT: &str = "INSERT INTO dpop_proof_use(jkt,jti_hash,accepted_by,retain_until) \
    SELECT ?1,?2,?3,?4 WHERE CAST(?5 AS INTEGER) <= CAST(strftime('%s','now') AS INTEGER)+10 \
    AND CAST(?4 AS INTEGER) >= CAST(strftime('%s','now') AS INTEGER) \
    AND (SELECT count(*) FROM dpop_proof_use) < 10000 ";

pub(super) async fn accept_token_proof(
    db: &D1Database,
    proof: &VerifiedDpopProof,
    operation: &str,
    require_nonce: bool,
) -> worker::Result<()> {
    accept_identity_proof(
        db,
        proof,
        operation,
        require_nonce,
        NonceScope::AuthorizationServer,
    )
    .await
}

pub(super) async fn accept_identity_proof(
    db: &D1Database,
    proof: &VerifiedDpopProof,
    operation: &str,
    require_nonce: bool,
    scope: NonceScope,
) -> worker::Result<()> {
    let mut bindings = values(proof, operation);
    let nonce_check = if require_nonce {
        bindings.push(
            proof
                .nonce()
                .map(JsValue::from_str)
                .unwrap_or(JsValue::NULL),
        );
        format!(
            " AND EXISTS (SELECT 1 FROM dpop_nonce WHERE scope='{}' AND nonce=?6 AND accept_until>CAST(strftime('%s','now') AS INTEGER))",
            scope.as_str()
        )
    } else {
        String::new()
    };
    let results = db
        .batch(vec![
            cleanup(db),
            db.prepare(format!(
                "{ACCEPT}{nonce_check} ON CONFLICT(jkt,jti_hash) DO NOTHING RETURNING accepted_by"
            ))
            .bind(&bindings)?,
        ])
        .await?;
    // Storage failures bubble up as server_error; a replay/full/expired ledger
    // never grants access. A valid proof used with an invalid grant stays used.
    let receipts = results[1].results::<Receipt>()?;
    if !receipts
        .iter()
        .any(|receipt| receipt.accepted_by == operation)
    {
        return Err(worker::Error::RustError("invalid_dpop_proof".into()));
    }
    Ok(())
}

pub(super) async fn authorize_resource(
    db: &D1Database,
    proof: &VerifiedDpopProof,
    operation: &str,
    token_hash: &str,
    require_nonce: bool,
) -> worker::Result<Option<String>> {
    let mut bindings = values(proof, operation);
    bindings.push(JsValue::from_str(token_hash));
    let nonce_check = if require_nonce {
        bindings.push(
            proof
                .nonce()
                .map(JsValue::from_str)
                .unwrap_or(JsValue::NULL),
        );
        " AND EXISTS (SELECT 1 FROM dpop_nonce WHERE scope='rs' AND nonce=?7 \
          AND accept_until>CAST(strftime('%s','now') AS INTEGER))"
    } else {
        ""
    };
    let results = db
        .batch(vec![
            cleanup(db),
            db.prepare(format!(
                "{ACCEPT} AND EXISTS (SELECT 1 FROM token_issue ti \
            JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
            JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
            WHERE ti.access_hash=?6 AND ti.dpop_jkt=?1 AND ti.revoked=0 \
            AND NOT EXISTS (SELECT 1 FROM vault_oauth_token_context vt WHERE vt.access_hash=ti.access_hash) \
            AND ti.access_expires_at>CAST(strftime('%s','now') AS INTEGER)) \
            {nonce_check} ON CONFLICT(jkt,jti_hash) DO NOTHING"
            ))
            .bind(&bindings)?,
            db.prepare(
                "SELECT v.sub FROM token_issue ti \
            JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
            JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
            JOIN dpop_proof_use p ON p.jkt=ti.dpop_jkt \
            WHERE ti.access_hash=?6 AND ti.revoked=0 \
            AND NOT EXISTS (SELECT 1 FROM vault_oauth_token_context vt WHERE vt.access_hash=ti.access_hash) \
            AND ti.access_expires_at>CAST(strftime('%s','now') AS INTEGER) \
            AND p.jkt=?1 AND p.jti_hash=?2 AND p.accepted_by=?3 \
            AND p.retain_until>=CAST(strftime('%s','now') AS INTEGER)",
            )
            .bind(&bindings[..6])?,
        ])
        .await?;
    Ok(results[2]
        .results::<super::UserInfoRow>()?
        .into_iter()
        .next()
        .map(|row| row.sub))
}

/// Accept one Vault resource proof only while the exact token audience,
/// attribute, grant revision, client, and owner session are still eligible.
pub(super) async fn authorize_vault_resource(
    db: &D1Database,
    proof: &VerifiedDpopProof,
    operation: &str,
    token_hash: &str,
    attribute: &str,
    require_nonce: bool,
) -> worker::Result<Option<VaultAccountRow>> {
    let mut bindings = values(proof, operation);
    bindings.push(JsValue::from_str(token_hash));
    bindings.push(JsValue::from_str(attribute));
    let nonce_check = if require_nonce {
        bindings.push(
            proof
                .nonce()
                .map(JsValue::from_str)
                .unwrap_or(JsValue::NULL),
        );
        " AND EXISTS (SELECT 1 FROM dpop_nonce WHERE scope='rs' AND nonce=?8 \
          AND accept_until>CAST(strftime('%s','now') AS INTEGER))"
    } else {
        ""
    };
    let authority = "FROM token_issue ti \
        JOIN vault_oauth_token_context vt ON vt.access_hash=ti.access_hash \
        JOIN vault_oauth_grant g ON g.grant_id=vt.grant_id \
        JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
        JOIN vault_oauth_code_context vc ON vc.code_hash=ac.code_hash \
        JOIN code_context cc ON cc.code_hash=ac.code_hash \
        JOIN valid_client_session s ON s.client_id=ac.client_id AND s.sid=ac.sid \
        JOIN client c ON c.client_id=ac.client_id \
        WHERE ti.access_hash=?6 AND ti.dpop_jkt=?1 AND ti.revoked=0 \
        AND ti.access_expires_at>unixepoch() AND ac.consumed_by=ti.operation_id \
        AND vt.resource='https://mikaki.tossa.app/vault-api/' \
        AND vt.attribute_id=?7 AND vt.grant_version=g.version \
        AND vt.attribute_id=g.attribute_id AND vt.resource=g.resource \
        AND vc.grant_id=g.grant_id AND vc.grant_version=g.version \
        AND vc.attribute_id=?7 AND vc.resource=vt.resource \
        AND g.action='read_ciphertext' AND g.revoked=0 \
        AND g.expires_at>unixepoch() AND ti.access_expires_at<=g.expires_at \
        AND g.account_id=s.account_id AND g.client_id=ac.client_id \
        AND g.client_revision=ac.client_revision \
        AND c.client_type='native' AND c.auth_method='none' \
        AND c.active=1 AND c.revision=ac.client_revision \
        AND cc.scope IN ('openid vault.read','vault.read openid')";
    let proof_check = format!(
        "{ACCEPT} AND EXISTS (SELECT 1 {authority}) {nonce_check} \
         ON CONFLICT(jkt,jti_hash) DO NOTHING"
    );
    let account_query = format!(
        "SELECT s.account_id {authority} AND EXISTS (SELECT 1 FROM dpop_proof_use p \
         WHERE p.jkt=?1 AND p.jti_hash=?2 AND p.accepted_by=?3 \
         AND p.retain_until>=unixepoch())"
    );
    let results = db
        .batch(vec![
            cleanup(db),
            db.prepare(proof_check).bind(&bindings)?,
            db.prepare(account_query).bind(&bindings[..7])?,
        ])
        .await?;
    Ok(results[2].results::<VaultAccountRow>()?.into_iter().next())
}
