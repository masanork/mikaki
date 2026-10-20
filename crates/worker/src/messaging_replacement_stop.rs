//! Stop-only continuity across a further device-generation change. This never
//! grants an old scope transport authority or approves a replacement candidate.
use super::*;

// The failed child must itself be an exact admitted changed-key successor of a
// completed original conversation. Only its endpoint's current same-slot head
// may stop it. Peer liveness is deliberately unnecessary for stopping delivery.
const AUTHORITY: &str = "EXISTS(SELECT 1 FROM messaging_replacement_candidate p JOIN messaging_channel old ON old.channel_id=p.previous_id JOIN messaging_generation historical ON historical.scope_hash IN(p.next_a_scope,p.next_b_scope) AND historical.fingerprint=CASE WHEN historical.scope_hash=p.next_a_scope THEN p.next_a_fingerprint ELSE p.next_b_fingerprint END JOIN messaging_live_device own ON own.account_id=historical.account_id AND own.device_id=historical.device_id JOIN messaging_live_owner a ON a.account_id=own.owner_id WHERE a.secret_hash=?2 AND own.scope_hash=?16 AND (own.scope_hash=historical.scope_hash OR (own.generation>historical.generation AND historical.status='revoked' AND own.public_key<>historical.public_key AND own.fingerprint<>historical.fingerprint)) AND old.blocked=1 AND p.previous_id=?9 AND p.previous_group=?10 AND p.old_a_scope=?11 AND p.old_b_scope=?12 AND p.old_a_fingerprint=?13 AND p.old_b_fingerprint=?14 AND p.old_inviter=?15 AND p.next_a_scope=?4 AND p.next_b_scope=?5 AND p.next_a_fingerprint=?6 AND p.next_b_fingerprint=?7)";
const RECEIPT: &str = "EXISTS(SELECT 1 FROM messaging_replacement_stop x JOIN messaging_live_owner a ON a.account_id=x.owner_id WHERE x.channel_id=?1 AND x.scope_hash=?16 AND x.operation_id=?17 AND x.intent_hash=?18 AND a.secret_hash=?2)";

pub(super) async fn status(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let v: Approval = match body(request, 3000).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if !v.valid_descriptors(id) || profile::decode(&v.scope, 32).is_err() {
        return error(400, "invalid_replacement_stop");
    }
    #[derive(Deserialize)]
    struct State {
        state: String,
    }
    let row = db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(format!("SELECT CASE WHEN c.blocked=1 THEN 'closed' ELSE 'admitted' END AS state FROM messaging_channel c WHERE {} AND c.a_consent=1 AND c.b_consent=1 AND {AUTHORITY} AND length(?17)=36 AND length(?18)=43", exact_child()))
        .bind(&v.args(actor)?)?.first::<State>(None).await?;
    match row {
        Some(row) => response(&v, &row.state),
        None => error(409, "replacement_stop_unavailable"),
    }
}

fn response(v: &Approval, state: &str) -> Result<Response> {
    json(
        &serde_json::json!({"predecessor_id":v.previous.channel.id,"channel":v.next.channel,"inviter_scope":v.next.inviter_scope,"scope":v.scope,"operation_id":v.operation_id,"state":state}),
    )
}

pub(super) async fn terminate(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let v: Approval = match body(request, 3000).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    // Unlike approval, scope may be a newer generation of an endpoint in next.
    // The historical/current relationship is verified against the registry.
    if !v.valid_descriptors(id) || profile::decode(&v.scope, 32).is_err() {
        return error(400, "invalid_replacement_stop");
    }
    let args = v.args(actor)?;
    let child = format!("{} AND c.a_consent=1 AND c.b_consent=1", exact_child());
    let insert = format!(
        "INSERT INTO messaging_replacement_stop(channel_id,owner_id,scope_hash,operation_id,intent_hash) SELECT c.channel_id,a.account_id,?16,?17,?18 FROM messaging_channel c JOIN messaging_live_owner a ON a.secret_hash=?2 WHERE {child} AND {AUTHORITY} AND (EXISTS(SELECT 1 FROM messaging_replacement_stop prior WHERE prior.channel_id=?1 AND prior.scope_hash=?16) OR (SELECT count(*) FROM messaging_replacement_stop limit_row WHERE limit_row.owner_id=a.account_id)<32) ON CONFLICT(channel_id,scope_hash) DO NOTHING"
    );
    let freeze = format!(
        "UPDATE messaging_channel AS c SET blocked=1 WHERE {child} AND {AUTHORITY} AND {RECEIPT}"
    );
    let confirmed = format!(
        "EXISTS(SELECT 1 FROM messaging_channel c WHERE {child} AND c.blocked=1 AND {AUTHORITY} AND {RECEIPT})"
    );
    let guard = format!(
        "INSERT INTO messaging_commit_guard(operation_id,valid) VALUES(?17,CASE WHEN {confirmed} THEN 1 ELSE 0 END) ON CONFLICT(operation_id) DO UPDATE SET valid=excluded.valid"
    );
    let outcome = db
        .batch(vec![
            db.prepare(insert).bind(&args)?,
            db.prepare(freeze).bind(&args)?,
            db.prepare(guard).bind(&args)?,
        ])
        .await;
    // Reconcile a lost batch response only while this exact scope and SSO are
    // still current. A retained old receipt never substitutes for live authority.
    let proof = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(format!("SELECT 1 AS stopped WHERE {confirmed}"))
        .bind(&args)?
        .first::<serde_json::Value>(None)
        .await?;
    if proof.is_none() {
        return error(
            if outcome.is_err() { 409 } else { 503 },
            "replacement_stop_unconfirmed",
        );
    }
    response(&v, "closed")
}
