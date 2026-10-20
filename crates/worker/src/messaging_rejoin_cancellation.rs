//! A pre-admission veto retains the original closed predecessor. Never report
//! cancellation if bilateral consent won the race, and never add consent here.
use super::*;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cancellation {
    previous: Offer,
    next: Offer,
    scope: String,
    operation_id: String,
}
const AUTHORITY: &str = "EXISTS(SELECT 1 FROM messaging_channel old JOIN messaging_channel_close stop ON stop.channel_id=old.channel_id AND stop.scope_hash=?12 JOIN messaging_live_device d ON d.scope_hash=stop.scope_hash JOIN messaging_live_owner a ON a.account_id=d.owner_id WHERE old.channel_id=?9 AND old.group_id=?10 AND old.inviter_scope=?11 AND old.a_scope=?4 AND old.b_scope=?5 AND old.a_fingerprint=?6 AND old.b_fingerprint=?7 AND old.blocked=1 AND a.secret_hash=?2 AND ((d.scope_hash=?4 AND d.fingerprint=?6) OR (d.scope_hash=?5 AND d.fingerprint=?7)))";
const CHILD: &str = "c.channel_id=?1 AND c.group_id=?3 AND c.a_scope=?4 AND c.b_scope=?5 AND c.a_fingerprint=?6 AND c.b_fingerprint=?7 AND c.inviter_scope=?8 AND c.predecessor_id=?9";

pub(super) async fn cancel(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let v: Cancellation = match body(request, 2600).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    let old = &v.previous.channel;
    let next = &v.next.channel;
    if !valid_offer(&v.previous, &old.id)
        || !valid_offer(&v.next, id)
        || old.id == next.id
        || old.group == next.group
        || old.a != next.a
        || old.b != next.b
        || ![&next.a.scope, &next.b.scope].contains(&&v.scope)
        || !profile::uuid(&v.operation_id)
    {
        return error(400, "invalid_rejoin_cancellation");
    }
    // The immutable descriptor itself is the approval identity on the existing
    // same-key protocol. A separate approval UUID is unnecessary: a cancelled
    // child can never receive another consent, even from a delayed old request.
    let args = vec![
        text(id),
        text(&actor.secret_hash),
        text(&next.group),
        text(&next.a.scope),
        text(&next.b.scope),
        text(&next.a.fingerprint),
        text(&next.b.fingerprint),
        text(&v.next.inviter_scope),
        text(&old.id),
        text(&old.group),
        text(&v.previous.inviter_scope),
        text(&v.scope),
        text(&v.operation_id),
        text(&profile::digest(&serde_json::to_vec(&v)?)),
    ];
    let receipt = "EXISTS(SELECT 1 FROM messaging_rejoin_cancellation x JOIN messaging_live_owner a ON a.account_id=x.owner_id WHERE x.channel_id=?1 AND x.scope_hash=?12 AND x.operation_id=?13 AND x.intent_hash=?14 AND a.secret_hash=?2";
    let create = format!(
        "INSERT INTO messaging_channel(channel_id,group_id,a_scope,b_scope,a_fingerprint,b_fingerprint,a_consent,b_consent,inviter_scope,bootstrap_complete,predecessor_id) SELECT ?1,?3,?4,?5,?6,?7,0,0,?8,0,?9 WHERE {AUTHORITY} AND length(?14)=43 ON CONFLICT DO NOTHING"
    );
    let insert = format!(
        "INSERT INTO messaging_rejoin_cancellation(channel_id,owner_id,scope_hash,operation_id,intent_hash,outcome) SELECT c.channel_id,a.account_id,?12,?13,?14,CASE WHEN c.a_consent=1 AND c.b_consent=1 THEN 'admitted' ELSE 'cancelled' END FROM messaging_channel c JOIN messaging_live_owner a ON a.secret_hash=?2 WHERE {CHILD} AND {AUTHORITY} AND (EXISTS(SELECT 1 FROM messaging_rejoin_cancellation prior WHERE prior.channel_id=?1 AND prior.owner_id=a.account_id) OR (SELECT count(*) FROM messaging_rejoin_cancellation quota WHERE quota.owner_id=a.account_id)<32) ON CONFLICT(channel_id,owner_id) DO NOTHING"
    );
    let block = format!(
        "UPDATE messaging_channel AS c SET blocked=1 WHERE {CHILD} AND NOT(c.a_consent=1 AND c.b_consent=1) AND {AUTHORITY} AND {receipt} AND x.outcome='cancelled')"
    );
    let confirmed = format!(
        "EXISTS(SELECT 1 FROM messaging_channel c WHERE {CHILD} AND {AUTHORITY} AND {receipt} AND ((x.outcome='cancelled' AND c.blocked=1 AND NOT(c.a_consent=1 AND c.b_consent=1)) OR (x.outcome='admitted' AND c.a_consent=1 AND c.b_consent=1))))"
    );
    let guard = format!(
        "INSERT INTO messaging_commit_guard(operation_id,valid) VALUES(?13,CASE WHEN {confirmed} THEN 1 ELSE 0 END) ON CONFLICT(operation_id) DO UPDATE SET valid=excluded.valid"
    );
    let result = db
        .batch(vec![
            db.prepare(create).bind(&args)?,
            db.prepare(insert).bind(&args)?,
            db.prepare(block).bind(&args)?,
            db.prepare(guard).bind(&args)?,
        ])
        .await;
    #[derive(Deserialize)]
    struct Proof {
        outcome: String,
    }
    let proof = db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(format!("SELECT x.outcome FROM messaging_rejoin_cancellation x JOIN messaging_live_owner a ON a.account_id=x.owner_id WHERE x.channel_id=?1 AND x.operation_id=?13 AND a.secret_hash=?2 AND {confirmed}"))
        .bind(&args)?.first::<Proof>(None).await?;
    let Some(proof) = proof else {
        return error(
            if result.is_err() { 409 } else { 503 },
            "rejoin_cancellation_unconfirmed",
        );
    };
    json(
        &serde_json::json!({"predecessor_id":old.id,"channel":next,"inviter_scope":v.next.inviter_scope,"scope":v.scope,"operation_id":v.operation_id,"outcome":proof.outcome}),
    )
}
