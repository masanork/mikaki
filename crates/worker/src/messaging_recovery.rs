//! Explicit termination and a fresh, bilaterally approved successor group.
use super::invitation::Offer;
use super::*;
#[path = "messaging_rejoin_cancellation.rs"]
mod cancellation;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Close {
    offer: Offer,
    scope: String,
    operation_id: String,
    reason: String,
}
#[derive(Deserialize)]
struct Closed {
    intent_hash: String,
}
pub(super) fn valid_offer(o: &Offer, id: &str) -> bool {
    o.channel.id == id
        && profile::uuid(id)
        && profile::decode(&o.channel.group, 16).is_ok()
        && o.channel.a.scope < o.channel.b.scope
        && [
            &o.channel.a.scope,
            &o.channel.b.scope,
            &o.channel.a.fingerprint,
            &o.channel.b.fingerprint,
        ]
        .iter()
        .all(|v| profile::decode(v, 32).is_ok())
        && [&o.channel.a.scope, &o.channel.b.scope].contains(&&o.inviter_scope)
}
async fn owned(
    db: &D1Database,
    actor: &Actor,
    id: &str,
    scope: &str,
) -> Result<Option<ChannelRow>> {
    let sql = format!("{OWN_CHANNEL} AND d.scope_hash=?3");
    db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&[text(id), text(&actor.secret_hash), text(scope)])?
        .first(None)
        .await
}
async fn closed(db: &D1Database, actor: &Actor, id: &str, scope: &str) -> Result<Option<Closed>> {
    db.with_session_constraint(D1SessionConstraint::FirstPrimary)?.prepare("SELECT x.intent_hash FROM messaging_channel_close x JOIN messaging_channel c ON c.channel_id=x.channel_id JOIN messaging_live_device d ON d.scope_hash=x.scope_hash JOIN messaging_live_owner a ON a.account_id=d.owner_id WHERE x.channel_id=?1 AND x.scope_hash=?3 AND a.secret_hash=?2 AND c.blocked=1")
        .bind(&[text(id),text(&actor.secret_hash),text(scope)])?.first(None).await
}
async fn terminate(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let v: Close = match body(request, 1536).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if !valid_offer(&v.offer, id)
        || !profile::uuid(&v.operation_id)
        || !matches!(
            v.reason.as_str(),
            "cancel_invitation" | "epoch_conflict" | "leave"
        )
        || ![&v.offer.channel.a.scope, &v.offer.channel.b.scope].contains(&&v.scope)
    {
        return error(400, "invalid_channel_close");
    }
    let Some(row) = owned(db, actor, id, &v.scope).await? else {
        return error(403, "channel_unavailable");
    };
    if row.channel() != v.offer.channel
        || row.inviter_scope.as_deref() != Some(&v.offer.inviter_scope)
    {
        return error(409, "channel_close_conflict");
    }
    let hash = profile::digest(&serde_json::to_vec(&v)?);
    let args = [
        text(id),
        text(&actor.secret_hash),
        text(&v.scope),
        text(&v.operation_id),
        text(&v.reason),
        text(&hash),
    ];
    let authority = "EXISTS(SELECT 1 FROM messaging_live_device d JOIN messaging_live_owner a ON a.account_id=d.owner_id WHERE d.scope_hash=?3 AND a.secret_hash=?2 AND d.scope_hash IN(c.a_scope,c.b_scope))";
    let insert = format!(
        "INSERT INTO messaging_channel_close(channel_id,scope_hash,operation_id,reason,intent_hash) SELECT c.channel_id,?3,?4,?5,?6 FROM messaging_channel c WHERE c.channel_id=?1 AND {authority} ON CONFLICT(channel_id,scope_hash) DO NOTHING"
    );
    let freeze = format!(
        "UPDATE messaging_channel AS c SET blocked=1 WHERE c.channel_id=?1 AND {authority} AND EXISTS(SELECT 1 FROM messaging_channel_close x WHERE x.channel_id=?1 AND x.scope_hash=?3 AND x.operation_id=?4 AND x.intent_hash=?6)"
    );
    let guard = format!(
        "INSERT INTO messaging_commit_guard(operation_id,valid) VALUES(?4,CASE WHEN EXISTS(SELECT 1 FROM messaging_channel c JOIN messaging_channel_close x ON x.channel_id=c.channel_id WHERE c.channel_id=?1 AND c.blocked=1 AND x.scope_hash=?3 AND x.operation_id=?4 AND x.intent_hash=?6 AND {authority}) THEN 1 ELSE 0 END) ON CONFLICT(operation_id) DO UPDATE SET valid=excluded.valid"
    );
    let result = db
        .batch(vec![
            db.prepare(insert).bind(&args)?,
            db.prepare(freeze).bind(&args)?,
            db.prepare(guard).bind(&args)?,
        ])
        .await;
    let Some(record) = closed(db, actor, id, &v.scope).await? else {
        return error(
            if result.is_err() { 503 } else { 409 },
            "channel_close_unconfirmed_or_denied",
        );
    };
    if record.intent_hash != hash {
        return error(409, "channel_close_conflict");
    }
    json(
        &serde_json::json!({"status":"closed","offer":v.offer,"scope":v.scope,"operation_id":v.operation_id,"reason":v.reason}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rejoin {
    previous: Offer,
    next: Offer,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejoinStatusRequest {
    previous: Offer,
    next: Offer,
    scope: String,
}
#[derive(Deserialize)]
struct RejoinRow {
    #[serde(flatten)]
    channel: ChannelRow,
    expired: i64,
    cancelled: i64,
}
async fn rejoin_status(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let v: RejoinStatusRequest = match body(request, 2500).await {
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
    {
        return error(400, "invalid_rejoin_status");
    }
    // Read metadata only, including closed children and historical peers. This
    // endpoint never grants consent or releases any admission packet.
    let sql = format!(
        "SELECT own.*,EXISTS(SELECT 1 FROM messaging_invitation_packet p WHERE p.channel_id=own.channel_id AND own.bootstrap_complete=0 AND p.expires_at<=unixepoch()) AS expired,EXISTS(SELECT 1 FROM messaging_rejoin_cancellation x WHERE x.channel_id=own.channel_id AND x.outcome='cancelled') AS cancelled FROM ({OWN_CHANNEL} AND d.scope_hash=?3) own"
    );
    let row: Option<RejoinRow> = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&[text(id), text(&actor.secret_hash), text(&v.scope)])?
        .first(None)
        .await?;
    let collision: Option<serde_json::Value> = if row.is_none() {
        db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
            .prepare("SELECT channel_id FROM messaging_channel WHERE channel_id=?1")
            .bind(&[text(id)])?
            .first(None)
            .await?
    } else {
        None
    };
    // Recheck current own authority and the original exact close receipt after
    // the child lookup. A peer's close never substitutes for this owner's close.
    let Some(prior) = owned(db, actor, &old.id, &v.scope).await? else {
        return error(403, "rejoin_status_unavailable");
    };
    if prior.channel() != *old
        || prior.inviter_scope.as_deref() != Some(&v.previous.inviter_scope)
        || prior.blocked != 1
        || closed(db, actor, &old.id, &v.scope).await?.is_none()
    {
        return error(403, "rejoin_status_unavailable");
    }
    let (state, complete, expired) = match row {
        Some(row) => {
            let c = row.channel;
            if c.channel() != *next
                || c.inviter_scope.as_deref() != Some(&v.next.inviter_scope)
                || c.predecessor_id.as_deref() != Some(&old.id)
            {
                return error(409, "rejoin_status_conflict");
            }
            let state = if c.blocked == 1 && row.cancelled == 1 {
                "cancelled"
            } else if c.blocked == 1 {
                "closed"
            } else if c.own_consent == 0 {
                "unpublished"
            } else if c.a_consent == 1 && c.b_consent == 1 {
                "admitted"
            } else {
                "waiting"
            };
            (state, c.bootstrap_complete == 1, row.expired == 1)
        }
        None if collision.is_some() => return error(409, "rejoin_status_conflict"),
        None => ("unpublished", false, false),
    };
    json(
        &serde_json::json!({"predecessor_id":old.id,"channel":next,"inviter_scope":v.next.inviter_scope,"scope":v.scope,"state":state,"complete":complete,"expired":expired}),
    )
}
async fn rejoin(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let v: Rejoin = match body(request, 2400).await {
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
    {
        return error(400, "invalid_channel_successor");
    }
    let Some(prior) = channel(db, &actor.secret_hash, &old.id).await? else {
        return error(403, "channel_unavailable");
    };
    if prior.channel() != *old
        || prior.inviter_scope.as_deref() != Some(&v.previous.inviter_scope)
        || prior.blocked != 1
    {
        return error(409, "predecessor_not_closed");
    }
    save_consent(db, actor, next, Some(&v.next.inviter_scope), Some(&old.id)).await?;
    let row = match invitation::authorized(db, actor, id, &next.a.scope).await? {
        Some(row) => Some(row),
        None => invitation::authorized(db, actor, id, &next.b.scope).await?,
    };
    let Some(row) = row else {
        return error(409, "rejoin_precondition_or_limit");
    };
    if row.channel() != *next
        || row.inviter_scope.as_deref() != Some(&v.next.inviter_scope)
        || row.predecessor_id.as_deref() != Some(&old.id)
        || row.blocked != 0
        || row.own_consent != 1
    {
        return error(409, "rejoin_conflict_or_limit");
    }
    json(
        &serde_json::json!({"predecessor_id":old.id,"channel":row.channel(),"inviter_scope":v.next.inviter_scope,"ready":row.a_consent==1 && row.b_consent==1,"complete":row.bootstrap_complete==1}),
    )
}
pub(super) async fn dispatch(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let path = request.url()?.path().to_owned();
    let parts: Vec<_> = path.split('/').collect();
    match (request.method(), parts.as_slice()) {
        (Method::Post, ["", "messaging", "channels", _, "close"]) => {
            terminate(request, db, actor, id).await
        }
        (Method::Post, ["", "messaging", "channels", _, "rejoin"]) => {
            rejoin(request, db, actor, id).await
        }
        (Method::Post, ["", "messaging", "channels", _, "rejoin", "status"]) => {
            rejoin_status(request, db, actor, id).await
        }
        (Method::Post, ["", "messaging", "channels", _, "rejoin", "cancel"]) => {
            cancellation::cancel(request, db, actor, id).await
        }
        _ => error(404, "not_found"),
    }
}
