//! A fixed three-packet admission flow; never silently replaces a group or key.
use super::*;
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Offer {
    pub(super) channel: Channel,
    pub(super) inviter_scope: String,
}
pub(super) async fn authorized(
    db: &D1Database,
    actor: &Actor,
    id: &str,
    scope: &str,
) -> Result<Option<ChannelRow>> {
    let sql = format!(
        "{OWN_CHANNEL} AND d.scope_hash=?3 AND EXISTS(SELECT 1 FROM messaging_live_device da JOIN messaging_live_device db WHERE da.scope_hash=c.a_scope AND db.scope_hash=c.b_scope AND da.fingerprint=c.a_fingerprint AND db.fingerprint=c.b_fingerprint)"
    );
    db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&[text(id), text(&actor.secret_hash), text(scope)])?
        .first(None)
        .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    offer: Offer,
    scope: String,
}
#[derive(Deserialize)]
struct AdmissionStatus {
    #[serde(flatten)]
    channel: ChannelRow,
    expired: i64,
}
// Metadata only: stopping/reporting an abandoned admission does not require a
// live peer, but always requires this endpoint's current device and Owner SSO.
async fn status(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let v: StatusRequest = match body(request, 1536).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if !recovery::valid_offer(&v.offer, id)
        || ![&v.offer.channel.a.scope, &v.offer.channel.b.scope].contains(&&v.scope)
    {
        return error(400, "invalid_invitation_status");
    }
    let sql = format!(
        "SELECT own.*,EXISTS(SELECT 1 FROM messaging_invitation_packet p WHERE p.channel_id=own.channel_id AND own.bootstrap_complete=0 AND p.expires_at<=unixepoch()) AS expired FROM ({OWN_CHANNEL} AND d.scope_hash=?3) own"
    );
    let row: Option<AdmissionStatus> = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&[text(id), text(&actor.secret_hash), text(&v.scope)])?
        .first(None)
        .await?;
    let Some(row) = row else {
        return error(403, "invitation_unavailable");
    };
    let c = row.channel;
    if c.channel() != v.offer.channel
        || c.inviter_scope.as_deref() != Some(&v.offer.inviter_scope)
        || c.own_consent != 1
    {
        return error(403, "invitation_unavailable");
    }
    json(
        &serde_json::json!({"channel":c.channel(),"inviter_scope":v.offer.inviter_scope,"ready":c.a_consent==1 && c.b_consent==1,"complete":c.bootstrap_complete==1,"blocked":c.blocked==1,"expired":row.expired==1}),
    )
}
async fn approve(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let o: Offer = match body(request, 1200).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    let c = &o.channel;
    if c.id != id
        || profile::decode(&c.group, 16).is_err()
        || c.a.scope >= c.b.scope
        || [&c.a.scope, &c.b.scope, &c.a.fingerprint, &c.b.fingerprint]
            .iter()
            .any(|v| profile::decode(v, 32).is_err())
        || ![&c.a.scope, &c.b.scope].contains(&&o.inviter_scope)
    {
        return error(400, "invalid_invitation");
    }
    save_consent(db, actor, c, Some(&o.inviter_scope), None).await?;
    let current = match authorized(db, actor, id, &c.a.scope).await? {
        Some(v) => Some(v),
        None => authorized(db, actor, id, &c.b.scope).await?,
    };
    let Some(row) = current else {
        return error(409, "invitation_precondition_or_limit");
    };
    if row.channel() != *c
        || row.inviter_scope.as_deref() != Some(&o.inviter_scope)
        || row.own_consent != 1
        || row.blocked != 0
    {
        return error(409, "invitation_conflict_or_limit");
    }
    json(
        &serde_json::json!({"channel":row.channel(),"inviter_scope":o.inviter_scope,"ready":row.a_consent==1 && row.b_consent==1,"complete":row.bootstrap_complete==1}),
    )
}
const PACKET_AUTH: &str = "p.channel_id=c.channel_id AND c.inviter_scope IS NOT NULL AND a.secret_hash=?2 AND ((p.sender_scope=c.a_scope AND p.recipient_scope=c.b_scope AND a.account_id=c.a_owner) OR (p.sender_scope=c.b_scope AND p.recipient_scope=c.a_scope AND a.account_id=c.b_owner))";
async fn stored_packet(db: &D1Database, actor: &Actor, e: &Envelope) -> Result<Option<Mail>> {
    let sql = format!(
        "SELECT p.* FROM messaging_invitation_packet p JOIN messaging_delivery_ready c JOIN messaging_live_owner a WHERE {PACKET_AUTH} AND c.channel_id=?1 AND p.sender_scope=?3 AND p.message_id=?4"
    );
    db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&[
            text(&e.channel_id),
            text(&actor.secret_hash),
            text(&e.sender_scope),
            text(&e.message_id),
        ])?
        .first(None)
        .await
}
async fn publish(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let e: Envelope = match body(request, 90 * 1024).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if !e.valid(id) || !matches!(e.kind.as_str(), "key_package" | "invite_commit" | "welcome") {
        return error(400, "invalid_invitation_packet");
    }
    let hash = e.hash()?;
    let result=db.batch(vec![db.prepare("INSERT INTO messaging_invitation_packet(channel_id,message_id,sender_scope,recipient_scope,kind,digest,expires_at,envelope_hash,wire) SELECT c.channel_id,?3,?4,?5,?6,?7,?8,?9,?10 FROM messaging_delivery_ready c JOIN messaging_live_owner a WHERE c.channel_id=?1 AND a.secret_hash=?2 AND c.inviter_scope IS NOT NULL AND c.bootstrap_complete=0 AND ((c.a_scope=?4 AND c.b_scope=?5 AND c.a_owner=a.account_id) OR (c.b_scope=?4 AND c.a_scope=?5 AND c.b_owner=a.account_id)) AND ?8>unixepoch() AND ?8<=unixepoch()+86400 AND NOT EXISTS(SELECT 1 FROM messaging_mail m WHERE m.sender_scope=?4 AND m.message_id=?3) AND ((?6='key_package' AND c.inviter_scope=?5) OR (?6='invite_commit' AND c.inviter_scope=?4 AND EXISTS(SELECT 1 FROM messaging_invitation_packet p WHERE p.channel_id=c.channel_id AND p.kind='key_package' AND p.finished=1 AND p.expires_at>unixepoch())) OR (?6='welcome' AND c.inviter_scope=?4 AND EXISTS(SELECT 1 FROM messaging_invitation_packet p WHERE p.channel_id=c.channel_id AND p.kind='invite_commit' AND p.expires_at>unixepoch()))) ON CONFLICT DO NOTHING")
        .bind(&[text(id),text(&actor.secret_hash),text(&e.message_id),text(&e.sender_scope),text(&e.recipient_scope),text(&e.kind),text(&e.digest),num(e.expires_at),text(&hash),text(&e.wire)])?]).await;
    let Some(mut row) = stored_packet(db, actor, &e).await? else {
        return error(
            if result.is_err() { 503 } else { 409 },
            "invitation_packet_unconfirmed_or_denied",
        );
    };
    if row.envelope_hash != hash {
        return error(409, "message_id_conflict");
    }
    row.wire = None;
    json(&serde_json::json!({"status":"stored","receipt":row}))
}
async fn snapshot(db: &D1Database, actor: &Actor, id: &str, scope: &str) -> Result<Response> {
    let Some(row) = authorized(db, actor, id, scope).await? else {
        return error(403, "invitation_unavailable");
    };
    let Some(ref inviter) = row.inviter_scope else {
        return error(409, "invitation_missing");
    };
    if row.blocked != 0 || row.own_consent != 1 {
        return error(403, "invitation_unavailable");
    }
    let ready = row.a_consent == 1 && row.b_consent == 1;
    let mut packet: Option<Mail> = None;
    if ready && row.bootstrap_complete == 0 {
        let kind = if inviter == scope {
            "key_package"
        } else {
            "welcome"
        };
        let sql = format!(
            "SELECT p.* FROM messaging_invitation_packet p JOIN messaging_delivery_ready c ON c.channel_id=p.channel_id JOIN messaging_live_owner a WHERE {RECIPIENT_AUTH} AND p.recipient_scope=?3 AND p.kind=?4 AND p.finished=0"
        );
        packet = db
            .with_session_constraint(D1SessionConstraint::FirstPrimary)?
            .prepare(sql)
            .bind(&[text(id), text(&actor.secret_hash), text(scope), text(kind)])?
            .first(None)
            .await?;
    }
    // Recheck current authority and time after fetching a potentially large packet.
    let Some(current) = authorized(db, actor, id, scope).await? else {
        return error(403, "invitation_unavailable");
    };
    if current.blocked != 0
        || current.own_consent != 1
        || current.bootstrap_complete != row.bootstrap_complete
    {
        return error(409, "invitation_changed_retry");
    }
    if packet.as_ref().is_some_and(|p| p.expires_at <= current.now) {
        return error(410, "invitation_expired_recovery_required");
    }
    json(
        &serde_json::json!({"channel":row.channel(),"inviter_scope":inviter,"ready":ready,"complete":row.bootstrap_complete==1,"packet":packet}),
    )
}
async fn consume(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
    message: &str,
) -> Result<Response> {
    let v: Consume = match body(request, 512).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if [&v.recipient_scope, &v.digest, &v.envelope_hash]
        .iter()
        .any(|v| profile::decode(v, 32).is_err())
    {
        return error(400, "invalid_receipt");
    }
    let args = [
        text(id),
        text(&actor.secret_hash),
        text(&v.recipient_scope),
        text(message),
        text(&v.digest),
        text(&v.envelope_hash),
    ];
    let authority = format!(
        "EXISTS(SELECT 1 FROM messaging_delivery_ready c JOIN messaging_live_owner a WHERE {RECIPIENT_AUTH} AND c.inviter_scope IS NOT NULL)"
    );
    let exact = "p.channel_id=?1 AND p.recipient_scope=?3 AND p.message_id=?4 AND p.digest=?5 AND p.envelope_hash=?6 AND p.kind IN('key_package','welcome')";
    let update = format!(
        "UPDATE messaging_invitation_packet AS p SET finished=1,wire=NULL WHERE {exact} AND (p.finished=1 OR p.expires_at>unixepoch()) AND {authority}"
    );
    let activate = format!(
        "UPDATE messaging_channel SET bootstrap_complete=1 WHERE channel_id=?1 AND {authority} AND EXISTS(SELECT 1 FROM messaging_invitation_packet p WHERE {exact} AND p.kind='welcome' AND p.finished=1)"
    );
    let cleanup = format!(
        "UPDATE messaging_invitation_packet SET finished=1,wire=NULL WHERE channel_id=?1 AND kind='invite_commit' AND {authority} AND EXISTS(SELECT 1 FROM messaging_channel WHERE channel_id=?1 AND bootstrap_complete=1)"
    );
    let operation = format!("invitation:{id}:{message}");
    let guard = format!(
        "INSERT INTO messaging_commit_guard(operation_id,valid) VALUES(?7,CASE WHEN {authority} AND EXISTS(SELECT 1 FROM messaging_invitation_packet p WHERE {exact} AND p.finished=1 AND (p.kind='key_package' OR EXISTS(SELECT 1 FROM messaging_channel WHERE channel_id=?1 AND bootstrap_complete=1))) THEN 1 ELSE 0 END) ON CONFLICT(operation_id) DO UPDATE SET valid=excluded.valid"
    );
    let mut guard_args = args.to_vec();
    guard_args.push(text(&operation));
    let result = db
        .batch(vec![
            db.prepare(update).bind(&args)?,
            db.prepare(activate).bind(&args)?,
            db.prepare(cleanup).bind(&args[..3])?,
            db.prepare(guard).bind(&guard_args)?,
        ])
        .await;
    let sql = format!(
        "SELECT c.* FROM messaging_delivery_ready c JOIN messaging_live_owner a WHERE {RECIPIENT_AUTH} AND EXISTS(SELECT 1 FROM messaging_invitation_packet p WHERE {exact} AND p.finished=1)"
    );
    #[derive(Deserialize)]
    struct Complete {
        bootstrap_complete: u8,
    }
    let row = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&args)?
        .first::<Complete>(None)
        .await?;
    match row {
        Some(row) => {
            json(&serde_json::json!({"status":"consumed","complete":row.bootstrap_complete==1}))
        }
        None => error(
            if result.is_err() { 503 } else { 409 },
            "invitation_consume_unconfirmed_or_denied",
        ),
    }
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
        (Method::Post, ["", "messaging", "channels", _, "invitation"]) => {
            approve(request, db, actor, id).await
        }
        (Method::Get, ["", "messaging", "channels", _, "invitation", scope])
            if profile::decode(scope, 32).is_ok() =>
        {
            snapshot(db, actor, id, scope).await
        }
        (Method::Post, ["", "messaging", "channels", _, "invitation", "status"]) => {
            status(request, db, actor, id).await
        }
        (Method::Post, ["", "messaging", "channels", _, "invitation", "packets"]) => {
            publish(request, db, actor, id).await
        }
        (
            Method::Post,
            [
                "",
                "messaging",
                "channels",
                _,
                "invitation",
                "packets",
                message,
                "consume",
            ],
        ) if profile::uuid(message) => consume(request, db, actor, id, message).await,
        _ => error(404, "not_found"),
    }
}
