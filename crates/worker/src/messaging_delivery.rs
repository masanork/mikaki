//! Qualification-only bounded mailbox for mutually approved, established groups.
//! SSO authorizes mailbox access; only the client's MLS leaf authenticates content.
use super::*;
#[path = "messaging_invitation.rs"]
mod invitation;
#[path = "messaging_recovery.rs"]
mod recovery;
#[path = "messaging_replacement.rs"]
mod replacement;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Endpoint {
    scope: String,
    fingerprint: String,
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Channel {
    id: String,
    group: String,
    a: Endpoint,
    b: Endpoint,
}
#[derive(Deserialize)]
struct ChannelRow {
    channel_id: String,
    group_id: String,
    a_scope: String,
    b_scope: String,
    a_fingerprint: String,
    b_fingerprint: String,
    a_consent: u8,
    b_consent: u8,
    blocked: u8,
    own_consent: u8,
    now: u64,
    inviter_scope: Option<String>,
    bootstrap_complete: u8,
    predecessor_id: Option<String>,
}
impl ChannelRow {
    fn channel(&self) -> Channel {
        Channel {
            id: self.channel_id.clone(),
            group: self.group_id.clone(),
            a: Endpoint {
                scope: self.a_scope.clone(),
                fingerprint: self.a_fingerprint.clone(),
            },
            b: Endpoint {
                scope: self.b_scope.clone(),
                fingerprint: self.b_fingerprint.clone(),
            },
        }
    }
}
const OWN_CHANNEL: &str = "SELECT c.*,unixepoch() AS now,CASE WHEN d.scope_hash=c.a_scope THEN c.a_consent ELSE c.b_consent END AS own_consent FROM messaging_channel c JOIN messaging_live_device d ON d.scope_hash IN(c.a_scope,c.b_scope) JOIN messaging_live_owner a ON a.account_id=d.owner_id WHERE c.channel_id=?1 AND a.secret_hash=?2";
// Every sensitive read gets its own first-primary session, including after writes.
async fn channel(db: &D1Database, secret: &str, id: &str) -> Result<Option<ChannelRow>> {
    db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(OWN_CHANNEL)
        .bind(&[text(id), text(secret)])?
        .first(None)
        .await
}
async fn consent(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let c: Channel = match body(request, 1024).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if c.id != id
        || profile::decode(&c.group, 16).is_err()
        || c.a.scope >= c.b.scope
        || [&c.a.scope, &c.b.scope, &c.a.fingerprint, &c.b.fingerprint]
            .iter()
            .any(|v| profile::decode(v, 32).is_err())
    {
        return error(400, "invalid_channel");
    }
    let current = save_consent(db, actor, &c, None, None).await?;
    let Some(row) = current else {
        return error(409, "channel_precondition_or_limit");
    };
    if row.channel() != c || row.blocked != 0 {
        return error(409, "channel_conflict_or_blocked");
    }
    if row.own_consent != 1 {
        return error(409, "channel_precondition_or_limit");
    }
    json(&serde_json::json!({"channel":row.channel(),"ready":row.a_consent==1 && row.b_consent==1}))
}
async fn save_consent(
    db: &D1Database,
    actor: &Actor,
    c: &Channel,
    inviter: Option<&str>,
    predecessor: Option<&str>,
) -> Result<Option<ChannelRow>> {
    db.prepare("INSERT INTO messaging_channel(channel_id,group_id,a_scope,b_scope,a_fingerprint,b_fingerprint,a_consent,b_consent,inviter_scope,bootstrap_complete,predecessor_id) SELECT ?1,?3,da.scope_hash,db.scope_hash,da.fingerprint,db.fingerprint,CASE WHEN da.owner_id=a.account_id THEN 1 ELSE 0 END,CASE WHEN db.owner_id=a.account_id THEN 1 ELSE 0 END,?8,CASE WHEN ?8 IS NULL THEN 1 ELSE 0 END,?9 FROM messaging_live_device da JOIN messaging_live_device db JOIN messaging_live_owner a WHERE da.scope_hash=?4 AND db.scope_hash=?5 AND da.fingerprint=?6 AND db.fingerprint=?7 AND da.owner_id<>db.owner_id AND a.secret_hash=?2 AND a.account_id IN(da.owner_id,db.owner_id) AND (?9 IS NULL OR NOT EXISTS(SELECT 1 FROM messaging_channel child WHERE child.predecessor_id=?9 AND child.channel_id<>?1 AND child.blocked=0 AND child.a_consent=1 AND child.b_consent=1)) AND (?9 IS NULL OR EXISTS(SELECT 1 FROM messaging_channel old JOIN messaging_channel_close closed ON closed.channel_id=old.channel_id WHERE old.channel_id=?9 AND old.blocked=1 AND old.channel_id<>?1 AND old.group_id<>?3 AND old.a_scope=?4 AND old.b_scope=?5 AND old.a_fingerprint=?6 AND old.b_fingerprint=?7 AND closed.scope_hash=CASE WHEN da.owner_id=a.account_id THEN da.scope_hash ELSE db.scope_hash END)) AND (SELECT count(*) FROM messaging_channel x WHERE (x.a_scope IN(SELECT g.scope_hash FROM messaging_generation g JOIN messaging_account ma ON ma.account_id=g.account_id WHERE ma.owner_id=a.account_id) AND x.a_consent=1) OR (x.b_scope IN(SELECT g.scope_hash FROM messaging_generation g JOIN messaging_account ma ON ma.account_id=g.account_id WHERE ma.owner_id=a.account_id) AND x.b_consent=1))<32 ON CONFLICT(channel_id) DO UPDATE SET a_consent=MAX(a_consent,excluded.a_consent),b_consent=MAX(b_consent,excluded.b_consent) WHERE messaging_channel.group_id=excluded.group_id AND messaging_channel.a_scope=excluded.a_scope AND messaging_channel.b_scope=excluded.b_scope AND messaging_channel.a_fingerprint=excluded.a_fingerprint AND messaging_channel.b_fingerprint=excluded.b_fingerprint AND messaging_channel.blocked=0 AND messaging_channel.predecessor_id IS excluded.predecessor_id AND (?8 IS NULL OR messaging_channel.inviter_scope IS ?8) ON CONFLICT(a_scope,b_scope,group_id) DO NOTHING")
        .bind(&[text(&c.id),text(&actor.secret_hash),text(&c.group),text(&c.a.scope),text(&c.b.scope),text(&c.a.fingerprint),text(&c.b.fingerprint),inviter.map(text).unwrap_or(JsValue::NULL),predecessor.map(text).unwrap_or(JsValue::NULL)])?.run().await?;
    channel(db, &actor.secret_hash, &c.id).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    message_id: String,
    channel_id: String,
    sender_scope: String,
    recipient_scope: String,
    kind: String,
    digest: String,
    expires_at: u64,
    wire: String,
}
impl Envelope {
    fn hash(&self) -> Result<String> {
        Ok(profile::digest(&serde_json::to_vec(&(
            "mikaki-mail-envelope-v1",
            &self.message_id,
            &self.channel_id,
            &self.sender_scope,
            &self.recipient_scope,
            &self.kind,
            &self.digest,
            self.expires_at,
        ))?))
    }
    fn valid(&self, channel: &str) -> bool {
        if self.channel_id != channel
            || !profile::uuid(&self.message_id)
            || self.sender_scope == self.recipient_scope
            || self.expires_at > MAX_SAFE
            || [&self.sender_scope, &self.recipient_scope, &self.digest]
                .iter()
                .any(|v| profile::decode(v, 32).is_err())
            || self.wire.is_empty()
            || self.wire.len() > 87382
        {
            return false;
        }
        B64.decode(&self.wire).is_ok_and(|b| {
            b.len() <= 65536 && B64.encode(&b) == self.wire && profile::digest(&b) == self.digest
        })
    }
}
#[derive(Deserialize, Serialize)]
struct Mail {
    sequence: u64,
    channel_id: String,
    message_id: String,
    sender_scope: String,
    recipient_scope: String,
    kind: String,
    digest: String,
    expires_at: u64,
    envelope_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    wire: Option<String>,
}
// c is always the current bilateral grant, with both exact device generations.
const MAIL_AUTH: &str = "m.channel_id=c.channel_id AND a.secret_hash=?2 AND ((m.sender_scope=c.a_scope AND m.recipient_scope=c.b_scope AND a.account_id=c.a_owner) OR (m.sender_scope=c.b_scope AND m.recipient_scope=c.a_scope AND a.account_id=c.b_owner))";
async fn stored(db: &D1Database, secret: &str, e: &Envelope) -> Result<Option<Mail>> {
    let sql = format!(
        "SELECT m.* FROM messaging_mail m JOIN messaging_delivery_ready c JOIN messaging_live_owner a WHERE {MAIL_AUTH} AND m.sender_scope=?3 AND m.message_id=?4 AND c.channel_id=?1"
    );
    db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&[
            text(&e.channel_id),
            text(secret),
            text(&e.sender_scope),
            text(&e.message_id),
        ])?
        .first(None)
        .await
}
async fn send(request: &mut Request, db: &D1Database, actor: &Actor, id: &str) -> Result<Response> {
    let e: Envelope = match body(request, 90 * 1024).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if !e.valid(id) || !matches!(e.kind.as_str(), "application" | "commit") {
        return error(400, "invalid_envelope");
    }
    let hash = e.hash()?;
    // Admission, current authority, quotas and ciphertext insertion are one SQL
    // mutation. A retained receipt wins even after its ciphertext was consumed.
    let outcome=db.batch(vec![db.prepare("INSERT INTO messaging_mail(channel_id,message_id,sender_scope,recipient_scope,kind,digest,expires_at,envelope_hash,wire) SELECT c.channel_id,?3,?4,?5,?6,?7,?8,?9,?10 FROM messaging_delivery_ready c JOIN messaging_live_owner a WHERE c.channel_id=?1 AND c.bootstrap_complete=1 AND a.secret_hash=?2 AND NOT EXISTS(SELECT 1 FROM messaging_invitation_packet p WHERE p.sender_scope=?4 AND p.message_id=?3) AND ((c.a_scope=?4 AND c.b_scope=?5 AND c.a_owner=a.account_id) OR (c.b_scope=?4 AND c.a_scope=?5 AND c.b_owner=a.account_id)) AND ?8>unixepoch() AND ?8<=unixepoch()+86400 AND (SELECT count(*) FROM messaging_mail m WHERE m.channel_id=c.channel_id)<512 AND (SELECT count(*) FROM messaging_mail m WHERE m.channel_id=c.channel_id AND m.consumed=0)<64 ON CONFLICT(sender_scope,message_id) DO NOTHING")
        .bind(&[text(id),text(&actor.secret_hash),text(&e.message_id),text(&e.sender_scope),text(&e.recipient_scope),text(&e.kind),text(&e.digest),num(e.expires_at),text(&hash),text(&e.wire)])?]).await;
    let Some(mut row) = stored(db, &actor.secret_hash, &e).await? else {
        return error(
            if outcome.is_err() { 503 } else { 409 },
            "delivery_unconfirmed_or_denied",
        );
    };
    if row.envelope_hash != hash {
        return error(409, "message_id_conflict");
    }
    row.wire = None;
    json(&serde_json::json!({"status":"stored","receipt":row}))
}
const RECIPIENT_AUTH: &str = "c.channel_id=?1 AND a.secret_hash=?2 AND ((c.a_scope=?3 AND c.a_owner=a.account_id) OR (c.b_scope=?3 AND c.b_owner=a.account_id))";
#[derive(Deserialize)]
struct Access {
    channel_id: String,
    now: u64,
}
async fn recipient(db: &D1Database, secret: &str, id: &str, scope: &str) -> Result<Option<u64>> {
    let sql = format!(
        "SELECT c.channel_id,unixepoch() AS now FROM messaging_delivery_ready c JOIN messaging_live_owner a WHERE {RECIPIENT_AUTH} AND c.bootstrap_complete=1"
    );
    let row = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&[text(id), text(secret), text(scope)])?
        .first::<Access>(None)
        .await?;
    Ok(row.filter(|r| r.channel_id == id).map(|r| r.now))
}
async fn inbox(db: &D1Database, actor: &Actor, id: &str, scope: &str) -> Result<Response> {
    let sql = format!(
        "SELECT m.* FROM messaging_mail m JOIN messaging_delivery_ready c ON c.channel_id=m.channel_id JOIN messaging_live_owner a WHERE {RECIPIENT_AUTH} AND m.recipient_scope=?3 AND m.consumed=0 ORDER BY m.sequence LIMIT 1"
    );
    let row = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&[text(id), text(&actor.secret_hash), text(scope)])?
        .first::<Mail>(None)
        .await?;
    // Recheck both permission and database time in the last awaited query.
    // Lost authority must not look like a synchronized empty inbox.
    let Some(now) = recipient(db, &actor.secret_hash, id, scope).await? else {
        return error(403, "channel_unavailable");
    };
    if row.as_ref().is_some_and(|m| m.expires_at <= now) {
        return error(410, "mailbox_expired_recovery_required");
    }
    json(&serde_json::json!({"message":row}))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consume {
    recipient_scope: String,
    digest: String,
    envelope_hash: String,
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
        .any(|x| profile::decode(x, 32).is_err())
    {
        return error(400, "invalid_receipt");
    }
    let sql = format!(
        "UPDATE messaging_mail AS m SET consumed=1,wire=NULL WHERE m.channel_id=?1 AND m.recipient_scope=?3 AND m.message_id=?4 AND m.digest=?5 AND m.envelope_hash=?6 AND (m.consumed=1 OR m.sequence=(SELECT MIN(x.sequence) FROM messaging_mail x WHERE x.channel_id=?1 AND x.recipient_scope=?3 AND x.consumed=0)) AND EXISTS(SELECT 1 FROM messaging_delivery_ready c JOIN messaging_live_owner a WHERE {RECIPIENT_AUTH})"
    );
    db.prepare(sql)
        .bind(&[
            text(id),
            text(&actor.secret_hash),
            text(&v.recipient_scope),
            text(message),
            text(&v.digest),
            text(&v.envelope_hash),
        ])?
        .run()
        .await?;
    let sql = format!(
        "SELECT m.* FROM messaging_mail m JOIN messaging_delivery_ready c ON c.channel_id=m.channel_id JOIN messaging_live_owner a WHERE {RECIPIENT_AUTH} AND m.recipient_scope=?3 AND m.message_id=?4 AND m.digest=?5 AND m.envelope_hash=?6 AND m.consumed=1"
    );
    let row = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&[
            text(id),
            text(&actor.secret_hash),
            text(&v.recipient_scope),
            text(message),
            text(&v.digest),
            text(&v.envelope_hash),
        ])?
        .first::<Mail>(None)
        .await?;
    match row {
        Some(_) => json(&serde_json::json!({"status":"consumed"})),
        None => error(409, "consume_unconfirmed_or_denied"),
    }
}
// A grant exposes fresh leases only for its two pinned generations. It does
// not establish first trust or silently follow a replacement device/key.
async fn grant_device(
    db: &D1Database,
    secret: &str,
    id: &str,
    scope: &str,
    own: bool,
) -> Result<Option<Device>> {
    let comparison = if own { "=" } else { "<>" };
    let sql = format!(
        "SELECT g.*,unixepoch() AS now FROM messaging_live_device g JOIN messaging_delivery_ready c ON g.scope_hash IN(c.a_scope,c.b_scope) JOIN messaging_live_owner a WHERE {RECIPIENT_AUTH} AND g.scope_hash{comparison}?3"
    );
    db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&[text(id), text(secret), text(scope)])?
        .first(None)
        .await
}
async fn bindings(
    db: &D1Database,
    actor: &Actor,
    env: &Env,
    issuer: &str,
    id: &str,
    scope: &str,
) -> Result<Response> {
    let signer = Signer::load(env).await?;
    let mut tokens = Vec::new();
    let mut snapshots = Vec::new();
    for own in [true, false] {
        let Some(d) = grant_device(db, &actor.secret_hash, id, scope, own).await? else {
            return error(403, "channel_unavailable");
        };
        let identity = Identity {
            issuer: issuer.into(),
            account_id: d.account_id.clone(),
            device_id: d.device_id.clone(),
            generation: d.generation,
        };
        tokens.push(
            signer
                .binding(&identity, &d.public_key, d.revision, &d.status, d.now)
                .await?,
        );
        snapshots.push(d);
    }
    for (own, old) in [true, false].into_iter().zip(snapshots) {
        let Some(d) = grant_device(db, &actor.secret_hash, id, scope, own).await? else {
            return error(403, "channel_unavailable");
        };
        if d.scope_hash != old.scope_hash
            || d.enrollment_id != old.enrollment_id
            || d.revision != old.revision
            || d.status != old.status
            || d.now >= old.now + 300
        {
            return error(409, "channel_device_changed");
        }
    }
    json(&serde_json::json!({"own":tokens[0],"peer":tokens[1]}))
}
pub(super) async fn dispatch(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    env: &Env,
    issuer: &str,
) -> Result<Response> {
    let path = request.url()?.path().to_owned();
    let p: Vec<_> = path.split('/').collect();
    match (request.method(), p.as_slice()) {
        (Method::Post, ["", "messaging", "channels", id, "replace", "predecessor"])
            if profile::uuid(id) =>
        {
            replacement::predecessor(request, db, actor, env, issuer, id).await
        }
        (Method::Post, ["", "messaging", "channels", id, "replace"]) if profile::uuid(id) => {
            replacement::approve(request, db, actor, id).await
        }
        (Method::Post, ["", "messaging", "channels", id, "replace", "cancel"])
            if profile::uuid(id) =>
        {
            replacement::cancel(request, db, actor, id).await
        }
        (Method::Post, ["", "messaging", "channels", id, "replace", "status"])
            if profile::uuid(id) =>
        {
            replacement::status(request, db, actor, id).await
        }
        (Method::Post, ["", "messaging", "channels", id, "replace", "stop", "status"])
            if profile::uuid(id) =>
        {
            replacement::stop_status(request, db, actor, id).await
        }
        (Method::Post, ["", "messaging", "channels", id, "replace", "stop"])
            if profile::uuid(id) =>
        {
            replacement::stop(request, db, actor, id).await
        }
        (_, ["", "messaging", "channels", id, "close" | "rejoin", ..]) if profile::uuid(id) => {
            recovery::dispatch(request, db, actor, id).await
        }
        (_, ["", "messaging", "channels", id, "invitation", ..]) if profile::uuid(id) => {
            invitation::dispatch(request, db, actor, id).await
        }
        (Method::Get, ["", "messaging", "channels", id, "bindings", scope])
            if profile::uuid(id) && profile::decode(scope, 32).is_ok() =>
        {
            bindings(db, actor, env, issuer, id, scope).await
        }
        (Method::Post, ["", "messaging", "channels", id]) if profile::uuid(id) => {
            consent(request, db, actor, id).await
        }
        (Method::Post, ["", "messaging", "channels", id, "block"]) if profile::uuid(id) => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Empty {}
            if let Err(r) = body::<Empty>(request, 64).await {
                return Ok(r);
            }
            db.prepare("UPDATE messaging_channel SET blocked=1 WHERE channel_id=?1 AND EXISTS(SELECT 1 FROM messaging_live_device d JOIN messaging_live_owner a ON a.account_id=d.owner_id WHERE a.secret_hash=?2 AND d.scope_hash IN(messaging_channel.a_scope,messaging_channel.b_scope))")
                .bind(&[text(id),text(&actor.secret_hash)])?.run().await?;
            match channel(db, &actor.secret_hash, id).await? {
                Some(c) if c.blocked == 1 => json(&serde_json::json!({"status":"blocked"})),
                _ => error(403, "channel_unavailable"),
            }
        }
        (Method::Post, ["", "messaging", "channels", id, "messages"]) if profile::uuid(id) => {
            send(request, db, actor, id).await
        }
        (Method::Get, ["", "messaging", "channels", id, "inbox", scope])
            if profile::uuid(id) && profile::decode(scope, 32).is_ok() =>
        {
            inbox(db, actor, id, scope).await
        }
        (
            Method::Post,
            [
                "",
                "messaging",
                "channels",
                id,
                "messages",
                message,
                "consume",
            ],
        ) if profile::uuid(id) && profile::uuid(message) => {
            consume(request, db, actor, id, message).await
        }
        _ => error(404, "not_found"),
    }
}
