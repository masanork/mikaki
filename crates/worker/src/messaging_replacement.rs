//! A changed-key successor is distinct from same-key rejoin. Historical device
//! ownership authorizes closure; only the current exact pair can approve/admit.
use super::invitation::Offer;
use super::*;
#[path = "messaging_replacement_stop.rs"]
mod stop;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    previous: Offer,
    next: Offer,
    scope: String,
    operation_id: String,
}
impl Approval {
    fn valid_descriptors(&self, id: &str) -> bool {
        recovery::valid_offer(&self.previous, &self.previous.channel.id)
            && recovery::valid_offer(&self.next, id)
            && self.previous.channel.id != self.next.channel.id
            && self.previous.channel.group != self.next.channel.group
            && profile::uuid(&self.operation_id)
    }
    fn valid(&self, id: &str) -> bool {
        self.valid_descriptors(id)
            && [&self.next.channel.a.scope, &self.next.channel.b.scope].contains(&&self.scope)
    }
    fn args(&self, actor: &Actor) -> Result<Vec<JsValue>> {
        let old = &self.previous.channel;
        let next = &self.next.channel;
        Ok(vec![
            text(&next.id),
            text(&actor.secret_hash),
            text(&next.group),
            text(&next.a.scope),
            text(&next.b.scope),
            text(&next.a.fingerprint),
            text(&next.b.fingerprint),
            text(&self.next.inviter_scope),
            text(&old.id),
            text(&old.group),
            text(&old.a.scope),
            text(&old.b.scope),
            text(&old.a.fingerprint),
            text(&old.b.fingerprint),
            text(&self.previous.inviter_scope),
            text(&self.scope),
            text(&self.operation_id),
            text(&profile::digest(&serde_json::to_vec(self)?)),
        ])
    }
}
pub(super) async fn stop(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    stop::terminate(request, db, actor, id).await
}
pub(super) async fn stop_status(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    stop::status(request, db, actor, id).await
}
const AUTHORITY: &str = "EXISTS(SELECT 1 FROM messaging_replacement_pair p JOIN messaging_live_owner a ON a.account_id=CASE WHEN p.next_a_scope=?16 THEN p.next_a_owner WHEN p.next_b_scope=?16 THEN p.next_b_owner END WHERE a.secret_hash=?2 AND p.previous_id=?9 AND p.previous_group=?10 AND p.old_a_scope=?11 AND p.old_b_scope=?12 AND p.old_a_fingerprint=?13 AND p.old_b_fingerprint=?14 AND p.old_inviter=?15 AND p.next_a_scope=?4 AND p.next_b_scope=?5 AND p.next_a_fingerprint=?6 AND p.next_b_fingerprint=?7)";
const CHILD: &str = "c.channel_id=?1 AND c.group_id=?3 AND c.a_scope=?4 AND c.b_scope=?5 AND c.a_fingerprint=?6 AND c.b_fingerprint=?7 AND c.inviter_scope=?8 AND c.predecessor_id=?9 AND c.blocked=0";
const UNIQUE_CHILD: &str = "NOT EXISTS(SELECT 1 FROM messaging_channel sibling WHERE sibling.predecessor_id=?9 AND sibling.channel_id<>?1 AND sibling.blocked=0 AND sibling.a_consent=1 AND sibling.b_consent=1)";

// Public historical identity only. The new device may be several generations
// ahead of the original MLS leaf. Never turn the old binding into a live lease.
pub(super) async fn predecessor(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    env: &Env,
    issuer: &str,
    id: &str,
) -> Result<Response> {
    let v: Approval = match body(request, 3000).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if !v.valid(id) {
        return error(400, "invalid_channel_replacement");
    }
    let args = v.args(actor)?;
    let sql = format!(
        "SELECT g.*,unixepoch() AS now FROM messaging_generation g JOIN messaging_live_device d ON d.account_id=g.account_id AND d.device_id=g.device_id AND d.generation>g.generation JOIN messaging_live_owner a ON a.account_id=d.owner_id WHERE d.scope_hash=?16 AND a.secret_hash=?2 AND g.status='revoked' AND ((g.scope_hash=?11 AND g.fingerprint=?13) OR (g.scope_hash=?12 AND g.fingerprint=?14)) AND {AUTHORITY} AND length(?17)=36 AND length(?18)=43"
    );
    let read = || -> Result<_> {
        db.with_session_constraint(D1SessionConstraint::FirstPrimary)?
            .prepare(&sql)
            .bind(&args)
    };
    let Some(old) = read()?.first::<Device>(None).await? else {
        return error(403, "replacement_predecessor_unavailable");
    };
    let signer = Signer::load(env).await?;
    let identity = Identity {
        issuer: issuer.into(),
        account_id: old.account_id.clone(),
        device_id: old.device_id.clone(),
        generation: old.generation,
    };
    let binding = signer
        .binding(&identity, &old.public_key, old.revision, "revoked", old.now)
        .await?;
    let Some(current) = read()?.first::<Device>(None).await? else {
        return error(403, "replacement_predecessor_unavailable");
    };
    if current.scope_hash != old.scope_hash
        || current.enrollment_id != old.enrollment_id
        || current.revision != old.revision
        || current.public_key != old.public_key
        || current.status != old.status
        || current.now >= old.now + 300
    {
        return error(409, "replacement_predecessor_changed");
    }
    json(
        &serde_json::json!({"predecessor_id":v.previous.channel.id,"channel":v.next.channel,"inviter_scope":v.next.inviter_scope,"scope":v.scope,"operation_id":v.operation_id,"binding":binding}),
    )
}

pub(super) async fn approve(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let v: Approval = match body(request, 3000).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    if !v.valid(id) {
        return error(400, "invalid_channel_replacement");
    }
    let old = &v.previous.channel;
    let next = &v.next.channel;
    let args = v.args(actor)?;
    let freeze = format!(
        "UPDATE messaging_channel SET blocked=1 WHERE channel_id=?9 AND {AUTHORITY} AND length(?18)=43"
    );
    let create = format!(
        "INSERT INTO messaging_channel(channel_id,group_id,a_scope,b_scope,a_fingerprint,b_fingerprint,a_consent,b_consent,inviter_scope,bootstrap_complete,predecessor_id) SELECT ?1,?3,?4,?5,?6,?7,0,0,?8,0,?9 WHERE {AUTHORITY} AND length(?18)=43 AND {UNIQUE_CHILD} AND EXISTS(SELECT 1 FROM messaging_channel old WHERE old.channel_id=?9 AND old.blocked=1) ON CONFLICT DO NOTHING"
    );
    let insert = format!(
        "INSERT INTO messaging_replacement_approval(channel_id,owner_id,scope_hash,operation_id,intent_hash) SELECT c.channel_id,a.account_id,?16,?17,?18 FROM messaging_channel c JOIN messaging_live_owner a ON a.secret_hash=?2 WHERE {CHILD} AND {AUTHORITY} AND {UNIQUE_CHILD} AND (EXISTS(SELECT 1 FROM messaging_replacement_approval prior WHERE prior.channel_id=?1 AND prior.owner_id=a.account_id) OR (SELECT count(*) FROM messaging_channel x WHERE (x.a_scope IN(SELECT g.scope_hash FROM messaging_generation g JOIN messaging_account m ON m.account_id=g.account_id WHERE m.owner_id=a.account_id) AND x.a_consent=1) OR (x.b_scope IN(SELECT g.scope_hash FROM messaging_generation g JOIN messaging_account m ON m.account_id=g.account_id WHERE m.owner_id=a.account_id) AND x.b_consent=1))<32) ON CONFLICT(channel_id,owner_id) DO NOTHING"
    );
    let receipt = "EXISTS(SELECT 1 FROM messaging_replacement_approval x JOIN messaging_live_owner a ON a.account_id=x.owner_id WHERE x.channel_id=?1 AND x.scope_hash=?16 AND x.operation_id=?17 AND x.intent_hash=?18 AND a.secret_hash=?2)";
    let consent = format!(
        "UPDATE messaging_channel AS c SET a_consent=MAX(a_consent,CASE WHEN a_scope=?16 THEN 1 ELSE 0 END),b_consent=MAX(b_consent,CASE WHEN b_scope=?16 THEN 1 ELSE 0 END) WHERE {CHILD} AND {AUTHORITY} AND {UNIQUE_CHILD} AND {receipt}"
    );
    let confirmed = format!(
        "EXISTS(SELECT 1 FROM messaging_channel c JOIN messaging_channel old ON old.channel_id=c.predecessor_id WHERE {CHILD} AND old.blocked=1 AND CASE WHEN c.a_scope=?16 THEN c.a_consent ELSE c.b_consent END=1 AND {AUTHORITY} AND {UNIQUE_CHILD} AND {receipt})"
    );
    let guard = format!(
        "INSERT INTO messaging_commit_guard(operation_id,valid) VALUES(?17,CASE WHEN {confirmed} THEN 1 ELSE 0 END) ON CONFLICT(operation_id) DO UPDATE SET valid=excluded.valid"
    );
    let outcome = db
        .batch(vec![
            db.prepare(freeze).bind(&args)?,
            db.prepare(create).bind(&args)?,
            db.prepare(insert).bind(&args)?,
            db.prepare(consent).bind(&args)?,
            db.prepare(guard).bind(&args)?,
        ])
        .await;
    #[derive(Deserialize)]
    struct Confirmed {
        valid: u8,
    }
    let proof = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(format!("SELECT 1 AS valid WHERE {confirmed}"))
        .bind(&args)?
        .first::<Confirmed>(None)
        .await?;
    if !proof.is_some_and(|p| p.valid == 1) {
        return error(
            if outcome.is_err() { 409 } else { 503 },
            "replacement_unconfirmed_or_denied",
        );
    }
    let Some(row) = invitation::authorized(db, actor, id, &v.scope).await? else {
        return error(409, "replacement_authority_changed");
    };
    if row.channel() != *next || row.predecessor_id.as_deref() != Some(&old.id) || row.blocked != 0
    {
        return error(409, "replacement_authority_changed");
    }
    json(
        &serde_json::json!({"predecessor_id":old.id,"channel":row.channel(),"inviter_scope":v.next.inviter_scope,"ready":row.a_consent==1 && row.b_consent==1,"complete":row.bootstrap_complete==1,"scope":v.scope,"operation_id":v.operation_id}),
    )
}

// A pending proposal can be vetoed even after the peer's head changes. The
// caller's own scope and SSO authority must still be current. No consent is added.
fn stop_authority() -> String {
    format!(
        "{} AND EXISTS(SELECT 1 FROM messaging_live_device own JOIN messaging_live_owner actor ON actor.account_id=own.owner_id WHERE own.scope_hash=?16 AND actor.secret_hash=?2)",
        AUTHORITY.replace(
            "messaging_replacement_pair",
            "messaging_replacement_candidate"
        )
    )
}
fn exact_child() -> String {
    CHILD.replace(" AND c.blocked=0", "")
}
const OWN_APPROVAL: &str = "NOT EXISTS(SELECT 1 FROM messaging_replacement_approval x JOIN messaging_live_owner a ON a.account_id=x.owner_id WHERE x.channel_id=?1 AND a.secret_hash=?2 AND (x.scope_hash<>?16 OR x.operation_id<>?17 OR x.intent_hash<>?18))";

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
    if !v.valid(id) {
        return error(400, "invalid_channel_replacement");
    }
    #[derive(Deserialize)]
    struct State {
        state: String,
    }
    let sql = format!(
        "SELECT CASE WHEN c.channel_id IS NULL THEN 'unpublished' WHEN c.blocked=1 AND NOT(c.a_consent=1 AND c.b_consent=1) THEN 'cancelled' WHEN c.blocked=1 THEN 'closed' WHEN c.a_consent=1 AND c.b_consent=1 THEN 'admitted' ELSE 'waiting' END AS state FROM (SELECT 1) seed LEFT JOIN messaging_channel c ON {} WHERE {} AND ({OWN_APPROVAL}) AND (c.channel_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM messaging_channel clash WHERE clash.channel_id=?1))",
        exact_child(),
        stop_authority()
    );
    let row = db
        .with_session_constraint(D1SessionConstraint::FirstPrimary)?
        .prepare(sql)
        .bind(&v.args(actor)?)?
        .first::<State>(None)
        .await?;
    match row {
        Some(row) => json(
            &serde_json::json!({"predecessor_id":v.previous.channel.id,"channel":v.next.channel,"inviter_scope":v.next.inviter_scope,"scope":v.scope,"operation_id":v.operation_id,"state":row.state}),
        ),
        None => error(409, "replacement_status_unavailable"),
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cancellation {
    previous: Offer,
    next: Offer,
    scope: String,
    approval_id: String,
    operation_id: String,
}
pub(super) async fn cancel(
    request: &mut Request,
    db: &D1Database,
    actor: &Actor,
    id: &str,
) -> Result<Response> {
    let v: Cancellation = match body(request, 3000).await {
        Ok(v) => v,
        Err(r) => return Ok(r),
    };
    let approval = Approval {
        previous: v.previous.clone(),
        next: v.next.clone(),
        scope: v.scope.clone(),
        operation_id: v.approval_id.clone(),
    };
    if !approval.valid(id) || !profile::uuid(&v.operation_id) || v.operation_id == v.approval_id {
        return error(400, "invalid_replacement_cancellation");
    }
    let mut args = approval.args(actor)?;
    args.push(text(&v.operation_id));
    args.push(text(&profile::digest(&serde_json::to_vec(&v)?)));
    let authority = stop_authority();
    let child = exact_child();
    let receipt = "EXISTS(SELECT 1 FROM messaging_replacement_cancellation x JOIN messaging_live_owner a ON a.account_id=x.owner_id WHERE x.channel_id=?1 AND x.scope_hash=?16 AND x.approval_id=?17 AND x.operation_id=?19 AND x.intent_hash=?20 AND a.secret_hash=?2";
    let freeze = format!(
        "UPDATE messaging_channel SET blocked=1 WHERE channel_id=?9 AND {authority} AND ({OWN_APPROVAL}) AND length(?20)=43"
    );
    let create = format!(
        "INSERT INTO messaging_channel(channel_id,group_id,a_scope,b_scope,a_fingerprint,b_fingerprint,a_consent,b_consent,inviter_scope,bootstrap_complete,predecessor_id) SELECT ?1,?3,?4,?5,?6,?7,0,0,?8,0,?9 WHERE {authority} AND ({OWN_APPROVAL}) AND length(?20)=43 ON CONFLICT DO NOTHING"
    );
    let insert = format!(
        "INSERT INTO messaging_replacement_cancellation(channel_id,owner_id,scope_hash,approval_id,operation_id,intent_hash,outcome) SELECT c.channel_id,a.account_id,?16,?17,?19,?20,CASE WHEN c.a_consent=1 AND c.b_consent=1 THEN 'admitted' ELSE 'cancelled' END FROM messaging_channel c JOIN messaging_live_owner a ON a.secret_hash=?2 WHERE {child} AND {authority} AND ({OWN_APPROVAL}) AND (EXISTS(SELECT 1 FROM messaging_replacement_cancellation prior WHERE prior.channel_id=?1 AND prior.owner_id=a.account_id) OR (SELECT count(*) FROM messaging_replacement_cancellation limit_row WHERE limit_row.owner_id=a.account_id)<32) ON CONFLICT(channel_id,owner_id) DO NOTHING"
    );
    let block = format!(
        "UPDATE messaging_channel AS c SET blocked=1 WHERE {child} AND NOT(c.a_consent=1 AND c.b_consent=1) AND {authority} AND ({OWN_APPROVAL}) AND {receipt} AND x.outcome='cancelled')"
    );
    let confirmed = format!(
        "EXISTS(SELECT 1 FROM messaging_channel c JOIN messaging_channel old ON old.channel_id=c.predecessor_id WHERE {child} AND old.blocked=1 AND {authority} AND ({OWN_APPROVAL}) AND {receipt} AND ((x.outcome='cancelled' AND c.blocked=1 AND NOT(c.a_consent=1 AND c.b_consent=1)) OR (x.outcome='admitted' AND c.a_consent=1 AND c.b_consent=1))))"
    );
    let guard = format!(
        "INSERT INTO messaging_commit_guard(operation_id,valid) VALUES(?19,CASE WHEN {confirmed} THEN 1 ELSE 0 END) ON CONFLICT(operation_id) DO UPDATE SET valid=excluded.valid"
    );
    let outcome = db
        .batch(vec![
            db.prepare(freeze).bind(&args)?,
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
    let proof=db.with_session_constraint(D1SessionConstraint::FirstPrimary)?.prepare(format!("SELECT x.outcome FROM messaging_replacement_cancellation x JOIN messaging_live_owner a ON a.account_id=x.owner_id WHERE x.channel_id=?1 AND x.operation_id=?19 AND a.secret_hash=?2 AND {confirmed}")).bind(&args)?.first::<Proof>(None).await?;
    let Some(proof) = proof else {
        return error(
            if outcome.is_err() { 409 } else { 503 },
            "replacement_cancellation_unconfirmed",
        );
    };
    json(
        &serde_json::json!({"predecessor_id":v.previous.channel.id,"channel":v.next.channel,"inviter_scope":v.next.inviter_scope,"scope":v.scope,"approval_id":v.approval_id,"operation_id":v.operation_id,"outcome":proof.outcome}),
    )
}
