//! Registered public-wallet authorization code + S256 PKCE, separate from card intake.
use super::*;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Client {
    client_id: String,
    name: String,
    redirect_uri: String,
    attesters: Option<Vec<String>>,
}
pub(super) fn enabled(ctx: &RouteContext<()>) -> bool {
    super::enabled(ctx)
        && ctx
            .env
            .var("IDENTITY_WALLET_ENABLED")
            .is_ok_and(|v| v.to_string() == "true")
}
pub(super) fn haip(ctx: &RouteContext<()>) -> bool {
    enabled(ctx)
        && ctx
            .env
            .var("IDENTITY_HAIP_ENABLED")
            .is_ok_and(|v| v.to_string() == "true")
}
fn attester_policy(
    ctx: &RouteContext<()>,
) -> worker::Result<(
    Vec<mikaki_identity::client_attestation::AttesterTrust>,
    String,
)> {
    let raw = ctx.env.var("IDENTITY_WALLET_ATTESTERS")?.to_string();
    if raw.len() > 65536 {
        return Err(server_error());
    }
    let policies: Vec<mikaki_identity::client_attestation::AttesterTrust> =
        serde_json::from_str(&raw).map_err(|_| server_error())?;
    let mut seen = std::collections::HashSet::new();
    if policies.is_empty()
        || policies.len() > 8
        || policies.iter().any(|p| {
            p.issuer.is_empty()
                || p.issuer.len() > 2048
                || !seen.insert(&p.issuer)
                || p.trust_anchors.is_empty()
                || p.trust_anchors.len() > 8
                || p.trust_anchors
                    .iter()
                    .any(|c| mikaki_identity::certificate::decode_certificate(c).is_err())
        })
    {
        return Err(server_error());
    }
    for p in &policies {
        mikaki_identity::certificate::validate_attester_roots(&p.trust_anchors)
            .map_err(|_| server_error())?;
    }
    Ok((policies, raw))
}
pub(super) fn key_attestation_policy(
    ctx: &RouteContext<()>,
) -> worker::Result<(mikaki_identity::key_attestation::Trust, String)> {
    let raw = ctx.env.var("IDENTITY_KEY_ATTESTATION_TRUST")?.to_string();
    if raw.len() > 65536 {
        return Err(server_error());
    }
    let policy: mikaki_identity::key_attestation::Trust =
        serde_json::from_str(&raw).map_err(|_| server_error())?;
    policy.validate().map_err(|_| server_error())?;
    Ok((policy, raw))
}
pub(super) fn validate_haip(ctx: &RouteContext<()>) -> worker::Result<()> {
    if haip(ctx) {
        clients(ctx)?;
    }
    Ok(())
}
async fn authenticate(
    req: &Request,
    ctx: &RouteContext<()>,
    client: &str,
) -> worker::Result<
    Result<Option<mikaki_identity::client_attestation::VerifiedAttestation>, &'static str>,
> {
    let attestation = req.headers().get("oauth-client-attestation")?;
    let pop = req.headers().get("oauth-client-attestation-pop")?;
    if !haip(ctx) {
        return Ok(if attestation.is_some() || pop.is_some() {
            Err("invalid_client")
        } else {
            Ok(None)
        });
    }
    let (Some(attestation), Some(pop)) = (attestation, pop) else {
        return Ok(Err("invalid_client"));
    };
    let (policies, _) = attester_policy(ctx)?;
    let (registry, _) = clients(ctx)?;
    let allowed = registry
        .iter()
        .find(|c| c.client_id == client)
        .and_then(|c| c.attesters.as_ref())
        .ok_or_else(server_error)?;
    let policies: Vec<_> = policies
        .into_iter()
        .filter(|p| allowed.contains(&p.issuer))
        .collect();
    let Ok(proof) = mikaki_identity::client_attestation::verify(
        &attestation,
        &pop,
        client,
        &issuer(ctx)?,
        &policies,
        now()?,
    ) else {
        return Ok(Err("invalid_client"));
    };
    Ok(Ok(Some(proof)))
}
fn binding(
    proof: &Option<mikaki_identity::client_attestation::VerifiedAttestation>,
) -> worker::Result<JsValue> {
    Ok(match proof {
        Some(p) => js(&hash(&serde_json::to_string(&(
            &p.attester,
            &p.thumbprint,
        ))?)),
        None => JsValue::NULL,
    })
}
pub(super) async fn accept_attestation(
    ctx: &RouteContext<()>,
    client: &str,
    proof: &Option<mikaki_identity::client_attestation::VerifiedAttestation>,
) -> worker::Result<bool> {
    let Some(proof) = proof else {
        return Ok(true);
    };
    let replay = hash(&serde_json::to_string(&(
        &proof.attester,
        client,
        &proof.thumbprint,
        &proof.replay_id,
    ))?);
    let db = ctx.env.d1("DB")?;
    db.prepare("DELETE FROM identity_wallet_attestation_replay WHERE replay_hash IN (SELECT replay_hash FROM identity_wallet_attestation_replay WHERE expires_at<=unixepoch() LIMIT 1000)").run().await?;
    let result = db.prepare("INSERT INTO identity_wallet_attestation_replay(replay_hash,expires_at) SELECT ?1,?2 WHERE NOT EXISTS(SELECT 1 FROM identity_wallet_attestation_replay WHERE replay_hash=?1) AND (SELECT count(*) FROM identity_wallet_attestation_replay)<10000")
        .bind(&[js(&replay), JsValue::from_f64(proof.replay_until as f64)])?.run().await?;
    Ok(result.meta()?.and_then(|m| m.changes).unwrap_or(0) != 0)
}

// Query parameters are fixed registration data, never request-selected routing.
fn valid_redirect_query(uri: &url::Url, authenticated: bool) -> bool {
    if uri.query().is_none() {
        return true;
    }
    if !authenticated || uri.query().is_none_or(|q| q.is_empty() || q.len() > 1024) {
        return false;
    }
    let mut names = std::collections::HashSet::new();
    let mut count = 0;
    uri.query_pairs().all(|(name, _)| {
        count += 1;
        count <= 16
            && !name.is_empty()
            && names.insert(name.to_string())
            && !matches!(
                name.as_ref(),
                "code" | "state" | "iss" | "error" | "error_description" | "error_uri"
            )
    })
}

fn clients(ctx: &RouteContext<()>) -> worker::Result<(Vec<Client>, String)> {
    let raw = ctx.env.var("IDENTITY_WALLET_CLIENTS")?.to_string();
    if raw.len() > 32768 {
        return Err(server_error());
    }
    let clients: Vec<Client> = serde_json::from_str(&raw).map_err(|_| server_error())?;
    let mut ids = std::collections::HashSet::new();
    if clients.is_empty()
        || clients.len() > 32
        || !clients.iter().all(|c| {
            let uri = url::Url::parse(&c.redirect_uri);
            !c.client_id.is_empty()
                && c.client_id.len() <= 256
                && ids.insert(&c.client_id)
                && !c.name.is_empty()
                && c.name.len() <= 160
                && c.redirect_uri.len() <= 2048
                && uri.is_ok_and(|u| {
                    u.scheme() == "https"
                        && u.host_str().is_some()
                        && u.username().is_empty()
                        && u.password().is_none()
                        && valid_redirect_query(&u, haip(ctx))
                        && u.fragment().is_none()
                        && u.as_str() == c.redirect_uri
                })
        })
    {
        return Err(server_error());
    }
    let binding_policy = if haip(ctx) {
        if !crate::dpop_nonce_required(&ctx.env)? {
            return Err(server_error());
        }
        let (policies, trust) = attester_policy(ctx)?;
        if clients.iter().any(|c| {
            c.attesters.as_ref().is_none_or(|a| {
                a.is_empty()
                    || a.len() > 8
                    || a.iter()
                        .any(|issuer| !policies.iter().any(|p| &p.issuer == issuer))
            })
        }) {
            return Err(server_error());
        }
        {
            let (_, key_trust) = key_attestation_policy(ctx)?;
            let encryption_policy = super::encryption_key(ctx)?
                .map(|key| key.public().metadata().to_string())
                .unwrap_or_default();
            format!("haip-attestation-v7-query-time:{trust}:{key_trust}:{encryption_policy}")
        }
    } else {
        "public-wallet-v3-par-completion".to_owned()
    };
    Ok((clients, hash(&format!("{raw}:{binding_policy}"))))
}
#[derive(Deserialize, serde::Serialize)]
struct Authorization {
    response_type: String,
    response_mode: Option<String>,
    client_id: String,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    code_challenge_method: String,
    state: Option<String>,
    dpop_jkt: Option<String>,
    resource: Option<String>,
    authorization_details: Option<String>,
    request: Option<String>,
    request_uri: Option<String>,
    issuer_state: Option<String>,
    client_secret: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<String>,
}
fn invalid_request(request: &Authorization, iss: &str) -> bool {
    request.response_type != "code"
        || request
            .response_mode
            .as_deref()
            .is_some_and(|mode| mode != "query")
        || request.code_challenge_method != "S256"
        || !challenge(&request.code_challenge)
        || request.scope.len() > 1024
        || request.dpop_jkt.as_ref().is_some_and(|jkt| !challenge(jkt))
        || request
            .state
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 512)
        || request.resource.as_ref().is_some_and(|s| s != iss)
        || request.authorization_details.is_some()
        || request.request.is_some()
        || request.request_uri.is_some()
        || request.issuer_state.is_some()
        || request.client_secret.is_some()
        || request.client_assertion.is_some()
        || request.client_assertion_type.is_some()
}
fn configuration(scope: &str) -> Option<&'static str> {
    let mut recognized = scope.split_ascii_whitespace().filter_map(|s| match s {
        "linked_document" => Some(issuance::CONFIGURATION),
        "linked_document_mdoc" => Some(mdoc::CONFIGURATION),
        _ => None,
    });
    let first = recognized.next()?;
    if recognized.next().is_some() {
        return None;
    }
    Some(first)
}
fn challenge(s: &str) -> bool {
    valid_id(s)
        && B64
            .decode(s)
            .is_ok_and(|bytes| bytes.len() == 32 && B64.encode(bytes) == s)
}
fn html(body: String) -> worker::Result<Response> {
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )?
        .from_html(body)
}
pub async fn authorize_get(req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    if !limited(&req, &ctx, "wallet-authorize").await? {
        return error(429, "slow_down");
    }
    let url = req.url()?;
    let query = url.query().unwrap_or("");
    let mut names = std::collections::HashSet::new();
    if query.len() > 8192
        || url.query_pairs().count() > 32
        || !url.query_pairs().all(|(k, _)| names.insert(k.into_owned()))
    {
        return error(400, "invalid_request");
    }
    let (clients, client_policy) = clients(&ctx)?;
    let (request, par_hash) = if let Some(uri) = url
        .query_pairs()
        .find(|(key, _)| key == "request_uri")
        .map(|(_, value)| value.into_owned())
    {
        // All authorization parameters come from the stored PAR. Parameters
        // alongside the reference cannot replace redirect_uri, scope or state.
        let client = url
            .query_pairs()
            .find(|(key, _)| key == "client_id")
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default();
        let Some(secret) = uri
            .strip_prefix("urn:ietf:params:oauth:request_uri:")
            .filter(|secret| valid_id(secret))
        else {
            return error(400, "invalid_request_uri");
        };
        #[derive(Deserialize)]
        struct Pushed {
            request_json: String,
            used: u32,
            expires_at: u64,
            redirect_uri: Option<String>,
            wallet_state: Option<String>,
        }
        let pushed = ctx.env.d1("DB")?.prepare("SELECT request_json,used,expires_at,redirect_uri,wallet_state FROM identity_wallet_par WHERE request_hash=?1 AND client_id=?2 AND client_policy_hash=?3")
            .bind(&[js(&hash(secret)),js(&client),js(&client_policy)])?.first::<Pushed>(None).await?;
        let Some(pushed) = pushed else {
            return error(400, "invalid_request_uri");
        };
        if pushed.used != 0 || pushed.expires_at <= now()? {
            let Some(destination) = pushed.redirect_uri.filter(|uri| {
                clients
                    .iter()
                    .any(|c| c.client_id == client && &c.redirect_uri == uri)
            }) else {
                return error(400, "invalid_request_uri");
            };
            let mut callback = url::Url::parse(&destination).map_err(|_| server_error())?;
            callback
                .query_pairs_mut()
                .append_pair("error", "invalid_request_uri");
            if let Some(state) = pushed.wallet_state {
                callback.query_pairs_mut().append_pair("state", &state);
            }
            callback
                .query_pairs_mut()
                .append_pair("iss", &issuer(&ctx)?);
            return Ok(Response::builder()
                .with_status(303)
                .with_header("Cache-Control", "no-store")?
                .with_header("Referrer-Policy", "no-referrer")?
                .with_header("Location", callback.as_str())?
                .empty());
        }
        (
            serde_json::from_str::<Authorization>(&pushed.request_json)
                .map_err(|_| server_error())?,
            Some(hash(secret)),
        )
    } else {
        if haip(&ctx) {
            return error(400, "invalid_request");
        }
        let Ok(request) = serde_urlencoded::from_str::<Authorization>(query) else {
            return error(400, "invalid_request");
        };
        (request, None)
    };
    let iss = issuer(&ctx)?;
    let Some(client) = clients
        .iter()
        .find(|c| c.client_id == request.client_id && c.redirect_uri == request.redirect_uri)
    else {
        return error(400, "invalid_client"); // Never redirect an unvalidated request.
    };
    if invalid_request(&request, &iss) {
        return error(400, "invalid_request");
    }
    let Some(configuration) = configuration(&request.scope) else {
        return error(400, "invalid_scope");
    };
    if configuration == mdoc::CONFIGURATION && mdoc_certificate(&ctx)?.is_none() {
        return error(400, "invalid_scope");
    }
    let (trust, policy_hash) = policy(&ctx)?;
    let time = now()?;
    signing(&ctx)?;
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    #[derive(Deserialize)]
    struct Document {
        document_id: String,
        document_json: String,
    }
    let documents = db.prepare("SELECT d.document_id,d.document_json FROM identity_document d JOIN account_security a ON a.account_id=d.account_id WHERE d.account_id=?1 AND d.revoked=0 AND d.valid_until>unixepoch() AND d.policy_hash=?2 AND a.active=1 AND a.epoch=d.epoch ORDER BY d.linked_at DESC LIMIT 100")
        .bind(&[js(&owner.account_id), js(&policy_hash)])?.all().await?.results::<Document>()?;
    let escape = crate::i18n::html_escape;
    let mut options = String::new();
    for document in documents {
        let parsed: VerifiedDocument =
            serde_json::from_str(&document.document_json).map_err(|_| server_error())?;
        // Recheck physical expiry and the evidence pin before displaying a choice.
        if issuance::Validity::new(&parsed, time, u64::MAX).is_err() {
            continue;
        }
        if !trust.iter().any(|k| {
            k.id == parsed.trusted_key_id
                && k.document_type == parsed.attributes.document_type
                && k.not_before <= time
                && time < k.not_after
        }) {
            continue;
        }
        options.push_str(&format!("<label><input type=radio name=document value='{}' required>{:?}: {} / {} / {}</label><br>", escape(&document.document_id), parsed.attributes.document_type, escape(&parsed.attributes.name), escape(&parsed.attributes.address), escape(&parsed.attributes.birth_date)));
    }
    if options.is_empty() {
        return error(403, "document_revalidation_required");
    }
    let grant = random()?;
    let csrf = random()?;
    let r = db.prepare("INSERT INTO identity_wallet_grant(grant_id,account_id,epoch,session_hash,csrf_hash,client_id,client_policy_hash,policy_hash,redirect_uri,wallet_state,code_challenge,configuration,state,expires_at,par_hash,authorization_dpop_jkt,issuance_limit) SELECT ?1,?2,a.epoch,?3,?4,?5,?6,?7,?8,?9,?10,?11,'pending',unixepoch()+300,?12,?13,?14 FROM account_security a WHERE a.account_id=?2 AND a.active=1 AND (SELECT count(*) FROM identity_wallet_grant WHERE state='pending' AND expires_at>unixepoch())<10000 AND (?12 IS NULL OR EXISTS(SELECT 1 FROM identity_wallet_par p WHERE p.request_hash=?12 AND p.used=0 AND p.expires_at>unixepoch()))")
        .bind(&[js(&grant), js(&owner.account_id), js(&owner.secret_hash), js(&hash(&csrf)), js(&client.client_id), js(&client_policy), js(&policy_hash), js(&client.redirect_uri), request.state.as_deref().map(js).unwrap_or(JsValue::NULL), js(&request.code_challenge), js(configuration),par_hash.as_deref().map(js).unwrap_or(JsValue::NULL),request.dpop_jkt.as_deref().map(js).unwrap_or(JsValue::NULL),JsValue::from_f64(if haip(&ctx) {16.0} else {1.0})])?.run().await?;
    if r.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(409, "transaction_unavailable");
    }
    html(format!(
        "<!doctype html><html lang=ja><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>walletへの発行</title><main><h1>walletへの発行を承認</h1><p>アカウント: {}</p><p>登録済み送信先: {} ({})</p><p>戻り先: {}</p><p>形式: {}</p><p>選んだ身分証の氏名・住所・生年月日と、記録されている性別・有効期限を発行します。政府発行の証明書ではありません。有効期間は最長5分です。受領するwalletが所有を証明した鍵に発行します。{}意図したwalletから開始した操作か確認してください。</p><form method=post action=/identity/issuer/authorize><input type=hidden name=grant value='{grant}'><input type=hidden name=csrf value='{csrf}'>{options}<button name=decision value=approve>このwalletへの発行を許可</button><button name=decision value=deny formnovalidate>拒否</button></form></main></html>",
        escape(&owner.account_id),
        escape(&client.name),
        escape(&client.client_id),
        escape(&client.redirect_uri),
        escape(configuration),
        if haip(&ctx) {
            "walletインスタンスのClient Attestationを検証しています。同じ形式・属性を、token取得から120秒以内に最大16件発行することを許可します。"
        } else {
            "公開クライアント登録はwalletの実体を認証するものではありません。"
        }
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    grant: String,
    csrf: String,
    document: Option<String>,
    decision: String,
}
#[derive(Deserialize)]
struct Callback {
    redirect_uri: String,
    wallet_state: Option<String>,
}
pub async fn authorize_post(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    let root = issuer(&ctx)?
        .trim_end_matches("/identity/issuer")
        .to_owned();
    if req.headers().get("origin")?.as_deref() != Some(&root) {
        return error(403, "invalid_origin");
    }
    let Some(body) = form::<Consent>(&mut req).await? else {
        return error(400, "invalid_request");
    };
    if !valid_id(&body.grant)
        || !valid_id(&body.csrf)
        || !matches!(body.decision.as_str(), "approve" | "deny")
        || (body.decision == "approve" && !body.document.as_deref().is_some_and(valid_id))
    {
        return error(400, "invalid_request");
    }
    let (_, client_policy) = clients(&ctx)?;
    let (_, policy_hash) = policy(&ctx)?;
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    let code = random()?;
    let callback = db.prepare("UPDATE identity_wallet_grant SET state=?1,document_id=?2,code_hash=?3,csrf_hash=NULL,expires_at=unixepoch()+90 WHERE grant_id=?4 AND state='pending' AND expires_at>unixepoch() AND csrf_hash=?5 AND session_hash=?6 AND account_id=?7 AND client_policy_hash=?8 AND policy_hash=?9 AND (par_hash IS NULL OR EXISTS(SELECT 1 FROM identity_wallet_par p WHERE p.request_hash=par_hash AND p.client_id=identity_wallet_grant.client_id AND p.client_policy_hash=?8 AND p.used=0 AND p.expires_at>unixepoch())) AND epoch=(SELECT epoch FROM account_security WHERE account_id=?7 AND active=1) AND (?1='denied' OR EXISTS(SELECT 1 FROM identity_document d WHERE d.document_id=?2 AND d.account_id=?7 AND d.epoch=identity_wallet_grant.epoch AND d.revoked=0 AND d.valid_until>unixepoch() AND d.policy_hash=?9)) RETURNING redirect_uri,wallet_state")
        .bind(&[js(if body.decision == "approve" {"offered"} else {"denied"}), if body.decision == "approve" {js(body.document.as_deref().unwrap())} else {JsValue::NULL}, if body.decision == "approve" {js(&hash(&code))} else {JsValue::NULL}, js(&body.grant), js(&hash(&body.csrf)), js(&owner.secret_hash), js(&owner.account_id), js(&client_policy), js(&policy_hash)])?.first::<Callback>(None).await?;
    let Some(callback) = callback else {
        return error(409, "transaction_unavailable");
    };
    let mut uri = url::Url::parse(&callback.redirect_uri).map_err(|_| server_error())?;
    uri.query_pairs_mut().append_pair(
        if body.decision == "approve" {
            "code"
        } else {
            "error"
        },
        if body.decision == "approve" {
            &code
        } else {
            "access_denied"
        },
    );
    if let Some(state) = callback.wallet_state {
        uri.query_pairs_mut().append_pair("state", &state);
    }
    uri.query_pairs_mut().append_pair("iss", &issuer(&ctx)?);
    Ok(Response::builder()
        .with_status(303)
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header("Location", uri.as_str())?
        .empty())
}
#[derive(Deserialize)]
pub(super) struct Token {
    pub grant_type: String,
    pub code: String,
    client_id: Option<String>,
    redirect_uri: String,
    #[serde(default)]
    code_verifier: String,
    resource: Option<String>,
    client_secret: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<String>,
}
pub(super) async fn token(
    req: &Request,
    ctx: &RouteContext<()>,
    body: Token,
) -> worker::Result<Response> {
    if !enabled(ctx) {
        return error(400, "unsupported_grant_type");
    }
    let client_id = match body.client_id {
        Some(id) => id,
        None if haip(ctx) => {
            let Some(compact) = req.headers().get("oauth-client-attestation")? else {
                return error(400, "invalid_client");
            };
            let Ok(id) = mikaki_identity::client_attestation::unverified_client_id(&compact) else {
                return error(400, "invalid_client");
            };
            id
        }
        None => return error(400, "invalid_client"),
    };
    let (clients, client_policy) = clients(ctx)?;
    let iss = issuer(ctx)?;
    if body.grant_type != "authorization_code"
        || !valid_id(&body.code)
        || !clients
            .iter()
            .any(|c| c.client_id == client_id && c.redirect_uri == body.redirect_uri)
        || !(43..=128).contains(&body.code_verifier.len())
        || !body
            .code_verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        || body.resource.as_ref().is_some_and(|s| s != &iss)
        || req.headers().get("authorization")?.is_some()
    {
        return error(400, "invalid_grant");
    }
    if body.client_secret.is_some()
        || body.client_assertion.is_some()
        || body.client_assertion_type.is_some()
    {
        return error(400, "invalid_client");
    }
    let binding = match authenticate(req, ctx, &client_id).await? {
        Ok(binding) => binding,
        Err(code) => return error(400, code),
    };
    let (_, policy_hash) = policy(ctx)?;
    let db = ctx.env.d1("DB")?;
    let dpop_proof = if let Some(compact) = req.headers().get("dpop")? {
        let Ok(proof) = mikaki_oidc::verify_dpop_proof(
            &compact,
            "POST",
            &format!("{iss}/token"),
            mikaki_oidc::DpopTarget::Token,
            now()?,
        ) else {
            return error(400, "invalid_dpop_proof");
        };
        let require_nonce = crate::dpop_nonce_required(&ctx.env)?;
        if require_nonce
            && !crate::dpop::accepts_nonce(
                &db,
                crate::dpop::NonceScope::AuthorizationServer,
                proof.nonce(),
            )
            .await?
        {
            let nonce = crate::dpop::current_nonce(
                &db,
                crate::dpop::NonceScope::AuthorizationServer,
                &mut WorkersCryptoRandom,
            )
            .await?;
            return crate::dpop_nonce_error_response(&nonce, false);
        }
        if let Err(failure) =
            crate::dpop::accept_token_proof(&db, &proof, &random()?, require_nonce).await
        {
            if matches!(&failure, worker::Error::RustError(message) if message == "invalid_dpop_proof")
            {
                return error(400, "invalid_dpop_proof");
            }
            return Err(failure);
        }
        Some(proof)
    } else {
        if haip(ctx) {
            return error(400, "invalid_dpop_proof");
        }
        None
    };
    // A nonce challenge must not consume the client PoP needed for its retry.
    if !accept_attestation(ctx, &client_id, &binding).await? {
        return error(400, "invalid_client");
    }
    let access = random()?;
    let result = ctx.env.d1("DB")?.prepare("UPDATE identity_wallet_grant SET state='token',access_hash=?1,redeemed_code_hash=code_hash,code_hash=NULL,token_expires_at=unixepoch()+120,dpop_jkt=?8 WHERE code_hash=?2 AND state='offered' AND expires_at>unixepoch() AND client_id=?3 AND redirect_uri=?4 AND code_challenge=?5 AND client_policy_hash=?6 AND policy_hash=?7 AND client_binding IS ?9 AND (authorization_dpop_jkt IS NULL OR authorization_dpop_jkt=?8) AND EXISTS(SELECT 1 FROM identity_document d JOIN account_security a ON a.account_id=d.account_id WHERE d.document_id=identity_wallet_grant.document_id AND d.account_id=identity_wallet_grant.account_id AND d.revoked=0 AND d.valid_until>unixepoch() AND d.policy_hash=?7 AND a.active=1 AND a.epoch=d.epoch AND a.epoch=identity_wallet_grant.epoch) RETURNING configuration")
        .bind(&[js(&hash(&access)),js(&hash(&body.code)),js(&client_id),js(&body.redirect_uri),js(&hash(&body.code_verifier)),js(&client_policy),js(&policy_hash),dpop_proof.as_ref().map(|proof|js(proof.thumbprint())).unwrap_or(JsValue::NULL),self::binding(&binding)?])?.first::<Value>(None).await?;
    let Some(row) = result else {
        // RFC 6749 4.1.2: revoke remaining authority on authenticated code reuse.
        // Possessing a code alone, a wrong PKCE verifier or a substitute sender
        // key must never let a caller cancel somebody else's live grant.
        db.prepare("DELETE FROM identity_wallet_grant WHERE redeemed_code_hash=?1 AND state='token' AND client_id=?2 AND redirect_uri=?3 AND code_challenge=?4 AND client_policy_hash=?5 AND policy_hash=?6 AND client_binding IS ?7 AND dpop_jkt IS ?8")
            .bind(&[js(&hash(&body.code)),js(&client_id),js(&body.redirect_uri),js(&hash(&body.code_verifier)),js(&client_policy),js(&policy_hash),self::binding(&binding)?,dpop_proof.as_ref().map(|proof|js(proof.thumbprint())).unwrap_or(JsValue::NULL)])?.run().await?;
        return error(400, "invalid_grant");
    };
    response(
        json!({"access_token":access,"token_type":if dpop_proof.is_some() {"DPoP"} else {"Bearer"},"expires_in":120,"scope":row["configuration"]}),
    )
}
pub(super) async fn load(
    ctx: &RouteContext<()>,
    access: &str,
    configuration: &str,
) -> worker::Result<Option<Row>> {
    if !enabled(ctx) {
        return Ok(None);
    }
    let (_, client_policy) = clients(ctx)?;
    ctx.env.d1("DB")?.prepare("SELECT g.grant_id AS tx_id,'{}' AS holder_json,d.document_json,g.policy_hash,g.state,g.document_id,g.client_id,g.dpop_jkt FROM identity_wallet_grant g JOIN identity_document d ON d.document_id=g.document_id WHERE g.access_hash=?1 AND g.state='token' AND g.token_expires_at>unixepoch() AND g.client_policy_hash=?2 AND g.configuration=?3 AND d.revoked=0")
        .bind(&[js(&hash(access)),js(&client_policy),js(configuration)])?.first::<Row>(None).await
}
pub(super) async fn commit(
    ctx: &RouteContext<()>,
    row: &Row,
    access: &str,
    nonce: &str,
    holder: &PublicJwk,
    expires_at: u64,
) -> worker::Result<bool> {
    let (_, client_policy) = clients(ctx)?;
    let result = ctx.env.d1("DB")?.prepare("UPDATE identity_wallet_grant SET issuance_count=issuance_count+1,state=CASE WHEN issuance_count+1=issuance_limit THEN 'issued' ELSE 'token' END,proof_nonce_hash=?1,holder_json=?2,access_hash=CASE WHEN issuance_count+1=issuance_limit THEN NULL ELSE access_hash END WHERE grant_id=?3 AND access_hash=?4 AND state='token' AND issuance_count<issuance_limit AND token_expires_at>unixepoch() AND client_policy_hash=?5 AND policy_hash=?6 AND EXISTS(SELECT 1 FROM identity_nonce n WHERE n.nonce_hash=?1 AND n.used=0 AND n.expires_at>unixepoch()) AND EXISTS(SELECT 1 FROM identity_document d JOIN account_security a ON a.account_id=d.account_id WHERE d.document_id=identity_wallet_grant.document_id AND d.account_id=identity_wallet_grant.account_id AND d.revoked=0 AND d.valid_until>=?7 AND unixepoch()<?7 AND d.policy_hash=?6 AND a.active=1 AND a.epoch=d.epoch AND a.epoch=identity_wallet_grant.epoch)")
        .bind(&[js(&hash(nonce)),js(&serde_json::to_string(holder)?),js(&row.tx_id),js(&hash(access)),js(&client_policy),js(&row.policy_hash),JsValue::from_f64(expires_at as f64)])?.run().await;
    Ok(matches!(result,Ok(r) if r.meta().ok().flatten().and_then(|m|m.changes).unwrap_or(0)>0))
}

pub async fn par(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if !enabled(&ctx) {
        return error(404, "not_found");
    }
    if !limited(&req, &ctx, "wallet-par").await? {
        return error(429, "slow_down");
    }
    let Some(mut request) = form::<Authorization>(&mut req).await? else {
        return error(400, "invalid_request");
    };
    let (clients, client_policy) = clients(&ctx)?;
    let iss = issuer(&ctx)?;
    if !clients
        .iter()
        .any(|c| c.client_id == request.client_id && c.redirect_uri == request.redirect_uri)
    {
        return error(400, "invalid_client");
    }
    if invalid_request(&request, &iss) || req.headers().get("authorization")?.is_some() {
        return error(400, "invalid_request");
    }
    let Some(configuration) = configuration(&request.scope) else {
        return error(400, "invalid_scope");
    };
    if configuration == mdoc::CONFIGURATION && mdoc_certificate(&ctx)?.is_none() {
        return error(400, "invalid_scope");
    }
    let binding = match authenticate(&req, &ctx, &request.client_id).await? {
        Ok(binding) => binding,
        Err(code) => return error(400, code),
    };
    if let Some(compact) = req.headers().get("dpop")? {
        let Ok(proof) = mikaki_oidc::verify_dpop_proof(
            &compact,
            "POST",
            &format!("{iss}/par"),
            mikaki_oidc::DpopTarget::Token,
            now()?,
        ) else {
            return error(400, "invalid_dpop_proof");
        };
        if request
            .dpop_jkt
            .as_deref()
            .is_some_and(|jkt| jkt != proof.thumbprint())
        {
            return error(400, "invalid_dpop_proof");
        }
        let db = ctx.env.d1("DB")?;
        let require_nonce = crate::dpop_nonce_required(&ctx.env)?;
        if require_nonce
            && !crate::dpop::accepts_nonce(
                &db,
                crate::dpop::NonceScope::AuthorizationServer,
                proof.nonce(),
            )
            .await?
        {
            let nonce = crate::dpop::current_nonce(
                &db,
                crate::dpop::NonceScope::AuthorizationServer,
                &mut WorkersCryptoRandom,
            )
            .await?;
            // Neither client attestation PoP nor PAR state is consumed by this challenge.
            return crate::dpop_nonce_error_response(&nonce, false);
        }
        if let Err(failure) =
            crate::dpop::accept_token_proof(&db, &proof, &random()?, require_nonce).await
        {
            if matches!(&failure, worker::Error::RustError(message) if message == "invalid_dpop_proof")
            {
                return error(400, "invalid_dpop_proof");
            }
            return Err(failure);
        }
        request.dpop_jkt = Some(proof.thumbprint().to_owned());
    }
    if !accept_attestation(&ctx, &request.client_id, &binding).await? {
        return error(400, "invalid_client");
    }
    let secret = random()?;
    let db = ctx.env.d1("DB")?;
    db.prepare("DELETE FROM identity_wallet_par WHERE request_hash IN (SELECT request_hash FROM identity_wallet_par WHERE expires_at<=unixepoch()-300 LIMIT 1000)").run().await?;
    let result = db.prepare("INSERT INTO identity_wallet_par(request_hash,client_id,client_policy_hash,request_json,expires_at,client_binding,redirect_uri,wallet_state) SELECT ?1,?2,?3,?4,unixepoch()+90,?5,?6,?7 WHERE (SELECT count(*) FROM identity_wallet_par)<10000")
        .bind(&[js(&hash(&secret)),js(&request.client_id),js(&client_policy),js(&serde_json::to_string(&request)?),self::binding(&binding)?,js(&request.redirect_uri),request.state.as_deref().map(js).unwrap_or(JsValue::NULL)])?.run().await?;
    if result.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(429, "slow_down");
    }
    Response::builder().with_status(201).with_header("Cache-Control","no-store")?.with_header("Pragma","no-cache")?
        .from_json(&json!({"request_uri":format!("urn:ietf:params:oauth:request_uri:{secret}"),"expires_in":90}))
}

pub(super) async fn authorize_credential(
    req: &Request,
    ctx: &RouteContext<()>,
    row: &Row,
    access: &str,
    is_dpop: bool,
) -> worker::Result<Option<Response>> {
    let Some(jkt) = row.dpop_jkt.as_deref() else {
        return if is_dpop {
            Ok(Some(error(401, "invalid_token")?))
        } else {
            Ok(None)
        };
    };
    if !is_dpop {
        return Ok(Some(error(401, "invalid_token")?));
    }
    let Some(compact) = req.headers().get("dpop")? else {
        return Ok(Some(error(401, "invalid_dpop_proof")?));
    };
    let Ok(proof) = mikaki_oidc::verify_dpop_proof(
        &compact,
        "POST",
        &format!("{}/credential", issuer(ctx)?),
        mikaki_oidc::DpopTarget::Resource {
            access_token: access,
            thumbprint: jkt,
        },
        now()?,
    ) else {
        return Ok(Some(error(401, "invalid_dpop_proof")?));
    };
    let db = ctx.env.d1("DB")?;
    let require_nonce = crate::dpop_nonce_required(&ctx.env)?;
    if require_nonce
        && !crate::dpop::accepts_nonce(&db, crate::dpop::NonceScope::ResourceServer, proof.nonce())
            .await?
    {
        let nonce = crate::dpop::current_nonce(
            &db,
            crate::dpop::NonceScope::ResourceServer,
            &mut WorkersCryptoRandom,
        )
        .await?;
        return Ok(Some(crate::dpop_nonce_error_response(&nonce, true)?));
    }
    if let Err(failure) = crate::dpop::accept_identity_proof(
        &db,
        &proof,
        &random()?,
        require_nonce,
        crate::dpop::NonceScope::ResourceServer,
    )
    .await
    {
        if matches!(&failure, worker::Error::RustError(message) if message == "invalid_dpop_proof")
        {
            return Ok(Some(error(401, "invalid_dpop_proof")?));
        }
        return Err(failure);
    }
    Ok(None)
}
