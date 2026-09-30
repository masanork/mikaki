//! Authenticated pushed authorization requests. The browser sees only an
//! opaque reference; the stored request is consumed with code issuance.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wasm_bindgen::JsValue;
use worker::d1::D1Database;

const PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
const TTL: u64 = 300;

#[derive(Deserialize)]
pub(super) struct PushedRequest {
    pub request_uri: String,
    pub request_query: String,
    pub client_revision: i64,
    pub key_id: String,
    pub key_revision: i64,
    pub dpop_jkt: Option<String>,
}

#[derive(Deserialize)]
struct Receipt {
    request_uri: String,
}

#[derive(Serialize)]
struct ParSuccess<'a> {
    request_uri: &'a str,
    expires_in: u64,
}

pub(super) fn required(env: &worker::Env) -> worker::Result<bool> {
    if super::fapi2_deployment(env)? {
        return Ok(true);
    }
    match env.var("MIKAKI_PAR_MODE") {
        Err(_) => Ok(false),
        Ok(value) if value.to_string() == "off" => Ok(false),
        Ok(value) if value.to_string() == "required" => Ok(true),
        _ => Err(worker::Error::RustError("invalid PAR mode".into())),
    }
}

fn error(code: &str, status: u16) -> worker::Result<worker::Response> {
    super::oauth_error_response(code, status, false)
}

fn form(body: &str, maximum: usize) -> Option<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(body.as_bytes()) {
        if values.len() >= maximum
            || !matches!(
                key.as_ref(),
                "client_id"
                    | "client_assertion_type"
                    | "client_assertion"
                    | "response_type"
                    | "scope"
                    | "redirect_uri"
                    | "state"
                    | "nonce"
                    | "code_challenge"
                    | "code_challenge_method"
                    | "dpop_jkt"
                    | "prompt"
                    | "max_age"
                    | "ui_locales"
                    | "response_mode"
            )
            || values
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return None;
        }
    }
    Some(values)
}

pub(super) async fn route(
    mut request: worker::Request,
    context: worker::RouteContext<()>,
) -> worker::Result<worker::Response> {
    if !required(&context.env)? {
        return worker::Response::error("not found", 404);
    }
    let db = context.env.d1("DB")?;
    let policy = super::WorkerRuntimePolicy::from_db(&db).await?;
    let issuer = super::configured_issuer(&context.env.var("MIKAKI_ISSUER")?.to_string())
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let endpoint = format!("{issuer}/par");
    if request.url()?.to_string() != endpoint {
        return error("invalid_request", 400);
    }
    let Some(content_type) = request.headers().get("content-type")? else {
        return error("invalid_request", 400);
    };
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return error("invalid_request", 400);
    }
    if request.headers().get("authorization")?.is_some() {
        return error("invalid_client", 401);
    }
    let body = super::read_bounded_body(&mut request, policy.form_body_bytes).await?;
    let Some(mut fields) = form(&body, policy.parameter_count()) else {
        return error("invalid_request", 400);
    };
    let (Some(client_id), Some(assertion_type), Some(compact), Some(redirect_uri)) = (
        fields.get("client_id"),
        fields.get("client_assertion_type"),
        fields.get("client_assertion"),
        fields.get("redirect_uri"),
    ) else {
        return error("invalid_request", 400);
    };
    if assertion_type != mikaki_oidc::PRIVATE_KEY_JWT_ASSERTION_TYPE {
        return error("invalid_client", 401);
    }
    let client_id = client_id.to_owned();
    let compact = compact.to_owned();
    let redirect_uri = redirect_uri.to_owned();
    let now =
        super::now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let proof = request
        .headers()
        .get("dpop")?
        .map(|value| {
            mikaki_oidc::verify_dpop_proof(
                &value,
                "POST",
                &endpoint,
                mikaki_oidc::DpopTarget::Token,
                now,
            )
            .map_err(|_| worker::Error::RustError("invalid_dpop_proof".into()))
        })
        .transpose();
    let proof = match proof {
        Ok(value) => value,
        Err(_) => return error("invalid_dpop_proof", 400),
    };
    if let Some(proof) = &proof
        && super::dpop_nonce_required(&context.env)?
    {
        let nonce = super::dpop::current_nonce(
            &db,
            super::dpop::NonceScope::AuthorizationServer,
            &mut super::WorkersCryptoRandom,
        )
        .await?;
        if !super::dpop::accepts_nonce(
            &db,
            super::dpop::NonceScope::AuthorizationServer,
            proof.nonce(),
        )
        .await?
        {
            return super::dpop_nonce_error_response(&nonce, false);
        }
    }
    let dpop_jkt = fields.remove("dpop_jkt");
    if let Some(jkt) = &dpop_jkt {
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(jkt) else {
            return error("invalid_request", 400);
        };
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != *jkt {
            return error("invalid_request", 400);
        }
    }
    if let (Some(proof), Some(jkt)) = (&proof, &dpop_jkt)
        && proof.thumbprint() != jkt
    {
        return error("invalid_request", 400);
    }
    let dpop_jkt = dpop_jkt.or_else(|| proof.as_ref().map(|value| value.thumbprint().to_owned()));
    let fapi = super::fapi2_deployment(&context.env)?;
    let candidate_audience = mikaki_oidc::client_assertion_audience(&compact, policy.jwt_bytes)
        .map_err(|_| worker::Error::RustError("invalid_client".into()));
    let audience = match candidate_audience {
        Ok(value)
            if value == issuer
                || (!fapi && (value == endpoint || value == format!("{issuer}/token"))) =>
        {
            value
        }
        _ => return error("invalid_client", 401),
    };
    let (assertion, reservation) = match super::verify_and_accept_client_assertion(
        &db,
        &client_id,
        &compact,
        &audience,
        &endpoint,
        fapi,
        now,
        &policy,
        &mut super::WorkersCryptoRandom,
    )
    .await
    {
        Ok(value) => value,
        Err(_) => return error("invalid_client", 401),
    };
    let registration = db
        .prepare(
            "SELECT 1 AS active FROM client_redirect_uri r \
        WHERE r.client_id=?1 AND r.redirect_uri=?2 AND r.active=1",
        )
        .bind(&[
            JsValue::from_str(&client_id),
            JsValue::from_str(&redirect_uri),
        ])?
        .first::<i64>(Some("active"))
        .await?;
    if registration.is_none() {
        return error("invalid_request", 400);
    }
    fields.remove("client_assertion_type");
    fields.remove("client_assertion");
    let Some(response_type) = fields.get("response_type") else {
        return error("invalid_request", 400);
    };
    let Some(scope) = fields.get("scope") else {
        return error("invalid_request", 400);
    };
    let fapi = super::fapi2_deployment(&context.env)?;
    let state = match fields.get("state") {
        Some(value) => value.clone(),
        None if fapi => String::new(),
        None => return error("invalid_request", 400),
    };
    let Some(challenge) = fields.get("code_challenge") else {
        return error("invalid_request", 400);
    };
    let Some(method) = fields.get("code_challenge_method") else {
        return error("invalid_request", 400);
    };
    let auth = mikaki_oidc::Authorization {
        client_id: client_id.clone(),
        redirect_uri: redirect_uri.clone(),
        response_type: response_type.clone(),
        scope: scope.clone(),
        state,
        nonce: fields.get("nonce").cloned(),
        code_challenge: challenge.clone(),
        code_challenge_method: method.clone(),
    };
    if (if fapi {
        auth.validate_for_fapi(
            &client_id,
            &redirect_uri,
            policy.state_bytes(),
            policy.nonce_bytes(),
        )
    } else {
        auth.validate(
            &client_id,
            &redirect_uri,
            policy.state_bytes(),
            policy.nonce_bytes(),
        )
    })
    .is_err()
        || fields
            .get("response_mode")
            .is_some_and(|value| value != "query")
        || fields
            .get("max_age")
            .is_some_and(|value| value.parse::<u64>().is_err())
        || fields.get("prompt").is_some_and(|value| {
            let parts = value.split_ascii_whitespace().collect::<Vec<_>>();
            parts.is_empty()
                || parts
                    .iter()
                    .any(|part| !["none", "login", "consent", "select_account"].contains(part))
                || (parts.contains(&"none") && parts.len() > 1)
        })
    {
        return error("invalid_request", 400);
    }
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(
            fields
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )
        .finish();
    if query.len() > policy.request_target_bytes() {
        return error("invalid_request", 400);
    }
    if let Some(proof) = &proof {
        let mut receipt = [0u8; 32];
        mikaki_oidc::CryptographicRandom::fill(&mut super::WorkersCryptoRandom, &mut receipt)
            .map_err(|_| worker::Error::RustError("server_error".into()))?;
        super::dpop::accept_token_proof(
            &db,
            proof,
            &URL_SAFE_NO_PAD.encode(receipt),
            super::dpop_nonce_required(&context.env)?,
        )
        .await?;
    }
    let mut bytes = [0u8; 32];
    mikaki_oidc::CryptographicRandom::fill(&mut super::WorkersCryptoRandom, &mut bytes)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let request_uri = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    bytes.fill(0);
    let expires = now
        .checked_add(TTL)
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let values = [
        JsValue::from_str(&request_uri),
        JsValue::from_str(&client_id),
        JsValue::from_str(&assertion.client_revision().to_string()),
        JsValue::from_str(assertion.key_id()),
        JsValue::from_str(&assertion.key_revision().to_string()),
        JsValue::from_str(&query),
        dpop_jkt
            .as_deref()
            .map(JsValue::from_str)
            .unwrap_or(JsValue::NULL),
        JsValue::from_str(&expires.to_string()),
        JsValue::from_str(&reservation),
        JsValue::from_str(&redirect_uri),
        JsValue::from_str(&endpoint),
    ];
    let results=db.batch(vec![
        db.prepare("DELETE FROM par_request WHERE expires_at<=CAST(strftime('%s','now') AS INTEGER)"),
        db.prepare("INSERT INTO par_request(request_uri,client_id,client_revision,key_id,key_revision,request_query,dpop_jkt,expires_at) \
            SELECT ?1,c.client_id,c.revision,k.kid,k.revision,?6,?7,?8 FROM client c \
            JOIN client_key k ON k.client_id=c.client_id AND k.kid=?4 \
            JOIN client_redirect_uri r ON r.client_id=c.client_id AND r.redirect_uri=?10 \
            JOIN client_auth_use au ON au.accepted_by=?9 \
            WHERE c.client_id=?2 AND c.active=1 AND c.auth_method='private_key_jwt' AND c.revision=?3 \
            AND k.active=1 AND k.revision=?5 AND r.active=1 \
            AND au.client_id=c.client_id AND au.method='private_key_jwt' AND au.endpoint=?11 \
            AND au.client_revision=?3 AND au.credential_revision=?5 \
            AND au.retain_until>CAST(strftime('%s','now') AS INTEGER) \
            AND CAST(?8 AS INTEGER)>CAST(strftime('%s','now') AS INTEGER) \
            AND (SELECT count(*) FROM par_request)<10000 RETURNING request_uri")
            .bind(&values)?,
    ]).await?;
    if !results[1]
        .results::<Receipt>()?
        .iter()
        .any(|row| row.request_uri == request_uri)
    {
        return error("invalid_request", 400);
    }
    worker::Response::builder()
        .with_status(201)
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .from_json(&ParSuccess {
            request_uri: &request_uri,
            expires_in: TTL,
        })
}

pub(super) async fn load(
    db: &D1Database,
    client_id: &str,
    request_uri: &str,
) -> worker::Result<Option<PushedRequest>> {
    if !request_uri.starts_with(PREFIX) || request_uri.len() != PREFIX.len() + 43 {
        return Ok(None);
    }
    db.prepare(
        "SELECT p.request_uri,p.request_query,p.client_revision,p.key_id,p.key_revision,p.dpop_jkt \
        FROM par_request p JOIN client c ON c.client_id=p.client_id \
        JOIN client_key k ON k.client_id=p.client_id AND k.kid=p.key_id \
        WHERE p.request_uri=?1 AND p.client_id=?2 AND p.consumed_by IS NULL \
        AND p.expires_at>CAST(strftime('%s','now') AS INTEGER) \
        AND c.active=1 AND c.revision=p.client_revision AND c.auth_method='private_key_jwt' \
        AND k.active=1 AND k.revision=p.key_revision",
    )
    .bind(&[JsValue::from_str(request_uri), JsValue::from_str(client_id)])?
    .first::<PushedRequest>(None)
    .await
}
