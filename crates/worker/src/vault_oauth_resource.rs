//! Explicit DPoP Vault audience. The owner Cookie never grants access here.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mikaki_oidc::CryptographicRandom;
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::{Request, Response, RouteContext};

use crate::{
    TokenBindingRow, WorkersCryptoRandom, configured_issuer, dpop, dpop_nonce_error_response,
    dpop_nonce_required, now_seconds, vault_attributes, vault_http,
};

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

fn unauthorized(code: &'static str) -> worker::Result<Response> {
    Response::builder()
        .with_status(401)
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .with_header(
            "WWW-Authenticate",
            &format!("DPoP error=\"{code}\", algs=\"ES256\""),
        )?
        .from_json(&ErrorBody { error: code })
}

pub async fn get(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    if !context
        .env
        .var("MIKAKI_NATIVE_VAULT_OAUTH")
        .ok()
        .is_some_and(|value| value.to_string() == "preview")
        || context.env.bucket("VAULT_BLOBS").is_err()
    {
        return vault_http::error(404, "not_found");
    }
    let Some(attribute) = context.param("attribute").map(String::as_str) else {
        return vault_http::error(404, "not_found");
    };
    if !matches!(attribute, "name" | "owner_note") {
        return vault_http::error(404, "not_found");
    }
    let issuer = configured_issuer(&context.env.var("MIKAKI_ISSUER")?.to_string())
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let endpoint = format!("{issuer}/vault-api/attributes/{attribute}");
    if request.url()?.to_string() != endpoint {
        return vault_http::error(400, "invalid_request");
    }
    let Some(header) = request.headers().get("authorization")? else {
        return unauthorized("invalid_token");
    };
    let Some((scheme, token)) = header.split_once(' ') else {
        return unauthorized("invalid_token");
    };
    if !scheme.eq_ignore_ascii_case("DPoP")
        || token.len() != 43
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return unauthorized("invalid_token");
    }
    let token_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    let db = context.env.d1("DB")?;
    let binding = db
        .prepare(
            "SELECT ti.dpop_jkt FROM token_issue ti \
             JOIN vault_oauth_token_context vt ON vt.access_hash=ti.access_hash \
             WHERE ti.access_hash=?1 AND ti.revoked=0 AND ti.access_expires_at>unixepoch() \
             AND vt.resource='https://mikaki.tossa.app/vault-api/' \
             AND vt.attribute_id=?2",
        )
        .bind(&[JsValue::from_str(&token_hash), JsValue::from_str(attribute)])?
        .first::<TokenBindingRow>(None)
        .await?;
    let Some(jkt) = binding.and_then(|row| row.dpop_jkt) else {
        return unauthorized("invalid_token");
    };
    let require_nonce = dpop_nonce_required(&context.env)?;
    let challenge = if require_nonce {
        Some(
            dpop::current_nonce(
                &db,
                dpop::NonceScope::ResourceServer,
                &mut WorkersCryptoRandom,
            )
            .await?,
        )
    } else {
        None
    };
    let Some(compact) = request.headers().get("dpop")? else {
        if let Some(nonce) = challenge.as_deref() {
            return dpop_nonce_error_response(nonce, true);
        }
        return unauthorized("invalid_dpop_proof");
    };
    let now = now_seconds().ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    let Ok(proof) = mikaki_oidc::verify_dpop_proof(
        &compact,
        "GET",
        &endpoint,
        mikaki_oidc::DpopTarget::Resource {
            access_token: token,
            thumbprint: &jkt,
        },
        now,
    ) else {
        return unauthorized("invalid_dpop_proof");
    };
    if require_nonce
        && !dpop::accepts_nonce(&db, dpop::NonceScope::ResourceServer, proof.nonce()).await?
    {
        return dpop_nonce_error_response(
            challenge
                .as_deref()
                .expect("required nonce has a challenge"),
            true,
        );
    }
    let mut receipt = [0u8; 32];
    WorkersCryptoRandom
        .fill(&mut receipt)
        .map_err(|_| worker::Error::RustError("server_error".into()))?;
    let Some(owner) = dpop::authorize_vault_resource(
        &db,
        &proof,
        &URL_SAFE_NO_PAD.encode(receipt),
        &token_hash,
        attribute,
        require_nonce,
    )
    .await?
    else {
        return unauthorized("invalid_token");
    };
    vault_attributes::read_ciphertext(&context.env, &db, &owner.account_id, attribute).await
}
