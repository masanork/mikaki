//! Owner-facing review of a narrowly scoped native Vault read transaction.
//! The authorization endpoint is responsible for creating the transaction and
//! atomically consuming approval with code issuance; this module does neither.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::JsValue;
use worker::{Request, Response, RouteContext};

use crate::{
    authorization_error_response, browser_cookie, configured_issuer, i18n, read_bounded_body,
};

#[derive(Deserialize)]
struct ConsentRow {
    client_id: String,
    attribute_id: String,
    authorization_url: String,
    redirect_uri: String,
    state: String,
}

fn valid_tx(tx: &str) -> bool {
    tx.len() == 43
        && tx
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn unavailable() -> worker::Result<Response> {
    Ok(Response::builder()
        .with_status(404)
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .empty())
}

async fn pending(
    context: &RouteContext<()>,
    tx: &str,
    sso_secret_hash: &str,
) -> worker::Result<Option<ConsentRow>> {
    context
        .env
        .d1("DB")?
        .prepare(
            "SELECT vc.client_id,vc.attribute_id,vc.authorization_url,vc.redirect_uri,vc.state \
             FROM vault_oauth_consent vc \
             JOIN sso_context sx ON sx.sso_id=vc.sso_id AND sx.secret_hash=vc.sso_secret_hash \
             JOIN sso_session ss ON ss.sso_id=vc.sso_id AND ss.account_id=vc.account_id \
             JOIN account_security a ON a.account_id=vc.account_id \
             JOIN credential cr ON cr.credential_id=ss.credential_id AND cr.account_id=ss.account_id \
             JOIN client c ON c.client_id=vc.client_id \
             JOIN app_connection ac ON ac.account_id=vc.account_id AND ac.client_id=vc.client_id \
             WHERE vc.tx_id=?1 AND vc.sso_secret_hash=?2 AND vc.decision='pending' \
             AND vc.expires_at>unixepoch() AND ss.revoked=0 AND ss.expires_at>unixepoch() \
             AND a.active=1 AND a.epoch=ss.epoch AND cr.active=1 AND c.active=1 \
             AND ac.active=1 \
             AND c.client_type='native' AND c.auth_method='none' \
             AND c.revision=vc.client_revision",
        )
        .bind(&[JsValue::from_str(tx), JsValue::from_str(sso_secret_hash)])?
        .first::<ConsentRow>(None)
        .await
}

fn sso_hash(request: &Request) -> worker::Result<Option<String>> {
    Ok(browser_cookie(request, "__Host-op-sso")?
        .map(|secret| URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))))
}

pub async fn get(request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    let url = request.url()?;
    let query = url.query_pairs().collect::<Vec<_>>();
    let [(key, tx)] = query.as_slice() else {
        return unavailable();
    };
    if key != "tx" || !valid_tx(tx) {
        return unavailable();
    }
    let Some(hash) = sso_hash(&request)? else {
        return unavailable();
    };
    let Some(row) = pending(&context, tx, &hash).await? else {
        return unavailable();
    };
    let locale = i18n::select(&request, None)?;
    let (title, description, approve, deny, attribute) = if locale == "en" {
        (
            "Allow encrypted Vault read?",
            "This client can read the selected encrypted record and its owner envelope. This does not unlock or decrypt the record.",
            "Allow this read",
            "Deny",
            if row.attribute_id == "name" {
                "Name"
            } else {
                "Owner note"
            },
        )
    } else {
        (
            "暗号化されたVaultデータの読取を許可しますか",
            "このクライアントは選択した暗号文とowner envelopeを取得できます。復号や鍵の利用は許可されません。",
            "この読取を許可",
            "拒否",
            if row.attribute_id == "name" {
                "名前"
            } else {
                "オーナーノート"
            },
        )
    };
    let html = format!(
        "<!doctype html><html lang=\"{locale}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{title}</title></head><body><main><h1>{title}</h1><p>{description}</p><dl><dt>Client ID</dt><dd>{}</dd><dt>Callback</dt><dd>{}</dd><dt>Attribute</dt><dd>{attribute}</dd><dt>Operation</dt><dd>read_ciphertext</dd></dl><form method=\"post\" action=\"/vault/oauth/consent\"><input type=\"hidden\" name=\"tx\" value=\"{}\"><button type=\"submit\" name=\"decision\" value=\"approve\">{approve}</button><button type=\"submit\" name=\"decision\" value=\"deny\">{deny}</button></form></main></body></html>",
        i18n::html_escape(&row.client_id),
        i18n::html_escape(&row.redirect_uri),
        i18n::html_escape(tx),
    );
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Pragma", "no-cache")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header(
            "Content-Security-Policy",
            "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )?
        .with_header("X-Content-Type-Options", "nosniff")?
        .from_html(html)
}

pub async fn post(mut request: Request, context: RouteContext<()>) -> worker::Result<Response> {
    let issuer = configured_issuer(&context.env.var("MIKAKI_ISSUER")?.to_string())
        .ok_or_else(|| worker::Error::RustError("server_error".into()))?;
    if request.headers().get("origin")?.as_deref() != Some(&issuer)
        || request
            .headers()
            .get("content-type")?
            .as_deref()
            .and_then(|value| value.split(';').next())
            .is_none_or(|value| {
                !value
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
    {
        return unavailable();
    }
    let Some(hash) = sso_hash(&request)? else {
        return unavailable();
    };
    let body = read_bounded_body(&mut request, 1024).await?;
    let fields = url::form_urlencoded::parse(body.as_bytes()).collect::<Vec<_>>();
    let [(tx_key, tx), (decision_key, decision)] = fields.as_slice() else {
        return unavailable();
    };
    if tx_key != "tx"
        || decision_key != "decision"
        || !valid_tx(tx)
        || !matches!(decision.as_ref(), "approve" | "deny")
    {
        return unavailable();
    }
    let Some(row) = pending(&context, tx, &hash).await? else {
        return unavailable();
    };
    let continuation = if decision == "approve" {
        let mut target = url::Url::parse(&row.authorization_url)
            .map_err(|_| worker::Error::RustError("invalid consent continuation".into()))?;
        if target.origin().ascii_serialization() != issuer
            || target.path() != "/authorize"
            || target.fragment().is_some()
            || target.query_pairs().any(|(key, _)| key == "vault_consent")
        {
            return unavailable();
        }
        target.query_pairs_mut().append_pair("vault_consent", tx);
        Some(target)
    } else {
        None
    };
    let result = context
        .env
        .d1("DB")?
        .prepare(
            "UPDATE vault_oauth_consent SET decision=?3 \
             WHERE tx_id=?1 AND sso_secret_hash=?2 AND decision='pending' \
             AND expires_at>unixepoch()",
        )
        .bind(&[
            JsValue::from_str(tx),
            JsValue::from_str(&hash),
            JsValue::from_str(if decision == "approve" {
                "approved"
            } else {
                "denied"
            }),
        ])?
        .run()
        .await;
    if result
        .ok()
        .and_then(|value| value.meta().ok().flatten())
        .and_then(|meta| meta.changes)
        != Some(1)
    {
        return unavailable();
    }
    if decision == "deny" {
        return authorization_error_response(
            &row.redirect_uri,
            Some(&row.state),
            &issuer,
            "access_denied",
        );
    }
    let target = continuation.expect("approved continuation checked");
    Ok(Response::builder()
        .with_status(303)
        .with_header("Location", target.as_str())?
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .empty())
}
