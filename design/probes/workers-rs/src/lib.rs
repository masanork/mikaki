use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mikaki_oidc::Authorization;
use mikaki_worker::WorkersCryptoRandom;
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Crypto, CryptoKey};
use worker::{D1SessionConstraint, Env, Request, Response, Result, RouteContext, Router, event};

#[derive(Deserialize)]
struct CountRow {
    count: u32,
}

#[derive(Serialize)]
struct AtomicityReport {
    batch_rejected: bool,
    rows_after_failure: u32,
    first_primary_value: u32,
}

#[derive(Serialize)]
struct ExchangeReport {
    accepted: bool,
}

#[derive(Serialize)]
struct SignedJws {
    token: String,
    jwk: String,
}

#[derive(Deserialize)]
struct RsaProbeKeys {
    private: String,
    public: String,
}

#[derive(Serialize)]
struct CodeReport {
    code: String,
    digest: String,
    expires_at: u64,
}

async fn issue_code(_req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    let challenge = mikaki_oidc::pkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        .ok_or_else(|| worker::Error::RustError("probe PKCE setup failed".into()))?;
    let authorization = Authorization {
        client_id: "probe-client".into(),
        redirect_uri: "https://rp.example/callback".into(),
        response_type: "code".into(),
        scope: "openid".into(),
        state: "probe-state".into(),
        nonce: "probe-nonce".into(),
        code_challenge: challenge,
        code_challenge_method: "S256".into(),
    }
    .validate("probe-client", "https://rp.example/callback", 256, 256)
    .map_err(|_| worker::Error::RustError("probe authorization invalid".into()))?;
    let prepared = authorization
        .prepare_code(&mut WorkersCryptoRandom, 1_000, 60, 1_050)
        .map_err(|_| worker::Error::RustError("probe code generation failed".into()))?;
    let (_, code, digest, expires_at) = prepared.into_parts();
    Response::from_json(&CodeReport {
        code: code.into_string(),
        digest: digest.as_base64url().into(),
        expires_at,
    })
}

fn database(ctx: &RouteContext<()>) -> Result<worker::d1::D1Database> {
    ctx.env.d1("DB")
}

async fn setup(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let db = database(&ctx)?;
    db.exec(
        "CREATE TABLE IF NOT EXISTS rollback_probe (id TEXT PRIMARY KEY);
         CREATE TABLE IF NOT EXISTS exchange_state (id INTEGER PRIMARY KEY, consumed INTEGER NOT NULL CHECK(consumed IN (0, 1)));
         CREATE TABLE IF NOT EXISTS exchange_winner (operation_id TEXT PRIMARY KEY);
         DELETE FROM rollback_probe;
         DELETE FROM exchange_winner;
         INSERT OR IGNORE INTO exchange_state VALUES (1, 0);
         UPDATE exchange_state SET consumed = 0 WHERE id = 1;",
    )
    .await?;
    Response::ok("ready")
}

async fn atomicity(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let db = database(&ctx)?;
    let batch_rejected = db
        .batch(vec![
            db.prepare("INSERT INTO rollback_probe VALUES ('same')"),
            db.prepare("INSERT INTO rollback_probe VALUES ('same')"),
        ])
        .await
        .is_err();

    let primary = db.with_session_constraint(D1SessionConstraint::FirstPrimary)?;
    let rows_after_failure = primary
        .prepare("SELECT COUNT(*) AS count FROM rollback_probe")
        .first::<CountRow>(None)
        .await?
        .map(|row| row.count)
        .unwrap_or(u32::MAX);
    let first_primary_value = primary
        .prepare("SELECT 1 AS count")
        .first::<CountRow>(None)
        .await?
        .map(|row| row.count)
        .unwrap_or_default();

    Response::from_json(&AtomicityReport {
        batch_rejected,
        rows_after_failure,
        first_primary_value,
    })
}

async fn exchange(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let db = database(&ctx)?;
    let operation_id = ctx
        .param("operation")
        .map(String::as_str)
        .unwrap_or("missing");
    let statements = vec![
        db.prepare("UPDATE exchange_state SET consumed = 1 WHERE id = 1 AND consumed = 0"),
        db.prepare("INSERT INTO exchange_winner(operation_id) SELECT ?1 WHERE changes() = 1")
            .bind(&[JsValue::from_str(operation_id)])?,
    ];
    let result = db.batch(statements).await?;
    let accepted = result
        .get(1)
        .and_then(|insert| insert.meta().ok().flatten())
        .and_then(|meta| meta.changes)
        .unwrap_or_default()
        > 0;
    Response::from_json(&ExchangeReport { accepted })
}

async fn sign(_req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    let global = js_sys::global();
    let crypto = js_sys::Reflect::get(&global, &"crypto".into())?
        .dyn_into::<Crypto>()
        .map_err(|_| worker::Error::RustError("crypto is unavailable".into()))?;
    let subtle = crypto.subtle();
    let generate_algorithm = js_sys::Object::new();
    js_sys::Reflect::set(
        &generate_algorithm,
        &JsValue::from_str("name"),
        &JsValue::from_str("ECDSA"),
    )?;
    js_sys::Reflect::set(
        &generate_algorithm,
        &JsValue::from_str("namedCurve"),
        &JsValue::from_str("P-256"),
    )?;
    let usages = js_sys::Array::new();
    usages.push(&JsValue::from_str("sign"));
    let pair = JsFuture::from(subtle.generate_key_with_object(
        &generate_algorithm,
        true,
        usages.as_ref(),
    )?)
    .await?;
    let private_key = js_sys::Reflect::get(&pair, &"privateKey".into())?
        .dyn_into::<CryptoKey>()
        .map_err(|_| worker::Error::RustError("private key unavailable".into()))?;
    let public_key = js_sys::Reflect::get(&pair, &"publicKey".into())?
        .dyn_into::<CryptoKey>()
        .map_err(|_| worker::Error::RustError("public key unavailable".into()))?;

    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "alg": "ES256",
            "kid": "workerd-rust-probe",
            "typ": "JWT"
        }))
        .map_err(|_| worker::Error::RustError("header serialization failed".into()))?,
    );
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({ "sub": "workers-rs-async-signer" }))
            .map_err(|_| worker::Error::RustError("payload serialization failed".into()))?,
    );
    let signing_input = format!("{protected}.{payload}");
    let signing_algorithm = js_sys::Object::new();
    js_sys::Reflect::set(
        &signing_algorithm,
        &JsValue::from_str("name"),
        &JsValue::from_str("ECDSA"),
    )?;
    js_sys::Reflect::set(
        &signing_algorithm,
        &JsValue::from_str("hash"),
        &JsValue::from_str("SHA-256"),
    )?;
    let signature = JsFuture::from(subtle.sign_with_object_and_u8_array(
        &signing_algorithm,
        &private_key,
        signing_input.as_bytes(),
    )?)
    .await?;
    let signature = js_sys::Uint8Array::new(&signature).to_vec();
    let public_jwk = JsFuture::from(subtle.export_key("jwk", &public_key)?).await?;
    let jwk = js_sys::JSON::stringify(&public_jwk)?
        .as_string()
        .ok_or_else(|| worker::Error::RustError("public JWK serialization failed".into()))?;

    Response::from_json(&SignedJws {
        token: format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)),
        jwk,
    })
}

async fn sign_rs256(mut req: Request, _ctx: RouteContext<()>) -> Result<Response> {
    let body = req.text().await?;
    let keys: RsaProbeKeys = serde_json::from_str(&body)
        .map_err(|_| worker::Error::RustError("RSA probe keys are invalid".into()))?;
    let crypto = js_sys::Reflect::get(&js_sys::global(), &"crypto".into())?
        .dyn_into::<Crypto>()
        .map_err(|_| worker::Error::RustError("crypto is unavailable".into()))?;
    let subtle = crypto.subtle();
    let usages = js_sys::Array::new();
    usages.push(&JsValue::from_str("sign"));
    let key = mikaki_oidc::RsaPrivateTokenKey::from_private_jwk(&keys.private)
        .map_err(|_| worker::Error::RustError("RSA JWK validation failed".into()))?;
    let canonical_public_jwk = mikaki_oidc::P256TokenSigner::canonical_public_jwk(&keys.public)
        .ok_or_else(|| worker::Error::RustError("RSA public JWK validation failed".into()))?;
    if !key.matches_public_jwk(&canonical_public_jwk) {
        return Err(worker::Error::RustError("RSA key pair mismatch".into()));
    }
    let private_jwk = js_sys::JSON::parse(
        &key.webcrypto_private_jwk_json()
            .map_err(|_| worker::Error::RustError("RSA JWK serialization failed".into()))?,
    )?
    .dyn_into::<js_sys::Object>()
    .map_err(|_| worker::Error::RustError("RSA private JWK import failed".into()))?;
    let import_algorithm = js_sys::JSON::parse(
        r#"{"name":"RSASSA-PKCS1-v1_5","hash":{"name":"SHA-256"}}"#,
    )?
    .dyn_into::<js_sys::Object>()
    .map_err(|_| worker::Error::RustError("RSA import algorithm setup failed".into()))?;
    let imported = JsFuture::from(subtle.import_key_with_object(
        "jwk",
        &private_jwk,
        &import_algorithm,
        false,
        usages.as_ref(),
    )?)
    .await?
    .dyn_into::<CryptoKey>()
    .map_err(|_| worker::Error::RustError("non-extractable RSA key import failed".into()))?;

    let input = mikaki_oidc::IdTokenSigningInput::new(
        "RS256",
        key.kid(),
        "https://issuer.example",
        "probe-subject",
        "probe-client",
        "probe-session",
        "probe-nonce",
        1_000,
        1_001,
        1_061,
    )
    .map_err(|_| worker::Error::RustError("RSA JWS input validation failed".into()))?;
    let signature = JsFuture::from(subtle.sign_with_str_and_u8_array(
        "RSASSA-PKCS1-v1_5",
        &imported,
        input.as_bytes(),
    )?)
    .await?;
    let signature = js_sys::Uint8Array::new(&signature).to_vec();
    if signature.len() != key.modulus_bytes() {
        return Err(worker::Error::RustError("RSA signature length mismatch".into()));
    }
    let token = input
        .finish(&signature)
        .map_err(|_| worker::Error::RustError("RSA JWS finalization failed".into()))?;
    Response::from_json(&SignedJws {
        token,
        jwk: canonical_public_jwk,
    })
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    Router::with_data(())
        .post_async("/setup", setup)
        .get_async("/atomicity", atomicity)
        .post_async("/exchange/:operation", exchange)
        .get_async("/code", issue_code)
        .get_async("/sign", sign)
        .post_async("/sign-rs256", sign_rs256)
        .run(req, env)
        .await
}
