//! Passport evidence is a source for the existing HAIP issuer, never a weaker issuer.
use super::*;

const REVIEW_STYLE: &str = "*{box-sizing:border-box}body{margin:0;padding:32px 18px;background:#f5f2f0;color:#252134;font:16px/1.7 system-ui,sans-serif}main{max-width:680px;margin:0 auto;padding:32px;border:1px solid #e1d7d8;border-top:5px solid #812747;border-radius:18px;background:#fff;box-shadow:0 18px 60px #48273912}h1{font:600 clamp(24px,5vw,32px)/1.4 Georgia,serif;letter-spacing:.03em;margin:0 0 24px}p{overflow-wrap:anywhere}dl{display:grid;grid-template-columns:1fr 1fr;gap:0 24px;padding:20px;background:#faf5f7;border-radius:12px}dt{font-size:13px;color:#705e6c;margin-top:12px}dd{margin:0 0 12px;font-weight:600;overflow-wrap:anywhere}dt:nth-of-type(1),dd:nth-of-type(1),dt:last-of-type,dd:last-of-type{grid-column:1/-1}dt:nth-of-type(2){grid-row:3}dd:nth-of-type(2){grid-row:4}dt:nth-of-type(3){grid-row:3;grid-column:2}dd:nth-of-type(3){grid-row:4;grid-column:2}dt:nth-of-type(4){grid-row:5}dd:nth-of-type(4){grid-row:6}dt:nth-of-type(5){grid-row:5;grid-column:2}dd:nth-of-type(5){grid-row:6;grid-column:2}form{display:grid;gap:12px;margin-top:28px}button{min-height:48px;padding:12px 18px;border:1px solid #812747;border-radius:10px;background:#812747;color:#fff;font:600 16px/1.5 system-ui,sans-serif;cursor:pointer}button[value=deny]{background:transparent;color:#812747}button:focus-visible{outline:3px solid #386fbe;outline-offset:3px}@media(max-width:380px){body{padding:16px 10px}main{padding:22px 16px}dl{padding:16px;gap:0 12px}}@media(prefers-color-scheme:dark){body{background:#17151c;color:#f3eaf0}main{background:#221d27;border-color:#443340;border-top-color:#e496b1}dl{background:#30242f}dt{color:#d7bdcc}button{background:#a44264;border-color:#d987a4}button[value=deny]{color:#f2b9ce}}";

pub(super) fn client_policy(ctx: &RouteContext<()>) -> worker::Result<String> {
    if wallet::haip(ctx) {
        wallet::client_policy_hash(ctx)
    } else {
        Ok(String::new())
    }
}
fn active(ctx: &RouteContext<()>) -> bool {
    enabled(ctx) && wallet::haip(ctx)
}

pub(in crate::identity) async fn authorize_get(
    req: &Request,
    ctx: &RouteContext<()>,
    request: &wallet::Authorization,
    par_hash: Option<&str>,
    client_policy: &str,
    client_name: &str,
) -> worker::Result<Response> {
    if !active(ctx) {
        return error(400, "invalid_scope");
    }
    let (Some(tx), Some(par), Some(jkt)) = (
        request.issuer_state.as_deref(),
        par_hash,
        request.dpop_jkt.as_deref(),
    ) else {
        return error(400, "invalid_request");
    };
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(req, &db).await? else {
        return error(401, "authentication_required");
    };
    let row = db.prepare("SELECT holder_json,projection_json FROM identity_passport_transaction WHERE tx_id=?1 AND haip=1 AND state='pending' AND expires_at>unixepoch() AND policy_hash=?2")
        .bind(&[js(tx),js(&policy(ctx)?.fingerprint())])?.first::<Value>(None).await?;
    let Some(row) = row else {
        return error(404, "transaction_unavailable");
    };
    let holder: PublicJwk =
        serde_json::from_str(row["holder_json"].as_str().ok_or_else(server_error)?)?;
    if holder.thumbprint().map_err(|_| server_error())? != jkt {
        return error(403, "wallet_binding_mismatch");
    }
    let csrf = random()?;
    let updated = db.prepare("UPDATE identity_passport_transaction SET account_id=?1,epoch=(SELECT epoch FROM account_security WHERE account_id=?1),session_hash=?2,csrf_hash=?3,client_id=?4,client_policy_hash=?5,client_binding=(SELECT client_binding FROM identity_wallet_par WHERE request_hash=?6),par_hash=?6,dpop_jkt=?7,redirect_uri=?8,wallet_state=?9,code_challenge=?10 WHERE tx_id=?11 AND haip=1 AND state='pending' AND expires_at>unixepoch() AND policy_hash=?12 AND (par_hash IS NULL OR par_hash=?6) AND (session_hash IS NULL OR (session_hash=?2 AND account_id=?1)) AND EXISTS(SELECT 1 FROM identity_wallet_par p WHERE p.request_hash=?6 AND p.used=0 AND p.expires_at>unixepoch() AND p.client_id=?4 AND p.client_policy_hash=?5 AND p.client_binding IS NOT NULL AND json_extract(p.request_json,'$.issuer_state')=?11 AND json_extract(p.request_json,'$.dpop_jkt')=?7)")
        .bind(&[js(&owner.account_id),js(&owner.secret_hash),js(&hash(&csrf)),js(&request.client_id),js(client_policy),js(par),js(jkt),js(&request.redirect_uri),request.state.as_deref().map(js).unwrap_or(JsValue::NULL),js(&request.code_challenge),js(tx),js(&policy(ctx)?.fingerprint())])?.run().await?;
    if updated.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
        return error(409, "transaction_unavailable");
    }
    let claims: Value =
        serde_json::from_str(row["projection_json"].as_str().ok_or_else(server_error)?)?;
    let escape = crate::i18n::html_escape;
    let mut fields = String::new();
    for (name, label) in [
        ("name_mrz", "氏名（MRZ表記）"),
        ("issuing_state", "発行国コード"),
        ("nationality", "国籍コード"),
        ("birth_date_mrz", "生年月日（YYMMDD）"),
        ("expiry_date_mrz", "旅券期限（YYMMDD）"),
        ("sex_mrz", "性別（MRZ表記）"),
    ] {
        fields.push_str(&format!(
            "<dt>{label}</dt><dd>{}</dd>",
            escape(claims[name].as_str().unwrap_or(""))
        ));
    }
    let html = format!(
        "<!doctype html><html lang=ja><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>旅券属性証明の発行</title><main><h1>旅券のMRZ属性をWalletへ発行</h1><p>アカウント: {}</p><p>認証したWallet: {} ({})</p><p>戻り先: {}</p><dl>{fields}<dt>Wallet連携鍵の識別子</dt><dd>{}</dd></dl><p>旅券のDG1・SODを受け取り、発行国の署名と失効情報を検証しました。原本には旅券番号・個人番号欄を含みますが、原本は保存せず、この6項目だけを証明します。審査期限は最長10分で、発行・拒否時または期限後に削除します。アカウント属性への永続的な紐付けは行いません。</p><p>日付はYYMMDDのままです。世紀・年齢・現在の旅券有効性・顔や現在の所持は証明しません。政府発行のデジタル旅券ではなく、Mikakiが発行する属性証明です。受取時にも原本を再検証します。有効期間が最長5分の証明書を、このWalletへ1件発行します。</p><form method=post action=/identity/issuer/authorize><input type=hidden name=grant value='{tx}'><input type=hidden name=document value='{tx}'><input type=hidden name=csrf value='{csrf}'><button name=decision value=approve>内容とWallet連携鍵を確認して発行を許可</button><button name=decision value=deny formnovalidate>拒否</button></form></main></html>",
        escape(&owner.account_id),
        escape(client_name),
        escape(&request.client_id),
        escape(&request.redirect_uri),
        escape(jkt)
    );
    let html = html.replacen(
        "<title>",
        &format!("<style>{REVIEW_STYLE}</style><title>"),
        1,
    );
    let style_hash =
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(REVIEW_STYLE.as_bytes()));
    Response::builder()
        .with_header("Cache-Control", "no-store")?
        .with_header("Referrer-Policy", "no-referrer")?
        .with_header("X-Content-Type-Options", "nosniff")?
        .with_header(
            "Content-Security-Policy",
            &format!("default-src 'none'; style-src 'sha256-{style_hash}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
        )?
        .from_html(html)
}

#[allow(clippy::too_many_arguments)]
pub(in crate::identity) async fn authorize_post(
    req: &Request,
    ctx: &RouteContext<()>,
    tx: &str,
    csrf: &str,
    decision: &str,
    document: Option<&str>,
    client_policy: &str,
) -> worker::Result<Option<Response>> {
    if !active(ctx) {
        return Ok(None);
    }
    let db = ctx.env.d1("DB")?;
    if db
        .prepare("SELECT tx_id FROM identity_passport_transaction WHERE tx_id=?1 AND haip=1")
        .bind(&[js(tx)])?
        .first::<Value>(None)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    if decision == "approve" && document != Some(tx) {
        return Ok(Some(error(400, "invalid_request")?));
    }
    let Some(owner) = owner(req, &db).await? else {
        return Ok(Some(error(401, "authentication_required")?));
    };
    let code = random()?;
    let row=db.prepare("UPDATE identity_passport_transaction SET state=?1,code_hash=?2,csrf_hash=NULL,expires_at=min(expires_at,unixepoch()+90) WHERE tx_id=?3 AND haip=1 AND state='pending' AND expires_at>unixepoch() AND csrf_hash=?4 AND session_hash=?5 AND account_id=?6 AND client_policy_hash=?7 AND policy_hash=?8 AND EXISTS(SELECT 1 FROM account_security a WHERE a.account_id=identity_passport_transaction.account_id AND a.active=1 AND a.epoch=identity_passport_transaction.epoch) RETURNING redirect_uri,wallet_state")
        .bind(&[js(if decision=="approve" {"offered"} else {"denied"}),if decision=="approve" {js(&hash(&code))} else {JsValue::NULL},js(tx),js(&hash(csrf)),js(&owner.secret_hash),js(&owner.account_id),js(client_policy),js(&policy(ctx)?.fingerprint())])?.first::<Value>(None).await?;
    let Some(row) = row else {
        return Ok(Some(error(409, "transaction_unavailable")?));
    };
    let mut callback = url::Url::parse(row["redirect_uri"].as_str().ok_or_else(server_error)?)
        .map_err(|_| server_error())?;
    callback.query_pairs_mut().append_pair(
        if decision == "approve" {
            "code"
        } else {
            "error"
        },
        if decision == "approve" {
            &code
        } else {
            "access_denied"
        },
    );
    if let Some(state) = row["wallet_state"].as_str() {
        callback.query_pairs_mut().append_pair("state", state);
    }
    callback.query_pairs_mut().append_pair("iss", &issuer(ctx)?);
    Ok(Some(
        Response::builder()
            .with_status(303)
            .with_header("Cache-Control", "no-store")?
            .with_header("Referrer-Policy", "no-referrer")?
            .with_header("Location", callback.as_str())?
            .empty(),
    ))
}

pub(in crate::identity) struct TokenBinding<'a> {
    pub code: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub pkce_hash: &'a str,
    pub client_policy: &'a str,
    pub client_binding: JsValue,
    pub dpop_jkt: Option<&'a str>,
    pub access: &'a str,
}
/// Invoked only after the common Token endpoint validates client authentication,
/// DPoP nonce/replay and PKCE syntax. The ledger binds their verified results.
pub(in crate::identity) async fn token(
    ctx: &RouteContext<()>,
    b: TokenBinding<'_>,
) -> worker::Result<Option<Response>> {
    if !active(ctx) {
        return Ok(None);
    }
    let db = ctx.env.d1("DB")?;
    if db.prepare("SELECT tx_id FROM identity_passport_transaction WHERE haip=1 AND (code_hash=?1 OR redeemed_code_hash=?1)").bind(&[js(&hash(b.code))])?.first::<Value>(None).await?.is_none() { return Ok(None); }
    let Some(jkt) = b.dpop_jkt else {
        return Ok(Some(error(400, "invalid_dpop_proof")?));
    };
    let policy_hash = policy(ctx)?.fingerprint();
    let row=db.prepare("UPDATE identity_passport_transaction SET state='token',access_hash=?1,redeemed_code_hash=code_hash,code_hash=NULL,token_expires_at=min(expires_at,unixepoch()+120) WHERE haip=1 AND code_hash=?2 AND state='offered' AND expires_at>unixepoch() AND client_id=?3 AND redirect_uri=?4 AND code_challenge=?5 AND client_policy_hash=?6 AND client_binding IS ?7 AND client_binding IS NOT NULL AND dpop_jkt=?8 AND policy_hash=?9 AND EXISTS(SELECT 1 FROM account_security a WHERE a.account_id=identity_passport_transaction.account_id AND a.active=1 AND a.epoch=identity_passport_transaction.epoch) RETURNING token_expires_at")
        .bind(&[js(&hash(b.access)),js(&hash(b.code)),js(b.client_id),js(b.redirect_uri),js(b.pkce_hash),js(b.client_policy),b.client_binding.clone(),js(jkt),js(&policy_hash)])?.first::<Value>(None).await?;
    let Some(row) = row else {
        // Authenticated code reuse revokes only the exact original Wallet/PKCE binding.
        db.prepare("UPDATE identity_passport_transaction SET state='denied' WHERE haip=1 AND redeemed_code_hash=?1 AND state='token' AND client_id=?2 AND redirect_uri=?3 AND code_challenge=?4 AND client_policy_hash=?5 AND client_binding IS ?6 AND dpop_jkt=?7 AND policy_hash=?8")
            .bind(&[js(&hash(b.code)),js(b.client_id),js(b.redirect_uri),js(b.pkce_hash),js(b.client_policy),b.client_binding,js(jkt),js(&policy_hash)])?.run().await?;
        return Ok(Some(error(400, "invalid_grant")?));
    };
    Ok(Some(response(
        json!({"access_token":b.access,"token_type":"DPoP","expires_in":row["token_expires_at"].as_u64().unwrap_or(0).saturating_sub(now()?),"scope":profile::CONFIGURATION}),
    )?))
}
