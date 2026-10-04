//! Explicit RP/field consent for linked static document data, separate from Vault claims.
use super::*;
use crate::vault_http::Owner;
use worker::D1Database;

pub(crate) const CLAIM: &str = "mikaki_linked_document";
const FIELDS: [(&str, &str); 5] = [
    ("name", "氏名"),
    ("address", "住所"),
    ("birthdate", "生年月日"),
    ("gender", "性別"),
    ("document_expiry_date", "身分証の有効期限"),
];
pub(crate) fn enabled(env: &worker::Env) -> bool {
    env.var("IDENTITY_USERINFO_ENABLED")
        .is_ok_and(|v| v.to_string() == "true")
        && env
            .var("IDENTITY_ENABLED")
            .is_ok_and(|v| v.to_string() == "true")
}

#[derive(Deserialize)]
struct Released {
    document_json: String,
    fields_json: String,
}
pub(crate) async fn userinfo(
    env: &worker::Env,
    db: &D1Database,
    token: &str,
) -> worker::Result<Option<Value>> {
    if !enabled(env) {
        return Ok(None);
    }
    let (trust, current_policy) = trust_policy(env)?;
    let row=db.prepare("SELECT d.document_json,r.fields_json FROM token_issue ti \
        JOIN authorization_code ac ON ac.code_hash=ti.code_hash \
        JOIN code_context cc ON cc.code_hash=ac.code_hash \
        JOIN valid_client_session v ON v.client_id=ac.client_id AND v.sid=ac.sid \
        JOIN client c ON c.client_id=v.client_id \
        JOIN app_connection g ON g.account_id=v.account_id AND g.client_id=v.client_id \
        JOIN account_security a ON a.account_id=v.account_id \
        JOIN identity_claim_release r ON r.account_id=v.account_id AND r.client_id=v.client_id \
        JOIN identity_document d ON d.document_id=r.document_id AND d.account_id=r.account_id \
        WHERE ti.access_hash=?1 AND ti.revoked=0 AND ti.access_expires_at>unixepoch() \
        AND cc.scope IN ('openid profile','profile openid') \
        AND c.active=1 AND c.revision=ac.client_revision AND c.revision=r.client_revision \
        AND g.active=1 AND g.grant_version=r.connection_grant_version \
        AND a.active=1 AND a.epoch=r.epoch AND a.epoch=d.epoch \
        AND r.active=1 AND r.expires_at>unixepoch() AND d.revoked=0 AND d.valid_until>unixepoch() AND d.policy_hash=?2 \
        AND NOT EXISTS(SELECT 1 FROM vault_oauth_token_context vt WHERE vt.access_hash=ti.access_hash)")
        .bind(&[js(token),js(&current_policy)])?.first::<Released>(None).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.document_json.len() > 8192 || row.fields_json.len() > 256 {
        return Err(server_error());
    }
    let document: VerifiedDocument =
        serde_json::from_str(&row.document_json).map_err(|_| server_error())?;
    let fields: Vec<String> = serde_json::from_str(&row.fields_json).map_err(|_| server_error())?;
    if fields.is_empty() || fields.len() > 5 {
        return Err(server_error());
    }
    let a = &document.attributes;
    let time = now()?;
    if !trust.iter().any(|k| {
        k.id == document.trusted_key_id
            && k.document_type == a.document_type
            && k.not_before <= time
            && time < k.not_after
    }) {
        return Ok(None);
    }
    if let Some(date) = a.expiry_date.as_deref() {
        if mikaki_identity::evidence::date_end(date).ok_or_else(server_error)? <= time {
            return Ok(None);
        }
    }

    let mut attributes = serde_json::Map::new();
    for field in fields {
        let value = match field.as_str() {
            "name" => Some(a.name.as_str()),
            "address" => Some(a.address.as_str()),
            "birthdate" => Some(a.birth_date.as_str()),
            "gender" => Some(a.gender.as_str()),
            "document_expiry_date" => a.expiry_date.as_deref(),
            _ => return Err(server_error()),
        };
        if attributes.contains_key(&field) {
            return Err(server_error());
        }
        if let Some(value) = value {
            attributes.insert(field, json!(value));
        }
    }
    Ok(Some(json!({"attributes":attributes,"evidence":{
        "document_type":a.document_type,"assurance":document.assurance,
        "attributes_source":document.attributes_source,"verified_at":document.verified_at,
        "live_possession_verified":false,"government_credential":false
    }})))
}

#[derive(Deserialize)]
struct Recipient {
    client_id: String,
    sector_identifier: String,
    revision: i64,
    grant_version: i64,
}
#[derive(Deserialize)]
struct Release {
    document_id: String,
    client_id: String,
    fields_json: String,
    expires_at: i64,
    version: i64,
    active: i64,
}
pub(super) struct Management {
    recipients: Vec<Recipient>,
    releases: Vec<Release>,
    secret: String,
    enabled: bool,
}
pub(super) async fn management(
    env: &worker::Env,
    db: &D1Database,
    owner: &Owner,
) -> worker::Result<Management> {
    let installed=db.prepare("SELECT 1 AS present FROM sqlite_master WHERE type='table' AND name='identity_claim_release'").first::<Value>(None).await?.is_some();
    if !installed {
        return Ok(Management {
            recipients: vec![],
            releases: vec![],
            secret: owner.secret_hash.clone(),
            enabled: false,
        });
    }
    let recipients = if enabled(env) {
        db.prepare("SELECT c.client_id,c.sector_identifier,c.revision,g.grant_version FROM client c \
            JOIN app_connection g ON g.client_id=c.client_id WHERE g.account_id=?1 AND g.active=1 AND c.active=1 ORDER BY c.client_id LIMIT 100")
            .bind(&[js(&owner.account_id)])?.all().await?.results::<Recipient>()?
    } else {
        vec![]
    };
    let releases=db.prepare("SELECT document_id,client_id,fields_json,expires_at,version,active FROM identity_claim_release WHERE account_id=?1 ORDER BY client_id LIMIT 100")
        .bind(&[js(&owner.account_id)])?.all().await?.results::<Release>()?;
    Ok(Management {
        recipients,
        releases,
        secret: owner.secret_hash.clone(),
        enabled: enabled(env),
    })
}
impl Management {
    pub(super) fn controls(&self, document: &str) -> worker::Result<String> {
        let escape = crate::i18n::html_escape;
        let csrf = hash(&format!("{}:identity-release:{document}", self.secret));
        let mut html = String::new();
        for release in self
            .releases
            .iter()
            .filter(|r| r.document_id == document && r.active == 1)
        {
            let recipient =
                serde_json::to_string(&(release.client_id.as_str(), 0, 0, release.version))
                    .map_err(|_| server_error())?;
            let fields: Vec<String> =
                serde_json::from_str(&release.fields_json).map_err(|_| server_error())?;
            let labels = fields
                .iter()
                .map(|field| {
                    FIELDS
                        .iter()
                        .find(|(f, _)| *f == field)
                        .map(|(_, label)| *label)
                        .ok_or_else(server_error)
                })
                .collect::<worker::Result<Vec<_>>>()?
                .join("・");
            let expires = js_sys::Date::new(&JsValue::from_f64(release.expires_at as f64 * 1000.0))
                .to_iso_string()
                .as_string()
                .ok_or_else(server_error)?;
            html.push_str(&format!("<p>公開許可: {} / 項目: {} / 期限: {}</p><form method=post action=/identity/release><input type=hidden name=document value='{document}'><input type=hidden name=csrf value='{csrf}'><input type=hidden name=recipient value='{}'><input type=hidden name=action value=revoke><button>この公開許可を取り消す</button></form>",escape(&release.client_id),escape(&labels),escape(&expires),escape(&recipient)));
        }
        if !self.enabled || self.recipients.is_empty() {
            return Ok(html);
        }
        html.push_str(&format!("<form method=post action=/identity/release><input type=hidden name=document value='{document}'><input type=hidden name=csrf value='{csrf}'><input type=hidden name=action value=grant><h3>アプリへの属性公開</h3><p>選んだアプリがprofileスコープでログインすると、チェックした属性をuserinfoで取得できます。許可は最長1時間です。同じアプリへの以前の許可を置き換えます。</p><label>公開先<select name=recipient required>"));
        for r in &self.recipients {
            let version = self
                .releases
                .iter()
                .find(|v| v.client_id == r.client_id)
                .map_or(0, |v| v.version);
            let value = serde_json::to_string(&(
                r.client_id.as_str(),
                r.revision,
                r.grant_version,
                version,
            ))
            .map_err(|_| server_error())?;
            html.push_str(&format!(
                "<option value='{}'>{} ({})</option>",
                escape(&value),
                escape(&r.client_id),
                escape(&r.sector_identifier)
            ));
        }
        html.push_str("</select></label><fieldset><legend>公開する項目を選択</legend>");
        for (field, label) in FIELDS {
            html.push_str(&format!(
                "<label><input type=checkbox name={field} value=on>{label}</label>"
            ));
        }
        html.push_str("</fieldset><button>選んだ属性の公開を許可</button></form>");
        Ok(html)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseForm {
    document: String,
    recipient: String,
    csrf: String,
    action: String,
    name: Option<String>,
    address: Option<String>,
    birthdate: Option<String>,
    gender: Option<String>,
    document_expiry_date: Option<String>,
}
pub(crate) async fn release_post(
    mut req: Request,
    ctx: RouteContext<()>,
) -> worker::Result<Response> {
    let root = issuer(&ctx)?
        .trim_end_matches("/identity/issuer")
        .to_string();
    if req.headers().get("origin")?.as_deref() != Some(&root) {
        return error(403, "invalid_origin");
    }
    let Some(body) = form::<ReleaseForm>(&mut req).await? else {
        return error(400, "invalid_request");
    };
    let Ok((client, revision, grant, version)) =
        serde_json::from_str::<(String, i64, i64, i64)>(&body.recipient)
    else {
        return error(400, "invalid_request");
    };
    if !valid_id(&body.document)
        || !valid_id(&body.csrf)
        || client.is_empty()
        || client.len() > 128
        || revision < 0
        || grant < 0
        || version < 0
        || version > 9007199254740990
        || revision > 9007199254740991
        || grant > 9007199254740991
    {
        return error(400, "invalid_request");
    }
    let db = ctx.env.d1("DB")?;
    let Some(owner) = owner(&req, &db).await? else {
        return error(401, "authentication_required");
    };
    use subtle::ConstantTimeEq;
    let expected = hash(&format!(
        "{}:identity-release:{}",
        owner.secret_hash, body.document
    ));
    if !bool::from(expected.as_bytes().ct_eq(body.csrf.as_bytes())) {
        return error(403, "invalid_request");
    }
    let values = [
        body.name,
        body.address,
        body.birthdate,
        body.gender,
        body.document_expiry_date,
    ];
    if values.iter().flatten().any(|v| v != "on") {
        return error(400, "invalid_request");
    }
    let fields: Vec<&str> = FIELDS
        .iter()
        .zip(&values)
        .filter(|(_, v)| v.is_some())
        .map(|((f, _), _)| *f)
        .collect();
    match body.action.as_str() {
        "revoke" if fields.is_empty() => {
            let result=db.prepare("UPDATE identity_claim_release SET active=0,fields_json='[]',version=version+1 WHERE account_id=?1 AND client_id=?2 AND document_id=?3 AND version=?4 AND active=1").bind(&[js(&owner.account_id),js(&client),js(&body.document),JsValue::from_f64(version as f64)])?.run().await?;
            if result.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
                return error(409, "consent_changed");
            }
        }
        "grant" if !fields.is_empty() => {
            if !enabled(&ctx.env) {
                return error(404, "not_found");
            }
            let (_, current_policy) = policy(&ctx)?;
            let fields = serde_json::to_string(&fields).map_err(|_| server_error())?;
            let result=db.prepare("INSERT INTO identity_claim_release(account_id,client_id,document_id,epoch,client_revision,connection_grant_version,fields_json,expires_at,version,active) \
                SELECT d.account_id,c.client_id,d.document_id,a.epoch,c.revision,g.grant_version,?4,min(d.valid_until,unixepoch()+3600),?9+1,1 \
                FROM identity_document d JOIN account_security a ON a.account_id=d.account_id \
                JOIN app_connection g ON g.account_id=d.account_id AND g.client_id=?2 JOIN client c ON c.client_id=g.client_id \
                WHERE d.account_id=?1 AND d.document_id=?3 AND d.revoked=0 AND d.valid_until>unixepoch() AND d.policy_hash=?8 \
                AND coalesce((SELECT version FROM identity_claim_release WHERE account_id=?1 AND client_id=?2),0)=?9 \
                AND a.active=1 AND a.epoch=d.epoch AND g.active=1 AND c.active=1 AND c.revision=?5 AND g.grant_version=?6 \
                AND EXISTS(SELECT 1 FROM sso_context sx JOIN sso_session ss ON ss.sso_id=sx.sso_id \
                    JOIN credential cr ON cr.credential_id=ss.credential_id AND cr.account_id=ss.account_id \
                    WHERE sx.secret_hash=?7 AND ss.account_id=d.account_id AND ss.epoch=a.epoch AND ss.revoked=0 AND ss.expires_at>unixepoch() AND cr.active=1) \
                ON CONFLICT(account_id,client_id) DO UPDATE SET document_id=excluded.document_id,epoch=excluded.epoch,client_revision=excluded.client_revision,connection_grant_version=excluded.connection_grant_version,fields_json=excluded.fields_json,expires_at=excluded.expires_at,version=excluded.version,active=1 WHERE identity_claim_release.version=?9")
                .bind(&[js(&owner.account_id),js(&client),js(&body.document),js(&fields),JsValue::from_f64(revision as f64),JsValue::from_f64(grant as f64),js(&owner.secret_hash),js(&current_policy),JsValue::from_f64(version as f64)])?.run().await?;
            if result.meta()?.and_then(|m| m.changes).unwrap_or(0) == 0 {
                return error(409, "consent_changed");
            }
        }
        _ => return error(400, "invalid_request"),
    }
    Ok(Response::builder()
        .with_status(303)
        .with_header("Cache-Control", "no-store")?
        .with_header("Location", "/identity")?
        .empty())
}
