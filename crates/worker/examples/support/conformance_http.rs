use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64},
};
use rusqlite::{Connection, OptionalExtension, params};
use sakimori_auth::Ceremony;
use sakimori_webauthn::{self as webauthn, Metadata};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tiny_http::{Header, Method, Request, Response, Server};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn check(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("invalid request".into())
    }
}
fn string(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| "missing string".into())
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}
fn timed<T>(ms: &mut f64, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let result = f();
    *ms += start.elapsed().as_secs_f64() * 1000.0;
    result
}
#[derive(Default)]
struct Timing {
    db: f64,
    metadata: f64,
    verify: f64,
}
struct Transaction {
    challenge: String,
    user: Option<Value>,
    expires: u64,
    registration: bool,
    uv: String,
    allowed: Vec<String>,
}
struct State {
    db: Connection,
    random: File,
    entries: Vec<Metadata>,
    transactions: HashMap<String, Transaction>,
    port: u16,
}
impl State {
    fn token(&mut self) -> Result<String> {
        let mut bytes = [0u8; 32];
        self.random.read_exact(&mut bytes)?;
        Ok(B64.encode(bytes))
    }
    fn options(
        &mut self,
        data: &Value,
        registration: bool,
        t: &mut Timing,
    ) -> Result<(Value, String)> {
        self.transactions.retain(|_, tx| tx.expires > now());
        check(self.transactions.len() < 1000)?;
        let username = data["username"].as_str().filter(|s| !s.is_empty());
        check(!registration || username.is_some())?;
        let mut user = if let Some(name) = username {
            timed(&mut t.db, || {
                self.db
                    .query_row("SELECT data FROM users WHERE name=?1", [name], |r| {
                        r.get::<_, String>(0)
                    })
                    .optional()
            })?
            .map(|s| serde_json::from_str::<Value>(&s))
            .transpose()?
        } else {
            None
        };
        if user.is_none() && registration {
            let count: i64 = timed(&mut t.db, || {
                self.db
                    .query_row("SELECT count(*) FROM users", [], |r| r.get(0))
            })?;
            check(count < 1000)?;
            user = Some(json!({"id": self.token()?, "name": username,
                "displayName": data["displayName"].as_str().filter(|s| !s.is_empty()).or(username)}));
        }
        check(registration || username.is_none() || user.is_some())?;
        let allowed = timed(&mut t.db, || -> Result<Vec<String>> {
            let mut stmt = self
                .db
                .prepare_cached("SELECT id FROM credentials WHERE user_id=?1 ORDER BY rowid")?;
            Ok(stmt
                .query_map([user.as_ref().and_then(|u| u["id"].as_str())], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?)
        })?;
        let selection = &data["authenticatorSelection"];
        let uv = if registration {
            &selection["userVerification"]
        } else {
            &data["userVerification"]
        };
        let uv = uv.as_str().unwrap_or("preferred");
        check(["required", "preferred", "discouraged"].contains(&uv))?;
        let resident = selection["residentKey"].as_str().unwrap_or(
            if selection["requireResidentKey"] == true {
                "required"
            } else {
                "discouraged"
            },
        );
        check(["required", "preferred", "discouraged"].contains(&resident))?;
        let challenge = self.token()?;
        let id = self.token()?;
        let list: Vec<_> = allowed
            .iter()
            .map(|id| json!({"type":"public-key", "id":id}))
            .collect();
        let mut output = json!({"status":"ok", "errorMessage":"", "challenge": challenge,
            "timeout":120000, "extensions": data.get("extensions").cloned().unwrap_or(json!({}))});
        if registration {
            output.as_object_mut().unwrap().extend(json!({
                "rp":{"id":"localhost", "name":"sakimori conformance"}, "user":user,
                "pubKeyCredParams": ([-7,-8,-257,-65535].map(|alg|json!({"type":"public-key", "alg":alg}))),
                "excludeCredentials":list, "attestation":data["attestation"].as_str().unwrap_or("none"),
                "authenticatorSelection":{"userVerification":uv,"residentKey":resident,"requireResidentKey":resident=="required"}
            }).as_object().unwrap().clone());
        } else {
            output.as_object_mut().unwrap().extend(
                json!({"rpId":"localhost", "allowCredentials":list,"userVerification":uv})
                    .as_object()
                    .unwrap()
                    .clone(),
            );
        }
        self.transactions.insert(
            id.clone(),
            Transaction {
                challenge,
                user,
                expires: now() + 120,
                registration,
                uv: uv.into(),
                allowed,
            },
        );
        Ok((output, id))
    }
    fn result(
        &mut self,
        data: &Value,
        registration: bool,
        id: &str,
        t: &mut Timing,
    ) -> Result<Value> {
        // Serial request processing: consumption, verification and commit cannot interleave.
        let tx = self.transactions.remove(id).ok_or("missing ceremony")?;
        check(tx.expires > now() && tx.registration == registration)?;
        check(data["type"] == "public-key")?;
        let credential_id = string(&data["id"])?;
        check(data.get("rawId").is_none_or(|raw| raw == credential_id))?;
        let stored = timed(&mut t.db, || {
            self.db
                .query_row(
                    "SELECT data FROM credentials WHERE id=?1",
                    [credential_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()
        })?;
        let mut stored = stored
            .map(|s| serde_json::from_str::<Value>(&s))
            .transpose()?;
        if !registration {
            let c = stored.as_ref().ok_or("unknown credential")?;
            check(tx.user.as_ref().is_none_or(|u| c["user_handle"] == u["id"]))?;
        }
        let r = &data["response"];
        let client_data = string(&r["clientDataJSON"])?;
        let selected = if registration {
            timed(&mut t.metadata, || -> Result<Vec<Value>> {
                let hint = webauthn::attestation_hint(string(&r["attestationObject"])?)
                    .map_err(|_| "invalid attestation")?;
                self.entries
                    .iter()
                    .filter(|e| e.aaguid == hint || e.key_ids.contains(&hint))
                    .map(|e| Ok(serde_json::to_value(e)?))
                    .collect()
            })?
        } else {
            vec![]
        };
        let ceremony: Ceremony = serde_json::from_value(json!({
            "purpose":if registration {"register"} else {"authenticate"}, "browser_hash":id,
            "expires_at":tx.expires,"failures":0,"consumed":false,
            "context":{"challenge":tx.challenge,"origin":format!("http://localhost:{}",self.port),
                "rp_id":"localhost","max_bytes":65536,"max_depth":8,"user_verification":tx.uv,
                "algorithms":[-7,-8,-257,-65535],"attestation":{"now":now(),"entries":selected},
                "authentication": if let Some(user) = tx.user.as_ref().filter(|_| !registration) {
                    json!({"mode":"identified","user_handle":user["id"],"allowed_credentials":tx.allowed})
                } else {json!({"mode":"discoverable"})}}
        }))?;
        let proof = if registration {
            let response = webauthn::Registration {
                id: credential_id.into(),
                client_data: client_data.into(),
                attestation: string(&r["attestationObject"])?.into(),
            };
            serde_json::to_value(
                timed(&mut t.verify, || ceremony.register(id, now(), 5, response))
                    .map_err(|_| "verification failed")?,
            )?
        } else {
            let credential = serde_json::from_value(stored.as_ref().unwrap().clone())?;
            let response = webauthn::Assertion {
                id: credential_id.into(),
                client_data: client_data.into(),
                authenticator_data: string(&r["authenticatorData"])?.into(),
                signature: string(&r["signature"])?.into(),
                user_handle: if r["userHandle"].is_null() {
                    None
                } else {
                    Some(string(&r["userHandle"])?.into())
                },
            };
            serde_json::to_value(
                timed(&mut t.verify, || {
                    ceremony.authenticate(id, now(), 5, &credential, response)
                })
                .map_err(|_| "verification failed")?,
            )?
        };
        timed(&mut t.db, || -> Result<()> {
            if registration {
                let user = tx.user.as_ref().ok_or("missing user")?;
                let mut credential = proof;
                credential["user_handle"] = user["id"].clone();
                let dbtx = self.db.transaction()?;
                let count: i64 =
                    dbtx.query_row("SELECT count(*) FROM credentials", [], |r| r.get(0))?;
                check(count < 1000)?;
                let existing: Option<String> = dbtx
                    .query_row(
                        "SELECT data FROM users WHERE name=?1",
                        [string(&user["name"])?],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(existing) = existing {
                    check(serde_json::from_str::<Value>(&existing)?["id"] == user["id"])?;
                } else {
                    dbtx.execute(
                        "INSERT INTO users(name,data) VALUES(?1,?2)",
                        params![string(&user["name"])?, user.to_string()],
                    )?;
                }
                // Unique key rejects duplicate registration; user write rolls back on failure.
                dbtx.execute(
                    "INSERT INTO credentials(id,user_id,data) VALUES(?1,?2,?3)",
                    params![credential_id, string(&user["id"])?, credential.to_string()],
                )?;
                dbtx.commit()?;
            } else {
                let credential = stored.as_mut().unwrap();
                credential
                    .as_object_mut()
                    .unwrap()
                    .extend(proof.as_object().unwrap().clone());
                check(
                    self.db.execute(
                        "UPDATE credentials SET data=?2 WHERE id=?1",
                        params![credential_id, credential.to_string()],
                    )? == 1,
                )?;
            }
            Ok(())
        })?;
        Ok(json!({"status":"ok","errorMessage":""}))
    }
    fn handle(&mut self, req: &mut Request, t: &mut Timing) -> Result<(Value, Option<String>)> {
        check(req.method() == &Method::Post)?;
        check(header(req, "Host") == Some(format!("localhost:{}", self.port).as_str()))?;
        check(req.body_length().is_none_or(|n| n <= 65536))?;
        let mut body = String::new();
        req.as_reader().take(65537).read_to_string(&mut body)?;
        webauthn::strict_json(&body, 65536, 16).map_err(|_| "invalid JSON")?;
        let data: Value = serde_json::from_str(&body)?;
        let registration = req.url().starts_with("/attestation/");
        let cookie_name = if registration {
            "fido2_reg_session"
        } else {
            "fido2_auth_session"
        };
        match req.url() {
            "/attestation/options" | "/assertion/options" => {
                let (output, id) = self.options(&data, registration, t)?;
                Ok((
                    output,
                    Some(format!(
                        "{cookie_name}={id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=120"
                    )),
                ))
            }
            "/attestation/result" | "/assertion/result" => {
                let id = header(req, "Cookie")
                    .unwrap_or("")
                    .split(';')
                    .filter_map(|s| s.trim().split_once('='))
                    .find(|(name, _)| *name == cookie_name)
                    .map(|(_, id)| id)
                    .ok_or("missing cookie")?;
                Ok((self.result(&data, registration, id, t)?, None))
            }
            _ => Err("unknown route".into()),
        }
    }
}
fn header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}
fn metadata() -> Result<Vec<Metadata>> {
    let mut entries = Vec::new();
    let mut files = fs::read_dir("target/fido-metadata")?.collect::<std::io::Result<Vec<_>>>()?;
    files.sort_by_key(|f| f.file_name());
    for file in files
        .into_iter()
        .filter(|f| f.path().extension().is_some_and(|e| e == "json"))
    {
        let m: Value = serde_json::from_reader(File::open(file.path())?)?;
        let aaguid = m["aaguid"].as_str().unwrap_or("").replace('-', "");
        let bytes = (0..aaguid.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&aaguid[i..i + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let roots = m["attestationRootCertificates"]
            .as_array()
            .ok_or("metadata roots")?
            .iter()
            .map(|r| Ok(B64.encode(STANDARD.decode(string(r)?)?)))
            .collect::<Result<Vec<_>>>()?;
        entries.push(Metadata {
            aaguid: B64.encode(bytes),
            roots,
            key_ids: serde_json::from_value(
                m.get("attestationCertificateKeyIdentifiers")
                    .cloned()
                    .unwrap_or(json!([])),
            )?,
            types: serde_json::from_value(m["attestationTypes"].clone())?,
            allowed: true,
            authenticator_version: None,
            status_reports: vec![],
            time_of_last_status_change: None,
        });
    }
    let mut files = fs::read_dir("target/fido-mds")?.collect::<std::io::Result<Vec<_>>>()?;
    files.sort_by_key(|f| f.file_name());
    for file in files
        .into_iter()
        .filter(|f| f.path().extension().is_some_and(|e| e == "json"))
    {
        let mut input: webauthn::metadata::MdsInput =
            serde_json::from_reader(File::open(file.path())?)?;
        input.now = now();
        match webauthn::metadata::verify_mds(input) {
            Ok(verified) => {
                eprintln!(
                    "MDS {}: verified {} entries (native)",
                    file.file_name().to_string_lossy(),
                    verified.entries.len()
                );
                for m in verified.entries {
                    if let Some(index) = entries.iter().position(|e| e.aaguid == m.aaguid) {
                        entries[index] = m;
                    } else {
                        entries.push(m);
                    }
                }
            }
            Err(_) => eprintln!(
                "MDS {}: rejected (native)",
                file.file_name().to_string_lossy()
            ),
        }
    }
    Ok(entries)
}
fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE users(name TEXT PRIMARY KEY,data TEXT NOT NULL);
        CREATE TABLE credentials(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,data TEXT NOT NULL);
        CREATE INDEX credential_user ON credentials(user_id);",
    )?;
    Ok(())
}
pub fn run() -> Result<()> {
    let port = std::env::var("FIDO_PORT")
        .unwrap_or("8080".into())
        .parse()?;
    let entries = metadata()?;
    let mut random = File::open("/dev/urandom")?;
    let mut bytes = [0u8; 16];
    random.read_exact(&mut bytes)?;
    let mode = std::env::var("FIDO_DB").unwrap_or("file".into());
    check(["file", "memory"].contains(&mode.as_str()))?;
    // New disposable file every start; never open a product database.
    let db = if mode == "memory" {
        Connection::open_in_memory()?
    } else {
        Connection::open(format!("target/fido-native-{}.sqlite", B64.encode(bytes)))?
    };
    schema(&db)?;
    let mut state = State {
        db,
        random,
        entries,
        transactions: HashMap::new(),
        port,
    };
    let server = Server::http((std::net::Ipv6Addr::LOCALHOST, port))?;
    eprintln!(
        "FIDO native-direct: http://localhost:{port}; SQLite {mode}; synchronous commits; metadata ready"
    );
    let epoch = Instant::now();
    for (sequence, mut req) in server.incoming_requests().enumerate() {
        let start = Instant::now();
        let received_ms = start.duration_since(epoch).as_secs_f64() * 1000.0;
        let path = match req.url() {
            p @ ("/attestation/options"
            | "/assertion/options"
            | "/attestation/result"
            | "/assertion/result") => p.to_string(),
            _ => "unknown".into(),
        };
        let mut timing = Timing::default();
        let result = state.handle(&mut req, &mut timing);
        let success = result.is_ok();
        let (output,cookie) = result.unwrap_or_else(|_|(json!({"status":"failed","errorMessage":"Request rejected by sakimori profile or verifier"}),None));
        let mut response = Response::from_string(output.to_string())
            .with_status_code(if success { 200 } else { 400 })
            .with_header(Header::from_bytes("Content-Type", "application/json").unwrap());
        if let Some(cookie) = cookie {
            response.add_header(Header::from_bytes("Set-Cookie", cookie).unwrap());
        }
        let handler_ms = start.elapsed().as_secs_f64() * 1000.0;
        let sent = req.respond(response).is_ok();
        if std::env::var("FIDO_TIMING").as_deref() == Ok("1") {
            println!(
                "{}",
                json!({"target":"native-direct","storage":mode,"path":path,
                "sequence":sequence,"received_ms":received_ms,
                "status":if success {"ok"} else {"failed"},"sent":sent,"ms":handler_ms,
                "response_ms":start.elapsed().as_secs_f64()*1000.0-handler_ms,
                "metadata_ms":timing.metadata,"verify_ms":timing.verify,"db_ms":timing.db})
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use sha2::{Digest, Sha256};
    fn state() -> State {
        let db = Connection::open_in_memory().unwrap();
        schema(&db).unwrap();
        State {
            db,
            random: File::open("/dev/urandom").unwrap(),
            entries: vec![],
            transactions: HashMap::new(),
            port: 8080,
        }
    }
    fn register_response(options: &Value) -> Value {
        let fixtures: Value =
            serde_json::from_str(include_str!("../../../webauthn/testdata/attestations.json"))
                .unwrap();
        let raw = B64
            .decode(
                fixtures["registrations"][0]["response"]["attestation"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        let value: ciborium::Value = ciborium::from_reader(raw.as_slice()).unwrap();
        let mut auth = value
            .as_map()
            .unwrap()
            .iter()
            .find(|(k, _)| k.as_text() == Some("authData"))
            .unwrap()
            .1
            .as_bytes()
            .unwrap()
            .clone();
        auth[..32].copy_from_slice(&Sha256::digest(b"localhost"));
        let value = ciborium::Value::Map(vec![
            ("fmt".into(), "none".into()),
            ("attStmt".into(), ciborium::Value::Map(vec![])),
            ("authData".into(), ciborium::Value::Bytes(auth)),
        ]);
        let mut attestation = Vec::new();
        ciborium::into_writer(&value, &mut attestation).unwrap();
        json!({"type":"public-key","id":"AQID","response":{
            "clientDataJSON":B64.encode(json!({"type":"webauthn.create","challenge":options["challenge"],"origin":"http://localhost:8080"}).to_string()),
            "attestationObject":B64.encode(attestation)}})
    }
    fn assertion(options: &Value, handle: &str, counter: u32) -> Value {
        let client = json!({"type":"webauthn.get","challenge":options["challenge"],"origin":"http://localhost:8080"}).to_string();
        let mut auth = Sha256::digest(b"localhost").to_vec();
        auth.push(5);
        auth.extend_from_slice(&counter.to_be_bytes());
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(client.as_bytes()));
        let signature: Signature = SigningKey::from_slice(&[7; 32]).unwrap().sign(&message);
        json!({"type":"public-key","id":"AQID","response":{"clientDataJSON":B64.encode(client),
            "authenticatorData":B64.encode(auth),"signature":B64.encode(signature.to_der().as_bytes()),"userHandle":handle}})
    }
    #[test]
    fn commits_counter_and_rejects_replay_expiry_wrong_challenge_and_database_failure() {
        let mut s = state();
        let mut t = Timing::default();
        let (o, id) = s
            .options(&json!({"username":"alice"}), true, &mut t)
            .unwrap();
        let registration = register_response(&o);
        s.result(&registration, true, &id, &mut t).unwrap();
        assert!(s.result(&registration, true, &id, &mut t).is_err());
        let handle = o["user"]["id"].as_str().unwrap();
        for counter in [1, 1, 2] {
            let (o, id) = s
                .options(&json!({"username":"alice"}), false, &mut t)
                .unwrap();
            let response = assertion(&o, handle, counter);
            let old: String =
                s.db.query_row("SELECT data FROM credentials", [], |r| r.get(0))
                    .unwrap();
            let old_counter = serde_json::from_str::<Value>(&old).unwrap()["counter"]
                .as_u64()
                .unwrap();
            assert_eq!(
                s.result(&response, false, &id, &mut t).is_ok(),
                u64::from(counter) > old_counter
            );
            assert!(s.result(&response, false, &id, &mut t).is_err());
        }
        let saved: String =
            s.db.query_row("SELECT data FROM credentials", [], |r| r.get(0))
                .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&saved).unwrap()["counter"], 2);
        let (o, id) = s
            .options(&json!({"username":"alice"}), false, &mut t)
            .unwrap();
        s.transactions.get_mut(&id).unwrap().expires = now();
        assert!(
            s.result(&assertion(&o, handle, 3), false, &id, &mut t)
                .is_err()
        );
        let (mut o, id) = s
            .options(&json!({"username":"alice"}), false, &mut t)
            .unwrap();
        o["challenge"] = json!(B64.encode([9; 32]));
        assert!(
            s.result(&assertion(&o, handle, 3), false, &id, &mut t)
                .is_err()
        );
        let (o, id) = s
            .options(&json!({"username":"alice"}), false, &mut t)
            .unwrap();
        s.db.execute_batch("CREATE TRIGGER fail_update BEFORE UPDATE ON credentials BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
        assert!(
            s.result(&assertion(&o, handle, 3), false, &id, &mut t)
                .is_err()
        );
        let unchanged: String =
            s.db.query_row("SELECT data FROM credentials", [], |r| r.get(0))
                .unwrap();
        assert_eq!(saved, unchanged);
    }
    #[test]
    fn duplicate_credential_rolls_back_user_and_failed_registration_consumes_ceremony() {
        let mut s = state();
        let mut t = Timing::default();
        let (o, id) = s
            .options(&json!({"username":"alice"}), true, &mut t)
            .unwrap();
        s.result(&register_response(&o), true, &id, &mut t).unwrap();
        let (o, id) = s.options(&json!({"username":"bob"}), true, &mut t).unwrap();
        assert!(s.result(&register_response(&o), true, &id, &mut t).is_err());
        assert!(!s.transactions.contains_key(&id));
        let count: i64 =
            s.db.query_row("SELECT count(*) FROM users", [], |r| r.get(0))
                .unwrap();
        assert_eq!(count, 1);
    }
}
