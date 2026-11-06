//! Debug-only emulator HTTPS fixture. Synthetic account, CA and local Worker.
use crate::installation_key::{InstallationKey, InstallationStore};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use mikaki_identity::{
    installation_recovery::{persist_completion, persist_status_request},
    installation_transaction::{RegistrationStatus, Started},
};
use rand_core::{Rng, UnwrapErr};
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};
use tauri_plugin_native_dpop::NativeDpopExt;

const ISSUER: &str = "https://auth.example:18443";
const CA: &[u8] = include_bytes!(env!("MIKAKI_INSTALLATION_TEST_CA"));
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    id: String,
    owner: String,
    registration: String,
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|n| n.as_secs())
        .map_err(|_| "clock".into())
}
fn random() -> String {
    let mut b = [0u8; 32];
    UnwrapErr(getrandom::SysRng).fill_bytes(&mut b);
    B64.encode(b)
}
fn client() -> Result<Client, String> {
    let ca = reqwest::Certificate::from_pem(CA).map_err(|_| "ca")?;
    Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(15))
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .resolve(
            "auth.example",
            "10.0.2.2:18443".parse().map_err(|_| "address")?,
        )
        .build()
        .map_err(|e| format!("client:{e:?}"))
}
fn post(client: &Client, path: &str, proof: &str, body: String) -> reqwest::Result<Response> {
    client
        .post(format!("{ISSUER}{path}"))
        .header("origin", ISSUER)
        .header("x-mikaki-app", "1")
        .header("content-type", "application/json")
        .header("cookie", "__Host-op-sso=qualification-sso-secret")
        .header("dpop", proof)
        .body(body)
        .send()
}
fn body(response: Response) -> Result<Vec<u8>, String> {
    if !response.status().is_success() {
        return Err(format!("http_status:{}", response.status().as_u16()));
    }
    let mut bytes = Vec::new();
    response
        .take(1025)
        .read_to_end(&mut bytes)
        .map_err(|_| "read")?;
    if bytes.len() > 1024 {
        return Err("oversized".into());
    }
    Ok(bytes)
}
fn prepare(app: &AppHandle, path: &Path) -> Result<(), String> {
    let mut bytes = [0u8; 16];
    UnwrapErr(getrandom::SysRng).fill_bytes(&mut bytes);
    let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let owner = random();
    let key = InstallationKey {
        app: app.clone(),
        id: id.clone(),
    };
    let store = InstallationStore {
        app: app.clone(),
        id: id.clone(),
    };
    let client = client()?;
    app.native_dpop().create_device_session_key(&id)?;
    let started = Started::begin(&key, ISSUER, &random(), now()?)?;
    let reply = post(
        &client,
        "/native/installations/start",
        started.proof(),
        "{}".into(),
    )
    .map_err(|e| format!("start_transport:{e:?}"))?;
    let challenged = started.challenge(&body(reply)?, now()?)?;
    let request = challenged.complete(&key, &random(), now()?)?;
    let sent = persist_completion(&store, request, &owner)?;
    let fixture = Fixture {
        id,
        owner,
        registration: sent.id().to_owned(),
    };
    std::fs::write(path, serde_json::to_vec(&fixture).map_err(|_| "encode")?)
        .map_err(|_| "write")?;
    // The test server commits and closes the TLS connection without a reply.
    if post(
        &client,
        "/native/installations/complete",
        sent.proof(),
        serde_json::json!({"id":sent.id()}).to_string(),
    )
    .is_ok()
    {
        return Err("completion_did_not_lose_reply".into());
    }
    Ok(())
}
fn resume(app: &AppHandle, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 512 {
        return Err("invalid_fixture".into());
    }
    let fixture: Fixture = serde_json::from_slice(bytes).map_err(|_| "invalid_fixture")?;
    let key = InstallationKey {
        app: app.clone(),
        id: fixture.id.clone(),
    };
    let store = InstallationStore {
        app: app.clone(),
        id: fixture.id.clone(),
    };
    let request = persist_status_request(&store, &key, ISSUER, &fixture.owner, &random(), now()?)?;
    if request.id() != fixture.registration {
        return Err("status_mismatch".into());
    }
    let reply = post(
        &client()?,
        "/native/installations/status",
        request.proof(),
        serde_json::json!({"id":request.id()}).to_string(),
    )
    .map_err(|e| format!("status_transport:{e:?}"))?;
    if request.response(&body(reply)?)? != RegistrationStatus::Active {
        return Err("not_active".into());
    }
    app.native_dpop().delete_device_session_key(&fixture.id)
}
pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        if let Ok(dir) = app.path().app_data_dir() {
            let _ = std::fs::create_dir_all(&dir);
            let state = dir.join("installation-https-fixture.json");
            let result: Result<&str, String> = match std::fs::read(&state) {
                Ok(bytes) => resume(&app, &bytes).map(|_| "active"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    prepare(&app, &state).map(|_| "reply_lost")
                }
                Err(_) => Err("state_read".into()),
            };
            let result = result
                .map(str::to_owned)
                .unwrap_or_else(|e| format!("error:{e}"));
            let _ = std::fs::write(dir.join("installation-https-result.txt"), result);
        }
    });
}
