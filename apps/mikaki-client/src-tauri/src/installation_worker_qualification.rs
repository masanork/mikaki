//! Debug-only host-shuttled Worker/D1 qualification; no real identity or TLS.
use crate::installation_key::{InstallationKey, InstallationStore};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use mikaki_identity::{
    installation_recovery::{persist_completion, persist_status_request},
    installation_transaction::{RegistrationStatus, Started},
};
use rand_core::{Rng, UnwrapErr};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::{AppHandle, Manager};
use tauri_plugin_native_dpop::NativeDpopExt;

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
    let mut bytes = [0u8; 32];
    UnwrapErr(getrandom::SysRng).fill_bytes(&mut bytes);
    B64.encode(bytes)
}
fn output(dir: &Path, name: &str, value: serde_json::Value) -> Result<(), String> {
    std::fs::write(
        dir.join(name),
        serde_json::to_vec(&value).map_err(|_| "encode")?,
    )
    .map_err(|_| "write".into())
}
fn input(dir: &Path, name: &str) -> Result<Vec<u8>, String> {
    for _ in 0..600 {
        match std::fs::read(dir.join(name)) {
            Ok(bytes) if bytes.len() <= 1024 => return Ok(bytes),
            Ok(_) => return Err("oversized".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(100))
            }
            Err(_) => return Err("read".into()),
        }
    }
    Err("timeout".into())
}
fn prepare(app: &AppHandle, dir: &Path) -> Result<(), String> {
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
    app.native_dpop().create_device_session_key(&id)?;
    let started = Started::begin(&key, "https://auth.example", &random(), now()?)?;
    output(
        dir,
        "installation-worker-start.json",
        serde_json::json!({"proof":started.proof()}),
    )?;
    let challenge = input(dir, "installation-worker-challenge.json")?;
    let request = started
        .challenge(&challenge, now()?)?
        .complete(&key, &random(), now()?)?;
    let sent = persist_completion(&store, request, &owner)?;
    let fixture = Fixture {
        id,
        owner,
        registration: sent.id().to_owned(),
    };
    std::fs::write(
        dir.join("installation-worker-fixture.json"),
        serde_json::to_vec(&fixture).map_err(|_| "encode")?,
    )
    .map_err(|_| "write")?;
    output(
        dir,
        "installation-worker-completion.json",
        serde_json::json!({"id":sent.id(),"proof":sent.proof()}),
    )
}
fn resume(app: &AppHandle, dir: &Path, bytes: &[u8]) -> Result<(), String> {
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
    let request = persist_status_request(
        &store,
        &key,
        "https://auth.example",
        &fixture.owner,
        &random(),
        now()?,
    )?;
    if request.id() != fixture.registration {
        return Err("status_mismatch".into());
    }
    output(
        dir,
        "installation-worker-status.json",
        serde_json::json!({"id":request.id(),"proof":request.proof()}),
    )?;
    let body = input(dir, "installation-worker-result.json")?;
    if request.response(&body)? != RegistrationStatus::Active {
        return Err("not_active".into());
    }
    app.native_dpop().delete_device_session_key(&fixture.id)?;
    output(
        dir,
        "installation-worker-done.json",
        serde_json::json!({"status":"active"}),
    )
}
pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        if let Ok(dir) = app.path().app_data_dir() {
            let _ = std::fs::create_dir_all(&dir);
            let fixture = dir.join("installation-worker-fixture.json");
            let result = match std::fs::read(fixture) {
                Ok(bytes) => resume(&app, &dir, &bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => prepare(&app, &dir),
                Err(_) => Err("read".into()),
            };
            if result.is_err() {
                let _ = output(
                    &dir,
                    "installation-worker-error.json",
                    serde_json::json!({"error":"qualification_failed"}),
                );
            }
        }
    });
}
