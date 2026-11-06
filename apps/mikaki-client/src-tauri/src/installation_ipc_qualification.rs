//! Debug-only, local IPC and process-restart qualification. No real account or server.
use crate::installation_key::{InstallationKey, InstallationStore};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use mikaki_identity::{
    installation_recovery::{persist_completion, persist_status_request, RecoveryStore},
    installation_transaction::Started,
};
use rand_core::{Rng, UnwrapErr};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tauri_plugin_native_dpop::NativeDpopExt;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    id: String,
    owner: String,
    registration: String,
}

fn prepare(app: &AppHandle, path: &std::path::Path) -> Result<(), String> {
    let mut random = [0u8; 176];
    UnwrapErr(getrandom::SysRng).fill_bytes(&mut random);
    let id: String = random[..16].iter().map(|b| format!("{b:02x}")).collect();
    let token = |offset| B64.encode(&random[offset..offset + 32]);
    let start = token(16);
    let completion = token(48);
    let owner = token(80);
    let registration = token(112);
    let nonce = token(144);
    let key = InstallationKey {
        app: app.clone(),
        id: id.clone(),
    };
    let store = InstallationStore {
        app: app.clone(),
        id: id.clone(),
    };
    app.native_dpop().create_device_session_key(&id)?;
    if store.load()?.is_some() {
        return Err("nonempty_fixture".into());
    }
    let challenge = serde_json::json!({"id":registration,"nonce":nonce,"expires_at":1120});
    let request = Started::begin(&key, "https://auth.example", &start, 1000)?
        .challenge(challenge.to_string().as_bytes(), 1001)?
        .complete(&key, &completion, 1002)?;
    let sent = persist_completion(&store, request, &owner)?;
    if sent.id() != registration || sent.proof().is_empty() {
        return Err("completion_mismatch".into());
    }
    let fixture = Fixture {
        id,
        owner,
        registration,
    };
    let bytes = serde_json::to_vec(&fixture).map_err(|_| "fixture_encode")?;
    std::fs::write(path, bytes).map_err(|_| "fixture_write")?;
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
    let jti = B64.encode([0x25; 32]);
    let request = persist_status_request(
        &store,
        &key,
        "https://auth.example",
        &fixture.owner,
        &jti,
        1003,
    )?;
    if request.id() != fixture.registration || request.proof().is_empty() {
        return Err("status_mismatch".into());
    }
    if persist_status_request(
        &store,
        &key,
        "https://auth.example",
        &fixture.owner,
        &jti,
        1004,
    )
    .is_ok()
    {
        return Err("replay_accepted".into());
    }
    app.native_dpop().delete_device_session_key(&fixture.id)
}

pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        if let Ok(dir) = app.path().app_data_dir() {
            let _ = std::fs::create_dir_all(&dir);
            let fixture_path = dir.join("installation-ipc-fixture.json");
            let marker = dir.join("installation-ipc-qualification.txt");
            let result = match std::fs::read(&fixture_path) {
                Ok(bytes) => {
                    if resume(&app, &bytes).is_ok() {
                        "ok"
                    } else {
                        "error"
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if prepare(&app, &fixture_path).is_ok() {
                        "prepared"
                    } else {
                        "error"
                    }
                }
                Err(_) => "error",
            };
            let _ = std::fs::write(marker, result);
        }
    });
}
