//! Debug-only, local IPC qualification. No user, network, or production route.
use crate::installation_key::{InstallationKey, InstallationStore};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use mikaki_identity::{
    installation_recovery::{persist_completion, persist_status_request, RecoveryStore},
    installation_transaction::Started,
};
use rand_core::{Rng, UnwrapErr};
use tauri::{AppHandle, Manager};
use tauri_plugin_native_dpop::NativeDpopExt;

fn exercise(app: &AppHandle) -> Result<(), String> {
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
    let result = (|| {
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
        let jti = B64.encode([0x25; 32]);
        let request =
            persist_status_request(&store, &key, "https://auth.example", &owner, &jti, 1003)?;
        if request.id() != registration || request.proof().is_empty() {
            return Err("status_mismatch".into());
        }
        if persist_status_request(&store, &key, "https://auth.example", &owner, &jti, 1004).is_ok()
        {
            return Err("replay_accepted".into());
        }
        Ok(())
    })();
    let deletion = app.native_dpop().delete_device_session_key(&id);
    result.and(deletion)
}

pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        let result = if exercise(&app).is_ok() {
            "ok"
        } else {
            "error"
        };
        if let Ok(dir) = app.path().app_data_dir() {
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(dir.join("installation-ipc-qualification.txt"), result);
        }
    });
}
