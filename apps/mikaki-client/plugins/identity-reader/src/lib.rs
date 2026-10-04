//! NFC transport adapted from madowi. Card protocols live in Rust.
//! No APDU, UID, PIN, or plugin command surface is exposed to JavaScript.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, PluginHandle, TauriPlugin},
    Manager, Runtime,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionRequest<'a> {
    session_id: &'a str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TransmitRequest<'a> {
    session_id: &'a str,
    apdu_base64: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    apdu_base64: String,
}

pub struct IdentityReader<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> IdentityReader<R> {
    pub fn open(&self, session_id: &str) -> Result<(), String> {
        self.0
            .run_mobile_plugin::<()>("open", SessionRequest { session_id })
            .map_err(|e| e.to_string())
    }
    pub fn transmit(&self, session_id: &str, apdu: &[u8]) -> Result<Vec<u8>, String> {
        let response = self
            .0
            .run_mobile_plugin::<Response>(
                "transmit",
                TransmitRequest {
                    session_id,
                    apdu_base64: STANDARD.encode(apdu),
                },
            )
            .map_err(|e| e.to_string())?;
        // No native error text or response bytes are reflected in app errors.
        let bytes = STANDARD
            .decode(response.apdu_base64)
            .map_err(|_| "invalid_response")?;
        if bytes.len() < 2 || bytes.len() > 4098 {
            return Err("invalid_response".into());
        }
        Ok(bytes)
    }
    pub fn close(&self, session_id: &str) {
        let _ = self
            .0
            .run_mobile_plugin::<()>("close", SessionRequest { session_id });
    }
}

pub trait IdentityReaderExt<R: Runtime> {
    fn identity_reader(&self) -> tauri::State<'_, IdentityReader<R>>;
}
impl<R: Runtime, T: Manager<R>> IdentityReaderExt<R> for T {
    fn identity_reader(&self) -> tauri::State<'_, IdentityReader<R>> {
        self.state()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("identity-reader")
        .setup(|app, api| {
            #[cfg(target_os = "android")]
            {
                let handle = api.register_android_plugin(
                    "app.mikaki.identity_reader",
                    "IdentityReaderPlugin",
                )?;
                app.manage(IdentityReader(handle));
            }
            #[cfg(not(target_os = "android"))]
            let _ = (app, api);
            Ok(())
        })
        .build()
}
