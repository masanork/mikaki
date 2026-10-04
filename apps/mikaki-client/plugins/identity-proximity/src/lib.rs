//! Bounded Rust-only ISO BLE peripheral transport; no generic WebView packets.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, PluginHandle, TauriPlugin},
    Manager, Runtime,
};
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Args<'a> {
    session_id: &'a str,
    service_uuid: &'a str,
    packet: &'a str,
    handover_select: &'a str,
    nfc_data: bool,
    negotiated: bool,
    expires_at: u64,
}
#[derive(Deserialize)]
struct Packet {
    packet: String,
}
pub struct IdentityProximity<R: Runtime>(PluginHandle<R>);
impl<R: Runtime> IdentityProximity<R> {
    pub fn start(
        &self,
        id: &str,
        uuid: &str,
        handover: Option<&[u8]>,
        nfc_data: bool,
        negotiated: bool,
    ) -> Result<(), String> {
        self.0
            .run_mobile_plugin(
                "start",
                Args {
                    expires_at: 0,
                    session_id: id,
                    service_uuid: uuid,
                    nfc_data,
                    negotiated,
                    handover_select: &handover.map(|h| B64.encode(h)).unwrap_or_default(),
                    packet: "",
                },
            )
            .map_err(|_| "ble_start_failed".into())
    }
    pub fn receive(&self, id: &str) -> Result<Vec<u8>, String> {
        let p = self
            .0
            .run_mobile_plugin::<Packet>(
                "receive",
                Args {
                    expires_at: 0,
                    session_id: id,
                    service_uuid: "",
                    nfc_data: false,
                    negotiated: false,
                    handover_select: "",
                    packet: "",
                },
            )
            .map_err(|_| "ble_receive_failed")?;
        if p.packet.len() > 43000 {
            return Err("invalid_ble_packet".into());
        }
        let bytes = B64.decode(p.packet).map_err(|_| "invalid_ble_packet")?;
        if bytes.len() > 32000 {
            return Err("invalid_ble_packet".into());
        }
        Ok(bytes)
    }
    pub fn receive_handover(&self, id: &str) -> Result<Vec<u8>, String> {
        let p = self
            .0
            .run_mobile_plugin::<Packet>(
                "receiveHandover",
                Args {
                    expires_at: 0,
                    session_id: id,
                    service_uuid: "",
                    packet: "",
                    handover_select: "",
                    nfc_data: false,
                    negotiated: false,
                },
            )
            .map_err(|_| "handover_receive_failed")?;
        if p.packet.len() > 5460 {
            return Err("invalid_handover".into());
        }
        let data = B64.decode(p.packet).map_err(|_| "invalid_handover")?;
        if data.is_empty() || data.len() > 4094 {
            return Err("invalid_handover".into());
        }
        Ok(data)
    }
    pub fn publish_handover(&self, id: &str, hs: &[u8]) -> Result<(), String> {
        if hs.is_empty() || hs.len() > 4094 {
            return Err("invalid_handover".into());
        }
        self.0
            .run_mobile_plugin(
                "publishHandover",
                Args {
                    expires_at: 0,
                    session_id: id,
                    service_uuid: "",
                    packet: &B64.encode(hs),
                    handover_select: "",
                    nfc_data: false,
                    negotiated: false,
                },
            )
            .map_err(|_| "handover_publish_failed".into())
    }
    pub fn send(&self, id: &str, bytes: &[u8], expires_at: u64) -> Result<(), String> {
        if bytes.len() > 32000 {
            return Err("invalid_ble_packet".into());
        }
        self.0
            .run_mobile_plugin(
                "send",
                Args {
                    expires_at,
                    session_id: id,
                    service_uuid: "",
                    nfc_data: false,
                    negotiated: false,
                    handover_select: "",
                    packet: &B64.encode(bytes),
                },
            )
            .map_err(|_| "ble_send_failed".into())
    }
    pub async fn wait_closed(&self, id: &str) -> Result<(), String> {
        self.0
            .run_mobile_plugin_async::<()>(
                "waitClosed",
                Args {
                    expires_at: 0,
                    session_id: id,
                    service_uuid: "",
                    packet: "",
                    handover_select: "",
                    nfc_data: false,
                    negotiated: false,
                },
            )
            .await
            .map_err(|_| "transport_closed".into())
    }
    pub fn close(&self, id: &str) {
        let _ = self.0.run_mobile_plugin::<()>(
            "close",
            Args {
                expires_at: 0,
                session_id: id,
                service_uuid: "",
                nfc_data: false,
                negotiated: false,
                handover_select: "",
                packet: "",
            },
        );
    }
}
pub trait IdentityProximityExt<R: Runtime> {
    fn identity_proximity(&self) -> tauri::State<'_, IdentityProximity<R>>;
}
impl<R: Runtime, T: Manager<R>> IdentityProximityExt<R> for T {
    fn identity_proximity(&self) -> tauri::State<'_, IdentityProximity<R>> {
        self.state()
    }
}
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("identity-proximity")
        .setup(|app, api| {
            #[cfg(target_os = "android")]
            {
                let handle = api.register_android_plugin(
                    "app.mikaki.identity_proximity",
                    "IdentityProximityPlugin",
                )?;
                app.manage(IdentityProximity(handle));
            }
            #[cfg(not(target_os = "android"))]
            let _ = (app, api);
            Ok(())
        })
        .build()
}
