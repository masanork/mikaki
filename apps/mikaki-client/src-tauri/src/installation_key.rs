//! Android-only adapter for a separate installation-session Keystore key.
//! No WebView command, enrollment, or session is exposed by this adapter.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use mikaki_identity::{installation_proof::InstallationSigner, issuance::PublicJwk};
use tauri::AppHandle;
use tauri_plugin_native_dpop::NativeDpopExt;

#[allow(dead_code)]
pub(crate) struct InstallationKey {
    pub app: AppHandle,
    pub id: String,
}
impl InstallationSigner for InstallationKey {
    fn public_key(&self) -> Result<PublicJwk, String> {
        let public = self.app.native_dpop().device_session_public_key(&self.id)?;
        Ok(PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: public.x,
            y: public.y,
        })
    }
    fn sign_der(&self, input: &str) -> Result<Vec<u8>, String> {
        let encoded = self
            .app
            .native_dpop()
            .sign_device_session(&self.id, input)?;
        let der = B64
            .decode(&encoded)
            .map_err(|_| "device_session_key_unavailable")?;
        if der.len() > 80 || B64.encode(&der) != encoded {
            return Err("device_session_key_unavailable".into());
        }
        Ok(der)
    }
}
