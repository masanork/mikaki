//! Android-only adapter for a separate installation-session Keystore key.
//! No WebView command, enrollment, or session is exposed by this adapter.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use mikaki_identity::{
    installation_proof::InstallationSigner, installation_recovery::RecoveryStore,
    issuance::PublicJwk,
};
use tauri::AppHandle;
use tauri_plugin_native_dpop::NativeDpopExt;
use zeroize::Zeroizing;

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

/// Internal native adapter; no WebView command or registration route is added.
#[allow(dead_code)]
pub(crate) struct InstallationStore {
    pub app: AppHandle,
    pub id: String,
}
impl RecoveryStore for InstallationStore {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        self.app
            .native_dpop()
            .load_installation_recovery(&self.id)?
            .map(|encoded| {
                let bytes = Zeroizing::new(
                    B64.decode(&encoded)
                        .map_err(|_| "installation_recovery_unavailable")?,
                );
                if bytes.is_empty() || bytes.len() > 4096 || B64.encode(&*bytes) != encoded {
                    return Err("installation_recovery_unavailable".into());
                }
                Ok(bytes)
            })
            .transpose()
    }
    fn compare_and_set(&self, expected: Option<[u8; 32]>, value: &[u8]) -> Result<(), String> {
        if value.is_empty() || value.len() > 4096 {
            return Err("installation_recovery_unavailable".into());
        }
        let expected = expected.map(|digest| B64.encode(digest));
        let payload = Zeroizing::new(B64.encode(value));
        self.app
            .native_dpop()
            .compare_and_set_installation_recovery(&self.id, expected.as_deref(), &payload)
    }
}
