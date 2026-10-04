//! Mobile OS key custody and Android identity-wallet storage. No JavaScript command is exposed.

#[cfg(target_os = "android")]
use serde::{Deserialize, Serialize};
#[cfg(target_os = "android")]
use tauri::{
    plugin::{Builder, PluginHandle, TauriPlugin},
    Manager, Runtime,
};

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "app.mikaki.native_dpop";

#[cfg(target_os = "android")]
#[derive(Clone, Deserialize)]
pub struct PublicKey {
    pub x: String,
    pub y: String,
}

#[cfg(target_os = "android")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttestedPublicKey {
    pub x: String,
    pub y: String,
    pub certificate_chain: Vec<String>,
}

#[cfg(target_os = "android")]
#[derive(Serialize)]
struct AttestedHolderRequest<'a> {
    id: &'a str,
    challenge: &'a str,
}

#[derive(Deserialize)]
#[cfg(target_os = "android")]
struct Signature {
    der: String,
}

#[cfg(target_os = "android")]
pub struct NativeDpop<R: Runtime>(PluginHandle<R>);

#[cfg(target_os = "android")]
#[derive(Serialize)]
struct HolderRequest<'a> {
    id: &'a str,
    input: &'a str,
    payload: &'a str,
}
#[cfg(target_os = "android")]
#[derive(Deserialize)]
struct WalletPayload {
    payload: Option<String>,
}
#[cfg(target_os = "android")]
impl<R: Runtime> NativeDpop<R> {
    pub fn create_attested_holder(
        &self,
        id: &str,
        challenge: &str,
    ) -> Result<AttestedPublicKey, String> {
        self.0
            .run_mobile_plugin(
                "createAttestedHolder",
                AttestedHolderRequest { id, challenge },
            )
            .map_err(|_| "wallet_attestation_unavailable".into())
    }
    pub fn create_holder(&self, id: &str) -> Result<PublicKey, String> {
        self.0
            .run_mobile_plugin(
                "createHolder",
                HolderRequest {
                    id,
                    input: "",
                    payload: "",
                },
            )
            .map_err(|_| "wallet_key_unavailable".into())
    }
    pub fn holder_public_key(&self, id: &str) -> Result<PublicKey, String> {
        self.0
            .run_mobile_plugin(
                "holderPublicKey",
                HolderRequest {
                    id,
                    input: "",
                    payload: "",
                },
            )
            .map_err(|_| "wallet_key_unavailable".into())
    }
    pub fn sign_holder(&self, id: &str, input: &str) -> Result<String, String> {
        self.0
            .run_mobile_plugin::<Signature>(
                "signHolder",
                HolderRequest {
                    id,
                    input,
                    payload: "",
                },
            )
            .map(|s| s.der)
            .map_err(|_| "wallet_key_unavailable".into())
    }
    pub fn sign_holder_bytes(&self, id: &str, input: &str) -> Result<String, String> {
        self.0
            .run_mobile_plugin::<Signature>(
                "signHolderBytes",
                HolderRequest {
                    id,
                    input,
                    payload: "",
                },
            )
            .map(|s| s.der)
            .map_err(|_| "wallet_key_unavailable".into())
    }
    pub fn delete_holder(&self, id: &str) -> Result<(), String> {
        self.0
            .run_mobile_plugin(
                "deleteHolder",
                HolderRequest {
                    id,
                    input: "",
                    payload: "",
                },
            )
            .map_err(|_| "wallet_key_unavailable".into())
    }
    pub fn store_wallet(&self, id: &str, payload: &str) -> Result<(), String> {
        self.0
            .run_mobile_plugin(
                "storeWallet",
                HolderRequest {
                    id,
                    input: "",
                    payload,
                },
            )
            .map_err(|_| "wallet_storage_unavailable".into())
    }
    pub fn load_wallet(&self) -> Result<Option<String>, String> {
        self.0
            .run_mobile_plugin::<WalletPayload>("loadWallet", ())
            .map(|p| p.payload)
            .map_err(|_| "wallet_storage_unavailable".into())
    }
    pub fn erase_wallet(&self) -> Result<(), String> {
        self.0
            .run_mobile_plugin("eraseWallet", ())
            .map_err(|_| "wallet_storage_unavailable".into())
    }
    pub fn delete_wallet(&self) -> Result<(), String> {
        self.0
            .run_mobile_plugin("deleteWallet", ())
            .map_err(|_| "wallet_storage_unavailable".into())
    }
}

#[cfg(target_os = "android")]
pub trait NativeDpopExt<R: Runtime> {
    fn native_dpop(&self) -> tauri::State<'_, NativeDpop<R>>;
}

#[cfg(target_os = "android")]
impl<R: Runtime, T: Manager<R>> NativeDpopExt<R> for T {
    fn native_dpop(&self) -> tauri::State<'_, NativeDpop<R>> {
        self.state::<NativeDpop<R>>()
    }
}

#[cfg(target_os = "android")]
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("native-dpop")
        .setup(|app, api| {
            let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "NativeDpopPlugin")?;
            app.manage(NativeDpop(handle));
            Ok(())
        })
        .build()
}
