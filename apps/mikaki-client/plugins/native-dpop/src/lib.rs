//! Mobile OS key custody for the Vault DPoP key. No JavaScript command is exposed.

use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, PluginHandle, TauriPlugin},
    Manager, Runtime,
};

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "app.mikaki.native_dpop";
#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_native_dpop);

#[derive(Clone, Deserialize)]
pub struct PublicKey {
    pub x: String,
    pub y: String,
}

#[derive(Deserialize)]
struct Signature {
    der: String,
}

#[derive(Serialize)]
struct SignRequest<'a> {
    input: &'a str,
}

pub struct NativeDpop<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> NativeDpop<R> {
    pub fn public_key(&self) -> Result<PublicKey, String> {
        self.0
            .run_mobile_plugin("publicKey", ())
            .map_err(|_| "OS DPoP key unavailable".into())
    }

    pub fn sign(&self, input: &str) -> Result<String, String> {
        self.0
            .run_mobile_plugin::<Signature>("sign", SignRequest { input })
            .map(|result| result.der)
            .map_err(|_| "OS DPoP signature unavailable".into())
    }
}

pub trait NativeDpopExt<R: Runtime> {
    fn native_dpop(&self) -> tauri::State<'_, NativeDpop<R>>;
}

impl<R: Runtime, T: Manager<R>> NativeDpopExt<R> for T {
    fn native_dpop(&self) -> tauri::State<'_, NativeDpop<R>> {
        self.state::<NativeDpop<R>>()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("native-dpop")
        .setup(|app, api| {
            #[cfg(target_os = "android")]
            let handle = api.register_android_plugin(PLUGIN_IDENTIFIER, "NativeDpopPlugin")?;
            #[cfg(target_os = "ios")]
            let handle = api.register_ios_plugin(init_plugin_native_dpop)?;
            app.manage(NativeDpop(handle));
            Ok(())
        })
        .build()
}
