//! Persistent first-party WebView. These methods are Rust-only; no JS commands.
use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, PluginHandle, TauriPlugin},
    Manager, Runtime,
};
use zeroize::Zeroizing;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRequest {
    pub visible: bool,
    pub page: String,
    pub top: f64,
    pub bottom: f64,
    pub viewport_width: f64,
}
#[derive(Deserialize)]
pub struct BrowserStatus {
    pub ready: bool,
    pub error: Option<String>,
    pub cookie: Option<String>,
}
impl BrowserStatus {
    pub fn take_cookie(&mut self) -> Option<Zeroizing<String>> {
        self.cookie.take().map(Zeroizing::new)
    }
}
pub struct AppSession<R: Runtime>(PluginHandle<R>);
impl<R: Runtime> AppSession<R> {
    pub fn workspace(&self, request: WorkspaceRequest) -> Result<(), String> {
        self.0
            .run_mobile_plugin("workspace", request)
            .map_err(|_| "workspace_unavailable".into())
    }
    pub fn status(&self) -> Result<BrowserStatus, String> {
        self.0
            .run_mobile_plugin("status", ())
            .map_err(|_| "workspace_unavailable".into())
    }
    pub fn clear(&self) -> Result<(), String> {
        self.0
            .run_mobile_plugin("clear", ())
            .map_err(|_| "workspace_unavailable".into())
    }
    pub fn reset(&self) -> Result<(), String> {
        self.0
            .run_mobile_plugin("reset", ())
            .map_err(|_| "workspace_unavailable".into())
    }
}
pub trait AppSessionExt<R: Runtime> {
    fn app_session(&self) -> tauri::State<'_, AppSession<R>>;
}
impl<R: Runtime, T: Manager<R>> AppSessionExt<R> for T {
    fn app_session(&self) -> tauri::State<'_, AppSession<R>> {
        self.state::<AppSession<R>>()
    }
}
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("app-session")
        .setup(|app, api| {
            let handle =
                api.register_android_plugin("app.mikaki.app_session", "AppSessionPlugin")?;
            app.manage(AppSession(handle));
            Ok(())
        })
        .build()
}
