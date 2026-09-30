#[cfg(any(target_os = "android", target_os = "ios"))]
mod mobile_oidc;
#[cfg(any(target_os = "android", target_os = "ios"))]
mod mobile_vault;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod native_oidc;
#[cfg(any(target_os = "android", target_os = "ios", test))]
mod vault_dpop;

#[cfg(any(target_os = "android", target_os = "ios"))]
use tauri_plugin_deep_link::DeepLinkExt;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init());
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let builder = builder
        .manage(native_oidc::NativeAuthState::default())
        .invoke_handler(tauri::generate_handler![
            native_oidc::native_platform,
            native_oidc::native_session,
            native_oidc::clear_native_session,
            native_oidc::start_desktop_login
        ]);
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder
        .plugin(tauri_plugin_native_dpop::init())
        .manage(mobile_oidc::MobileAuthState::default())
        .invoke_handler(tauri::generate_handler![
            mobile_oidc::native_platform,
            mobile_oidc::native_session,
            mobile_oidc::mobile_auth_status,
            mobile_oidc::clear_native_session,
            mobile_oidc::start_mobile_login,
            mobile_oidc::start_mobile_vault_read,
            mobile_oidc::check_mobile_vault_key,
            mobile_oidc::read_mobile_vault_ciphertext
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    let app = handle.clone();
                    tauri::async_runtime::spawn(async move {
                        mobile_oidc::handle_open_url(app, url).await;
                    });
                }
            });
            Ok(())
        });
    builder
        .run(tauri::generate_context!())
        .expect("failed to run Mikaki client");
}
