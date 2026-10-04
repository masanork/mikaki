#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
mod identity_card;
mod identity_events;
mod identity_issuance;
mod identity_reader;
mod identity_wallet;
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
        .manage(identity_reader::ReadState::default())
        .manage(identity_events::IdentityEvents::default())
        .manage(identity_issuance::IdentityState::default())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_deep_link::init());
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let builder = builder
        .manage(native_oidc::NativeAuthState::default())
        .invoke_handler(tauri::generate_handler![
            identity_events::subscribe_identity_updates,
            identity_issuance::haip::flow::identity_wallet_issuance_status,
            identity_issuance::haip::flow::start_identity_wallet_issuance,
            identity_issuance::haip::flow::receive_identity_wallet_credential,
            identity_issuance::haip::flow::cancel_identity_wallet_issuance,
            identity_reader::identity_reader_supported,
            identity_reader::read_identity_card,
            identity_reader::cancel_identity_card,
            identity_issuance::clear_identity_evidence,
            identity_issuance::start_identity_link,
            identity_issuance::receive_identity_credential,
            identity_issuance::clear_identity_credential,
            identity_issuance::identity_credential_status,
            identity_issuance::open_identity_management,
            identity_issuance::proximity::start_identity_proximity,
            identity_issuance::proximity::review_identity_proximity,
            identity_issuance::proximity::confirm_identity_proximity,
            identity_issuance::proximity::cancel_identity_proximity,
            identity_issuance::review_identity_presentation,
            identity_issuance::invocation::pending_identity_invocation,
            identity_issuance::invocation::review_identity_invocation,
            identity_issuance::invocation::cancel_identity_presentation,
            identity_issuance::confirm_identity_presentation,
            native_oidc::native_platform,
            native_oidc::native_session,
            native_oidc::clear_native_session,
            native_oidc::cancel_native_login,
            native_oidc::start_desktop_login
        ]);
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder
        .plugin(tauri_plugin_native_dpop::init())
        .manage(mobile_oidc::MobileAuthState::default())
        .invoke_handler(tauri::generate_handler![
            identity_events::subscribe_identity_updates,
            identity_issuance::haip::flow::identity_wallet_issuance_status,
            identity_issuance::haip::flow::start_identity_wallet_issuance,
            identity_issuance::haip::flow::receive_identity_wallet_credential,
            identity_issuance::haip::flow::cancel_identity_wallet_issuance,
            identity_reader::identity_reader_supported,
            identity_reader::read_identity_card,
            identity_reader::cancel_identity_card,
            identity_issuance::clear_identity_evidence,
            identity_issuance::start_identity_link,
            identity_issuance::receive_identity_credential,
            identity_issuance::clear_identity_credential,
            identity_issuance::identity_credential_status,
            identity_issuance::open_identity_management,
            identity_issuance::proximity::start_identity_proximity,
            identity_issuance::proximity::review_identity_proximity,
            identity_issuance::proximity::confirm_identity_proximity,
            identity_issuance::proximity::cancel_identity_proximity,
            identity_issuance::review_identity_presentation,
            identity_issuance::invocation::pending_identity_invocation,
            identity_issuance::invocation::review_identity_invocation,
            identity_issuance::invocation::cancel_identity_presentation,
            identity_issuance::confirm_identity_presentation,
            mobile_oidc::native_platform,
            mobile_oidc::native_session,
            mobile_oidc::mobile_auth_status,
            mobile_oidc::clear_native_session,
            mobile_oidc::cancel_native_login,
            mobile_oidc::start_mobile_login,
            mobile_oidc::start_mobile_vault_read,
            mobile_oidc::check_mobile_vault_key,
            mobile_oidc::read_mobile_vault_ciphertext
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            if let Ok(Some(urls)) = app.deep_link().get_current() {
                for url in urls {
                    if identity_issuance::haip::receive(&handle, &url) {
                        continue;
                    }
                    identity_issuance::invocation::receive(&handle, &url);
                }
            }
            app.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    if identity_issuance::haip::receive(&handle, &url) {
                        continue;
                    }
                    identity_issuance::invocation::receive(&handle, &url);
                    let app = handle.clone();
                    tauri::async_runtime::spawn(async move {
                        mobile_oidc::handle_open_url(app, url).await;
                    });
                }
            });
            Ok(())
        });
    #[cfg(target_os = "android")]
    let builder = builder
        .plugin(tauri_plugin_identity_reader::init())
        .plugin(tauri_plugin_identity_proximity::init());
    builder
        .run(tauri::generate_context!())
        .expect("failed to run Mikaki client");
}
