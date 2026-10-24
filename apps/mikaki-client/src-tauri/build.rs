mod client_config;

fn main() {
    println!("cargo:rerun-if-env-changed=MIKAKI_WEBVIEW_DEV_ORIGIN");
    println!("cargo:rerun-if-env-changed=MIKAKI_PASSPORT_CRLS");
    println!("cargo:rerun-if-env-changed=MIKAKI_HAIP_WALLET");
    println!("cargo:rerun-if-env-changed=MIKAKI_OID4VP_VERIFIERS");
    println!("cargo:rerun-if-env-changed=MIKAKI_MDOC_READERS");
    println!("cargo:rerun-if-env-changed=MIKAKI_DESKTOP_CLIENT_ID");
    println!("cargo:rerun-if-env-changed=MIKAKI_MOBILE_CLIENT_ID");
    println!("cargo:rerun-if-env-changed=MIKAKI_MOBILE_LOGIN_PROMPT");
    println!("cargo:rerun-if-changed=../mobile-client-registration.json");
    let client_id = client_config::mobile_client_id(std::env::var("MIKAKI_MOBILE_CLIENT_ID").ok())
        .expect("mobile OIDC registration must be valid when packaging the app");
    println!("cargo:rustc-env=MIKAKI_MOBILE_CLIENT_ID={client_id}");
    tauri_build::build();
}
