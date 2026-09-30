fn main() {
    println!("cargo:rerun-if-env-changed=MIKAKI_MOBILE_CLIENT_ID");
    println!("cargo:rerun-if-env-changed=MIKAKI_NATIVE_VAULT_PREVIEW");
    tauri_build::build();
}
