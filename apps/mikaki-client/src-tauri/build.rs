fn main() {
    println!("cargo:rerun-if-env-changed=MIKAKI_HAIP_WALLET");
    println!("cargo:rerun-if-env-changed=MIKAKI_OID4VP_VERIFIERS");
    println!("cargo:rerun-if-env-changed=MIKAKI_MDOC_READERS");
    println!("cargo:rerun-if-env-changed=MIKAKI_MOBILE_CLIENT_ID");
    println!("cargo:rerun-if-env-changed=MIKAKI_MOBILE_LOGIN_PROMPT");
    println!("cargo:rerun-if-env-changed=MIKAKI_NATIVE_VAULT_PREVIEW");
    tauri_build::build();
}
