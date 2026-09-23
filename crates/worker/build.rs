use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=ui/login.ts");
    println!("cargo:rerun-if-changed=ui/vault.ts");
    println!("cargo:rerun-if-changed=ui/vault-crypto.ts");
    println!("cargo:rerun-if-changed=ui/tsconfig.json");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("wasm32") {
        return;
    }
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let compiler = manifest.join("../../node_modules/@typescript/native/bin/tsc");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
    let status = Command::new(compiler)
        .arg("--project")
        .arg(manifest.join("ui/tsconfig.json"))
        .arg("--outDir")
        .arg(&output)
        .status()
        .expect("TypeScript 7 compiler is required; run npm ci");
    assert!(status.success(), "Worker UI TypeScript compilation failed");
}
