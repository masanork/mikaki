use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=ui/login.ts");
    println!("cargo:rerun-if-changed=ui/vault.ts");
    println!("cargo:rerun-if-changed=ui/Login.svelte");
    println!("cargo:rerun-if-changed=ui/Admin.svelte");
    println!("cargo:rerun-if-changed=ui/admin.ts");
    println!("cargo:rerun-if-changed=ui/Complete.svelte");
    println!("cargo:rerun-if-changed=ui/complete.ts");
    println!("cargo:rerun-if-changed=ui/Vault.svelte");
    println!("cargo:rerun-if-changed=ui/locale.ts");
    println!("cargo:rerun-if-changed=ui/vault-crypto.ts");
    println!("cargo:rerun-if-changed=ui/vault-recipient-envelope.ts");
    println!("cargo:rerun-if-changed=ui/tsconfig.json");
    println!("cargo:rerun-if-changed=ui/vite.config.ts");
    println!("cargo:rerun-if-changed=../../project.inlang/settings.json");
    println!("cargo:rerun-if-changed=../../messages/ja.json");
    println!("cargo:rerun-if-changed=../../messages/en.json");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("wasm32") {
        return;
    }
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let compiler = manifest.join("../../node_modules/@typescript/native/bin/tsc");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
    let paraglide = manifest.join("../../node_modules/.bin/paraglide-js");
    let status = Command::new(paraglide)
        .arg("compile")
        .arg("--project")
        .arg(manifest.join("../../project.inlang"))
        .arg("--outdir")
        .arg(manifest.join("ui/paraglide"))
        .arg("--emit-ts-declarations")
        .status()
        .expect("Paraglide JS is required; run npm ci");
    assert!(status.success(), "Worker UI messages compilation failed");
    let status = Command::new(compiler)
        .arg("--project")
        .arg(manifest.join("ui/tsconfig.json"))
        .arg("--noEmit")
        .status()
        .expect("TypeScript 7 compiler is required; run npm ci");
    assert!(status.success(), "Worker UI TypeScript compilation failed");
    let svelte_check = manifest.join("../../node_modules/.bin/svelte-check");
    let status = Command::new(svelte_check)
        .arg("--tsconfig")
        .arg(manifest.join("ui/tsconfig.json"))
        .arg("--tsgo")
        .arg("--fail-on-warnings")
        .status()
        .expect("svelte-check is required; run npm ci");
    assert!(status.success(), "Worker UI Svelte check failed");
    let vite = manifest.join("../../node_modules/.bin/vite");
    for entry in ["login", "vault", "admin", "complete"] {
        let status = Command::new(&vite)
            .arg("build")
            .arg("--config")
            .arg(manifest.join("ui/vite.config.ts"))
            .env("MIKAKI_UI_ENTRY", entry)
            .env("MIKAKI_UI_OUTDIR", &output)
            .status()
            .expect("Vite is required; run npm ci");
        assert!(status.success(), "Worker UI Vite build failed: {entry}");
    }
}
