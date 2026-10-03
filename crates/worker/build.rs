use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=GITHUB_SHA");
    println!("cargo:rerun-if-changed=migrations");
    println!("cargo:rerun-if-changed=../../branding");
    println!("cargo:rerun-if-changed=ui/BrandMark.svelte");
    println!("cargo:rerun-if-changed=ui/login.ts");
    println!("cargo:rerun-if-changed=ui/auth.css");
    println!("cargo:rerun-if-changed=ui/product.css");
    println!("cargo:rerun-if-changed=ui/ProductHeader.svelte");
    println!("cargo:rerun-if-changed=ui/logout.html");
    println!("cargo:rerun-if-changed=ui/vault.html");
    println!("cargo:rerun-if-changed=ui/vault.ts");
    println!("cargo:rerun-if-changed=ui/VaultSession.svelte");
    println!("cargo:rerun-if-changed=ui/VaultRouter.svelte");
    println!("cargo:rerun-if-changed=ui/OwnerVault.svelte");
    println!("cargo:rerun-if-changed=ui/vault-owner-crypto.ts");
    println!("cargo:rerun-if-changed=ui/vault-owner-session.ts");
    println!("cargo:rerun-if-changed=ui/vault-owner-store.ts");
    println!("cargo:rerun-if-changed=ui/vault-owner-record-store.ts");
    println!("cargo:rerun-if-changed=ui/vault-thread-archive.ts");
    println!("cargo:rerun-if-changed=ui/vault-lifecycle.ts");
    println!("cargo:rerun-if-changed=ui/vault-context.ts");
    println!("cargo:rerun-if-changed=ui/session-events.ts");
    println!("cargo:rerun-if-changed=ui/logout.ts");
    println!("cargo:rerun-if-changed=ui/Login.svelte");
    println!("cargo:rerun-if-changed=ui/Home.svelte");
    println!("cargo:rerun-if-changed=ui/WovenGate.svelte");
    println!("cargo:rerun-if-changed=ui/woven-gate.ts");
    println!("cargo:rerun-if-changed=ui/SessionCue.svelte");
    println!("cargo:rerun-if-changed=ui/LivingSeal.svelte");
    println!("cargo:rerun-if-changed=ui/seal-light.ts");
    println!("cargo:rerun-if-changed=ui/Admin.svelte");
    println!("cargo:rerun-if-changed=ui/admin.ts");
    println!("cargo:rerun-if-changed=ui/Complete.svelte");
    println!("cargo:rerun-if-changed=ui/complete.ts");
    println!("cargo:rerun-if-changed=ui/Vault.svelte");
    println!("cargo:rerun-if-changed=ui/AgentPanel.svelte");
    println!("cargo:rerun-if-changed=ui/AgentOAuth.svelte");
    println!("cargo:rerun-if-changed=ui/PasskeyTransfer.svelte");
    println!("cargo:rerun-if-changed=ui/OwnerNote.svelte");
    println!("cargo:rerun-if-changed=ui/vault-note.ts");
    println!("cargo:rerun-if-changed=ui/attribute-commit.ts");
    println!("cargo:rerun-if-changed=ui/agent-crypto.ts");
    println!("cargo:rerun-if-changed=ui/locale.ts");
    println!("cargo:rerun-if-changed=ui/vault-crypto.ts");
    println!("cargo:rerun-if-changed=ui/vault-recipient-envelope.ts");
    println!("cargo:rerun-if-changed=ui/recipient-directory.ts");
    println!("cargo:rerun-if-changed=ui/tsconfig.json");
    println!("cargo:rerun-if-changed=ui/vite.config.ts");
    println!("cargo:rerun-if-changed=../../project.inlang/settings.json");
    println!("cargo:rerun-if-changed=../../messages/ja.json");
    println!("cargo:rerun-if-changed=../../messages/en.json");
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("wasm32") {
        return;
    }
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let mut migrations = fs::read_dir(manifest.join("migrations"))
        .expect("Worker migrations directory")
        .map(|entry| {
            entry
                .expect("Worker migration entry")
                .file_name()
                .into_string()
                .expect("UTF-8 migration name")
        })
        .filter(|name| name.ends_with(".sql"))
        .collect::<Vec<_>>();
    migrations.sort();
    println!(
        "cargo:rustc-env=MIKAKI_LATEST_MIGRATION={}",
        migrations.last().expect("at least one Worker migration")
    );
    let repository = manifest.join("../..");
    let git_output = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(&repository)
            .output()
            .ok()
            .filter(|output| output.status.success())
    };
    let commit = git_output(&["rev-parse", "HEAD"])
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let clean = git_output(&[
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ])
    .is_some_and(|output| output.stdout.is_empty());
    if let (Some(expected), Some(actual)) = (env::var_os("GITHUB_SHA"), commit.as_deref()) {
        assert_eq!(
            expected.to_string_lossy(),
            actual,
            "GITHUB_SHA differs from checked-out source"
        );
    }
    println!(
        "cargo:rustc-env=MIKAKI_SOURCE_COMMIT={}",
        commit.unwrap_or_default()
    );
    println!("cargo:rustc-env=MIKAKI_SOURCE_CLEAN={clean}");
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
    println!("cargo:rerun-if-env-changed=MIKAKI_UI_COVERAGE");
    for entry in ["login", "vault", "admin", "complete", "logout"] {
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
