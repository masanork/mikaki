fn main() {
    // APDU methods are Rust-only; no JavaScript plugin commands or permissions.
    tauri_plugin::Builder::new(&[])
        .android_path("android")
        .build();
}
