# Direct dependency inventory

Snapshot: `2026-09-23` / commit `b4af4f9`

Runtime dependency source: 1,146,704 lines total (108,465 npm, 1,038,239 Rust; 19 npm packages, 131 Rust crates in the resolved runtime graph).

| Scope | Count | Direct dependencies |
|---|---:|---|
| Rust runtime | 21 | `base64`, `ciborium`, `der`, `ed25519-dalek`, `futures-util`, `js-sys`, `p256`, `p384`, `rsa`, `serde`, `serde_json`, `serde_urlencoded`, `sha1`, `sha2`, `subtle`, `url`, `wasm-bindgen`, `wasm-bindgen-futures`, `web-sys`, `worker`, `x509-cert` |
| Rust build | 0 | — |
| Rust development | 8 | `base64`, `ciborium`, `p256`, `rusqlite`, `serde_json`, `sha2`, `tiny_http`, `wasm-bindgen-test` |
| npm runtime | 2 | `jose`, `svelte` |
| npm development | 9 | `@playwright/test`, `@sveltejs/vite-plugin-svelte`, `@typescript/native`, `prettier`, `prettier-plugin-svelte`, `svelte-check`, `typescript`, `vite`, `wrangler` |

The inventory lists direct manifest dependencies; the source-line total includes transitive packages resolved for the runtime.
