# Direct dependency inventory

Snapshot: `2026-09-23` / commit `4750ee7`

Runtime dependency source: 1,151,273 lines total (108,465 npm, 1,042,808 Rust; 19 npm packages, 137 Rust crates in the resolved runtime graph).

| Scope | Count | Direct dependencies |
|---|---:|---|
| Rust runtime | 23 | `base64`, `ciborium`, `der`, `ed25519-dalek`, `futures-util`, `js-sys`, `ml-kem`, `p256`, `p384`, `rsa`, `serde`, `serde_json`, `serde_urlencoded`, `sha1`, `sha2`, `subtle`, `url`, `wasm-bindgen`, `wasm-bindgen-futures`, `web-sys`, `worker`, `x509-cert`, `zeroize` |
| Rust build | 0 | — |
| Rust development | 9 | `base64`, `ciborium`, `hpke`, `p256`, `rusqlite`, `serde_json`, `sha2`, `tiny_http`, `wasm-bindgen-test` |
| npm runtime | 2 | `jose`, `svelte` |
| npm development | 12 | `@inlang/paraglide-js`, `@inlang/plugin-message-format`, `@playwright/test`, `@sveltejs/vite-plugin-svelte`, `@types/node`, `@typescript/native`, `prettier`, `prettier-plugin-svelte`, `svelte-check`, `typescript`, `vite`, `wrangler` |

The inventory lists direct manifest dependencies; the source-line total includes transitive packages resolved for the runtime.
