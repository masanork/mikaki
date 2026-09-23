# Direct dependency inventory

Snapshot: `2026-09-23` / commit `95165eb`

Runtime dependency source: 583,331 lines total (108,465 npm, 474,866 Rust; 19 npm packages, 72 Rust crates in the resolved runtime graph).

| Scope | Count | Direct dependencies |
|---|---:|---|
| Rust runtime | 13 | `base64`, `ciborium`, `der`, `ed25519-dalek`, `p256`, `p384`, `rsa`, `serde`, `serde_json`, `sha1`, `sha2`, `wasm-bindgen`, `x509-cert` |
| Rust build | 0 | — |
| Rust development | 8 | `base64`, `ciborium`, `p256`, `rusqlite`, `serde_json`, `sha2`, `tiny_http`, `wasm-bindgen-test` |
| npm runtime | 2 | `jose`, `svelte` |
| npm development | 9 | `@playwright/test`, `@sveltejs/vite-plugin-svelte`, `@typescript/native`, `prettier`, `prettier-plugin-svelte`, `svelte-check`, `typescript`, `vite`, `wrangler` |

The inventory lists direct manifest dependencies; the source-line total includes transitive packages resolved for the runtime.
