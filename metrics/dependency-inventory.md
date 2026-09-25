# Direct dependency inventory

Snapshot: `2026-09-25` / commit `b83219b`

Runtime dependency source: 1,201,358 lines total (139,454 npm, 1,061,904 Rust; 23 npm packages, 154 Rust crates in the resolved runtime graph).

| Scope | Count | Direct dependencies |
|---|---:|---|
| Rust runtime | 25 | `aes-gcm`, `base64`, `ciborium`, `der`, `ed25519-dalek`, `futures-util`, `hpke`, `js-sys`, `ml-kem`, `p256`, `p384`, `rsa`, `serde`, `serde_json`, `serde_urlencoded`, `sha1`, `sha2`, `subtle`, `url`, `wasm-bindgen`, `wasm-bindgen-futures`, `web-sys`, `worker`, `x509-cert`, `zeroize` |
| Rust build | 0 | — |
| Rust development | 8 | `base64`, `ciborium`, `p256`, `rusqlite`, `serde_json`, `sha2`, `tiny_http`, `wasm-bindgen-test` |
| npm runtime | 3 | `@noble/post-quantum`, `jose`, `svelte` |
| npm development | 15 | `@cloudflare/workers-types`, `@inlang/paraglide-js`, `@inlang/plugin-message-format`, `@playwright/test`, `@sveltejs/vite-plugin-svelte`, `@types/node`, `@typescript/native`, `esbuild`, `prettier`, `prettier-plugin-svelte`, `smol-toml`, `svelte-check`, `typescript`, `vite`, `wrangler` |

The inventory lists direct manifest dependencies; the source-line total includes transitive packages resolved for the runtime.
