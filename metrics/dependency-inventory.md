# Direct dependency inventory

Snapshot: `2026-10-04` / commit `a672274`

Runtime dependency source: 1,431,783 lines total (356,708 npm, 1,075,075 Rust; 117 npm packages, 156 Rust crates in the resolved runtime graph).

| Scope | Count | Direct dependencies |
|---|---:|---|
| Rust runtime | 27 | `aes-gcm`, `base64`, `ciborium`, `der`, `ed25519-dalek`, `futures-util`, `hpke`, `js-sys`, `k256`, `ml-kem`, `p256`, `p384`, `p521`, `rsa`, `serde`, `serde_json`, `serde_urlencoded`, `sha1`, `sha2`, `subtle`, `url`, `wasm-bindgen`, `wasm-bindgen-futures`, `web-sys`, `worker`, `x509-cert`, `zeroize` |
| Rust build | 0 | — |
| Rust development | 9 | `base64`, `ciborium`, `p256`, `rusqlite`, `serde_json`, `serde_urlencoded`, `sha2`, `tiny_http`, `wasm-bindgen-test` |
| npm runtime | 6 | `@modelcontextprotocol/sdk`, `@noble/post-quantum`, `@sqlite.org/sqlite-wasm`, `jose`, `svelte`, `zod` |
| npm development | 20 | `@cloudflare/workers-types`, `@inlang/paraglide-js`, `@inlang/plugin-message-format`, `@jridgewell/trace-mapping`, `@playwright/test`, `@sorane/cli`, `@sorane/core`, `@sorane/okf`, `@sveltejs/vite-plugin-svelte`, `@types/node`, `@typescript/native`, `esbuild`, `prettier`, `prettier-plugin-svelte`, `smol-toml`, `svelte-check`, `tsx`, `typescript`, `vite`, `wrangler` |

The inventory lists direct manifest dependencies; the source-line total includes transitive packages resolved for the runtime.
