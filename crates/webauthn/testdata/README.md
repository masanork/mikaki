# Independent signature fixtures

`signatures.json` was generated on 2026-09-22 with Node's `node:crypto`
(OpenSSL backend): `generateKeyPairSync('rsa', {modulusLength: 2048})`,
`generateKeyPairSync('ed25519')`, and `sign` with SHA-256, SHA-1, and null
respectively. The message is stored as base64url alongside each signature.
Only public JWKs and signatures are retained; private keys were not saved.
These fixtures exercise RSA/Ed25519 verification independently of the Rust
implementation on both native and Wasm. They do not establish full WebAuthn
or certificate conformance.


attestations.jsonはgenerate_attestations.py（Python cryptography 48.0.0 / cbor2）で独立生成した公開fixture。packed、U2F、TPM、MDS JWTとCRLの正常・改変・失効・期限切れを含む。RSA/EC秘密鍵は生成処理のメモリーだけに存在し、保存しない。時刻はContextで2026-09-22へ固定し、テストが壁時計に依存しない。通常CIにPython依存の追加は不要。
