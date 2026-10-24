# crypto-bigint timing advisory disposition

Reviewed on 2026-10-24 for [RUSTSEC-2026-0387](https://github.com/RustSec/advisory-db/blob/main/crates/crypto-bigint/RUSTSEC-2026-0387.md).
The advisory concerns secret-dependent timing in integer arithmetic. Its patched
range is `>=0.7.6`; it does not identify a compatible fix for the 0.5 series.

Every graph that can resolve the current series now pins `crypto-bigint` 0.7.6
and `ctutils` 0.4.5. This includes product Worker, identity, Wallet and MLS
operations. The three remaining 0.5.5 records are accepted only for the usage
below, until **2026-11-07 00:00 UTC**. They are not patched dependencies.

| Exact lock graph                                | Reviewed dependency and usage                                                                                                                                                                                                                                                     |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/mikaki-client/src-tauri/Cargo.lock`       | `openidconnect` 4.0.1 requires `p256`/`p384` 0.13. `native_oidc.rs` and `mobile_oidc.rs` use its client for discovery, PKCE exchange and public ID Token signature/claims verification. They do not supply a private signing key or perform ECDH through this library.            |
| `design/probes/jose/Cargo.lock`                 | `jsonwebtoken` 11.1.0's RustCrypto provider requires `p256`/`p384` 0.13. `design/probes/jose/src/lib.rs` exposes only `DecodingKey`/`decode` public signature verification. It neither imports signing APIs nor accepts private keys. This is an isolated evaluation package.     |
| `design/probes/native-identity-http/Cargo.lock` | The binary is `apps/mikaki-client/src-tauri/examples/oid4vp_transport.rs`, which compiles `identity_issuance/presentation_transport.rs`. `openidconnect` supplies the `reqwest` HTTP re-export. There is no private-key operation through its legacy elliptic-curve dependencies. |

The app's separate direct dependency is pinned to `p256 =0.14.0`. Wallet
`HolderKey` signing, native issuance and ECDH use that dependency, resolving
`crypto-bigint` 0.7.6. Android hardware signing uses Android Keystore. The legacy
OIDC verifier does not receive these private keys. Public signature operands do
not establish the secret-integer exposure described by this advisory; this is a
source-based usage assessment, not a proof about arbitrary future library use.

Reproduce the dependency review with:

```sh
cargo tree --locked --manifest-path apps/mikaki-client/src-tauri/Cargo.toml -i crypto-bigint@0.5.5
cargo tree --locked --manifest-path apps/mikaki-client/src-tauri/Cargo.toml -i crypto-bigint@0.7.6
cargo tree --locked --manifest-path design/probes/jose/Cargo.toml -i crypto-bigint@0.5.5
cargo tree --locked --manifest-path design/probes/native-identity-http/Cargo.toml -i crypto-bigint@0.5.5
```

The exact graph/version/advisory dispositions are in
[the dependency policy](../.github/dependency-advisory-exceptions.json).
Other versions, graphs or advisories remain blocking. Remove these entries when
the upstream OIDC/JOSE dependencies support a patched version. Any private-key
signing, key agreement or other secret-integer use through the legacy dependency
requires remediation before release; this disposition does not authorize it.
