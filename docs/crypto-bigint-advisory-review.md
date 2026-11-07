# crypto-bigint timing advisory disposition

Re-reviewed on 2026-11-07 for [RUSTSEC-2026-0387](https://github.com/RustSec/advisory-db/blob/main/crates/crypto-bigint/RUSTSEC-2026-0387.md).
The advisory concerns secret-dependent timing in integer arithmetic. Its patched
range is `>=0.7.6`; it does not identify a compatible fix for the 0.5 series.

Product Worker, identity, Wallet and MLS graphs pin `crypto-bigint` 0.7.6
and `ctutils` 0.4.5. The native OIDC and HTTP probe graphs now use openidconnect 4.1.0,
which removes their 0.5.5 dependency. The remaining 0.5.5 record is accepted
only for the isolated JOSE probe below, until **2026-11-14 00:00 UTC**. It is
not a patched dependency.

| Exact lock graph                                | Reviewed dependency and usage                                                                                                                                                                                                                                                     |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `design/probes/jose/Cargo.lock`                 | `jsonwebtoken` 11.1.0's RustCrypto provider requires `p256`/`p384` 0.13. `design/probes/jose/src/lib.rs` exposes only `DecodingKey`/`decode` public signature verification. It neither imports signing APIs nor accepts private keys. This is an isolated evaluation package.     |

The app's separate direct dependency is pinned to `p256 =0.14.0`. Wallet
`HolderKey` signing, native issuance and ECDH use that dependency, resolving
`crypto-bigint` 0.7.6. Android hardware signing uses Android Keystore. The JOSE
probe does not receive these private keys. Public signature operands do
not establish the secret-integer exposure described by this advisory; this is a
source-based usage assessment, not a proof about arbitrary future library use.

Reproduce the dependency review with:

```sh
cargo tree --locked --manifest-path apps/mikaki-client/src-tauri/Cargo.toml -i crypto-bigint@0.7.6
cargo tree --locked --manifest-path design/probes/jose/Cargo.toml -i crypto-bigint@0.5.5
cargo tree --locked --manifest-path design/probes/native-identity-http/Cargo.toml -i crypto-bigint
```

The exact graph/version/advisory dispositions are in
[the dependency policy](../.github/dependency-advisory-exceptions.json).
Other versions, graphs or advisories remain blocking. Remove the remaining entry when
the JOSE dependency supports a patched version. Any private-key
signing, key agreement or other secret-integer use through the legacy dependency
requires remediation before release; this disposition does not authorize it.
