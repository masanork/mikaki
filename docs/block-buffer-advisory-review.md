# Legacy block-buffer advisory range review

Review date: 2026-10-30. This records a version-specific false-positive review, not an exception for an affected release or a claim that caught cryptographic panics are safe to ignore.

The [publisher's GHSA-qwgh-2vcv-g2f7](https://github.com/RustCrypto/utils/security/advisories/GHSA-qwgh-2vcv-g2f7) identifies the affected range as `>=0.11.0,<0.12.1`. The [aggregate advisory](https://github.com/advisories/GHSA-qwgh-2vcv-g2f7) initially reported `<0.12.1` without the lower bound, causing OSV to flag legacy `block-buffer 0.10.4` in four independently locked graphs. The GitHub advisory API was corrected at `2026-10-30T15:32:34Z` to `>= 0.11.0, < 0.12.1`; the subsequent full CI scan no longer reports these findings. The scanner correctly rejected the four obsolete exceptions, which have now been removed.

The reported bug requires the cursor stored inside the data buffer. The immutable [0.10.4 source](https://docs.rs/crate/block-buffer/0.10.4/source/src/lib.rs) instead stores `buffer` and `pos: u8` separately and predates `ReadBuffer`. Its `src/lib.rs` SHA-256 is `b437252d389042d894b1ef17859b043e827d2bd2a1bca4b5311c67dff565274d`.

The [executable probe](../scripts/block-buffer-advisory.test.ts) compiles the exact `=0.10.4` package in a disposable project and runs the publisher's eager-buffer caught-panic scenario. After the compression callback panics, the cursor remains 2 and the subsequent bounded write advances it to 3. This verifies the relevant legacy invariant; it is not Miri qualification or a broad cryptographic audit.

```sh
node --test scripts/block-buffer-advisory.test.ts
node --test scripts/check-dependency-advisories.test.ts
```

The removed dispositions covered only version `0.10.4`, that exact advisory, and these graphs:

- `apps/mikaki-client/plugins/identity-proximity/Cargo.lock`
- `apps/mikaki-client/src-tauri/Cargo.lock`
- `design/probes/jose/Cargo.lock`
- `design/probes/native-identity-http/Cargo.lock`

The four temporary exceptions were removed before their 2026-11-20 expiry. No version of `block-buffer` is exempted in the [current dispositions](../.github/dependency-advisory-exceptions.json). The scanner still requires complete coverage of every tracked lockfile, rejects unknown findings and expired exceptions, and fails on stale exceptions when the aggregate range is corrected. Legacy dependencies and the separate crypto-bigint review remain independent migration work.
