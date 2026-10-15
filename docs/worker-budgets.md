# Worker bundle limits and resource measurements

`npm run check:worker-budgets` enforces **64 MiB (67,108,864 bytes) of
uncompressed code per complete Worker bundle**. Individual asset/module raw
sizes and local level-9 gzip estimates are recorded and compared with warning
thresholds. Exceeding those thresholds emits a GitHub Actions warning and does
not fail CI.

Cloudflare removed the compressed-size limit on September 4, 2026. Free and Paid
Workers both allow 64 MiB uncompressed, including the JavaScript entry point and
all uploaded modules such as Wasm. See the [official change](https://developers.cloudflare.com/changelog/post/2026-09-04-increased-worker-size-limit/)
and [current limits](https://developers.cloudflare.com/workers/platform/limits/#worker-size).

## Complete bundle gate

The check uses the installed Wrangler's `deploy --dry-run` to bundle the OP's
service entry point and the Claim Worker's entry point into fresh directories.
It reads the multipart upload emitted with `--outfile` and sums the entry
JavaScript and every additional code/data module. Metadata, multipart framing
and source maps are excluded by their field types. Browser assets already
embedded in the Wasm are not counted again. Each Worker is checked separately, so two valid Workers may
together exceed 64 MiB.

The same counter and 64 MiB limit run during release upload preparation and
reverification, against the frozen OP, Claim and checkpoint bundles. Release
archive/member hashes, source identity and migrations remain independently
verified. No upload or deployment occurs during these checks.

On 2026-10-15 the local source-based OP service bundle measured **9,065,834
bytes (8.64 MiB)** and Claim measured **748,631 bytes (0.71 MiB)**. Both are well
below 64 MiB. Release checks measure the actual frozen production entries again;
these local values do not substitute for release evidence.

A disposable local rehearsal of frozen built archives also passed preparation
and reverification: OP **9,099,939**, Claim **748,667** and checkpoint **43,078**
bytes. This used the explicit dirty-source local mode and was not eligible for
promotion. The multipart upload digest is verified alongside the emitted-file
hashes and its recomputed code-size total.

## Resource growth warnings

The check also starts the actual built Rust OP in a disposable local harness
and reads its public JavaScript/CSS/Wasm responses. HTTP status, MIME type,
nonempty bodies and the served source commit remain mandatory checks. Both
built server Wasm modules are measured separately; they are not browser
downloads. No account login, schema migration, Vault object access or
production call is needed.

[scripts/worker-budgets.json](../scripts/worker-budgets.json) contains the
per-resource raw/gzip **warning thresholds**, retained from the existing
measurements. They are neither Cloudflare limits nor size targets. A warning
is a prompt to examine growth; normal gzip variation does not require a
threshold change or block a release.

For example, the combined workspace snapshots and Passkey handoff Vault script
has **342,007 raw bytes** and the same SHA-256 on local macOS / Node 26.11.1 and
Ubuntu / Node 26.10.0 CI. Its gzip estimate is **97,871** locally and **98,339**
in the [CI measurement](https://github.com/masanork/mikaki/actions/runs/38645584100/job/116131487988).
The former hard ceiling of 98,304 bytes stopped that job by 35 bytes before
contract tests ran. The revised policy treats even an over-threshold estimate
as a warning; the complete uncompressed Worker determines the size gate.

## Reports and verification

`artifacts/worker-budgets.json` (schema version 2) contains the source identity,
served Worker source state, complete upload module hashes/totals, the 64 MiB
limit, individual resource measurements, warning thresholds, warnings and hard
failures. `artifacts/worker-budgets.md` summarizes both tables and warnings for
CI. Wrangler output and its emitted files are retained under
`artifacts/worker-budget-bundles/`.

The command rejects stale built Workers. Local dirty builds are recorded;
release inventory and promotion continue to require clean, matching source.
Missing/duplicate resources or Worker bundles, invalid measurements, a failed
Wrangler build, unavailable responses or malformed Wasm still fail validation.

Run after building the OP and Claim Workers:

```sh
npm run test:worker-budgets
npm run check:worker-budgets
```

Tests cover warning-only asset growth, per-Worker 64 MiB boundaries, aggregate
entry/module accounting, source-map exclusion, incomplete/duplicate coverage
and release size-record integrity. The same gate runs for ordinary CI and the
separate release candidate build.

Startup time and runtime memory remain separate constraints: [Cloudflare's
limits](https://developers.cloudflare.com/workers/platform/limits/) specify one
second of startup time and 128 MB of memory per isolate, including JS and Wasm
allocations. gzip estimates do not measure wire compression, parsing, execution,
startup time or memory use.
