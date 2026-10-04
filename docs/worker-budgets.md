# Worker resource byte budgets

Measured locally on 2026-10-03 against source `7097756a4772da03f163ae972167a020fbfb57ab` using the pinned release Worker build. These are regression guardrails, not a page-speed target or a Cloudflare platform limit.

`npm run check:worker-budgets` starts the actual built Rust OP in a disposable local harness and reads the public JavaScript/CSS/WASM asset responses. It checks HTTP status and MIME type, rejects an empty body, and hashes the measured bytes. It also measures both built **server-side** Wasm modules; those modules are not downloaded by the browser. No account login, schema migration, Vault object access, or production call is needed.

| Resource | Baseline raw bytes | Baseline gzip estimate | Raw limit | gzip limit |
| --- | ---: | ---: | ---: | ---: |
| `/login/login.js` | 82,693 | 25,839 | 103,424 | 32,768 |
| `/login/login.css` | 8,880 | 2,742 | 11,264 | 4,096 |
| `/ui/product.css` | 38,487 | 7,906 | 48,128 | 10,240 |
| `/ui/session-events.js` | 9,561 | 3,614 | 12,288 | 5,120 |
| `/enroll/complete.js` | 72,999 | 23,183 | 92,160 | 29,696 |
| `/admin/admin.js` | 76,256 | 24,293 | 96,256 | 30,720 |
| `/vault/vault.js` | 322,557 | 86,413 | 323,584 | 91,136 |
| `/vault/search.js` | 220,030 | 67,660 | 245,760 | 73,728 |
| `/vault/sqlite3.wasm` | 868,907 | 402,022 | 900,000 | 420,000 |
| `crates/worker/build/index_bg.wasm` | 5,689,749 | 2,063,146 | 8,388,608 | 3,145,728 |
| `crates/userinfo-claim-worker/build/index_bg.wasm` | 642,724 | 216,532 | 803,840 | 271,360 |

Each initial limit allows 25% growth from this baseline, rounded up to the next KiB. Both raw and gzip limits are enforced independently. Deliberate changes beyond a limit need an explicit update to [the budget file](../scripts/worker-budgets.json) with reviewed new measurements; CI never raises limits automatically. Limits are not minimum sizes or a reason to grow a bundle.

## Identity integration and Cloudflare ceilings

Remeasured on 2026-10-04 after identity integration on `feat/identity-wallet-qualification`. The OP Wasm ceiling is now **8 MiB raw / 3 MiB gzip estimate**, with approximately 47% / 52% headroom over the measured identity implementation. These are reviewed project regression budgets, not Cloudflare upload limits. Other resource and claim-Worker budgets remain unchanged. They supersede the original OP limits of 4,500,000 / 1,600,000 bytes and its original growth rule.

As of [Cloudflare's September 4, 2026 change](https://developers.cloudflare.com/changelog/post/2026-09-04-increased-worker-size-limit/), Free and Paid Workers allow **64 MiB uncompressed for the entire upload bundle**, and there is no compressed-size platform limit. The [current limits documentation](https://developers.cloudflare.com/workers/platform/limits/#worker-size) makes the full-bundle scope explicit. A single Wasm-module measurement is not a complete upload measurement: the JavaScript entry point and other uploaded modules also count. Browser assets embedded in the server Wasm already contribute to its measured bytes; adding their served sizes again would double-count them.

Pinned Wrangler 4.144.0 `deploy --dry-run --config crates/worker/wrangler.jsonc --outdir artifacts/worker-budget-upload` reported **5,608.94 KiB uncompressed / 2,031.72 KiB gzip** for the complete OP bundle (about 5.48 MiB raw, 8.6% of the platform ceiling). This local dry run uploads nothing. Repeat it when uploaded modules or bundling configuration change; production preparation also retains its separate bundle-validation step. Keep the much smaller internal Wasm budget to detect growth rather than setting it to the platform maximum.

The [startup limit is one second](https://developers.cloudflare.com/workers/platform/limits/#worker-startup-time) and isolate memory is limited to **128 MB**. Wasm file size is not runtime memory usage: linear memory, allocations and initialization must be assessed separately. Dry-run size success does not qualify startup, memory or request CPU consumption. `wrangler check startup` can profile local startup; Cloudflare-reported `startup_time_ms` from a separate version upload/deployment is platform evidence. No such upload or production activation is performed by this budget change. Continue performance and abuse-limit qualification before enabling real-card verification in production.

The pinned CLI required `wrangler check startup --args='--config crates/worker/wrangler.jsonc' --outfile artifacts/identity-worker-startup.cpuprofile` to pass the configuration to its build subprocess. The local run recorded a 13.5 ms profile window, 5.1 ms active time and only three samples. This is a sparse local profile, not a Cloudflare startup-time qualification or memory measurement. The revised byte-budget check and its three existing boundary/coverage tests passed; the rechecked OP gzip estimate was 2,063,148 bytes (compression varies slightly with embedded build identity).

The four Vault/search rows above were remeasured for the SQLite search integration on 2026-10-03 (local dirty release build based on `40bff2b`). Search JS and pinned SQLite WASM are separate, lazy responses; profile unlock downloads neither. The small Vault limit increase covers the lifecycle/search UI adapter. The server Wasm increase embeds these public runtime assets in the existing attested Worker artifact, so no separate mutable bucket or asset deployment is required. Search uses esbuild rather than Vite library mode, which otherwise duplicates the WASM as inline base64 in JavaScript. These feature-specific limits replace the original 25% rule for those rows; other baseline rows retain their original measurements. gzip remains a local estimate, not observed transfer size.

The gzip value uses local level-9 compression. It does not measure the server's HTTP Content-Encoding, actual network transfer, browser parsing, execution, or memory use. Individual asset budgets do not cover HTML, images, every route, total page requests, the landing website, or the native client. Slow-network/device testing and endpoint abuse limits remain separate work.

The command requires freshly built Workers and rejects an OP whose embedded source commit differs from the checkout. Local dirty builds are allowed and recorded; the existing release inventory and promotion checks enforce clean source for production. `artifacts/worker-budgets.json` retains the build/check source state, measured hashes, byte counts, limits and failures; `worker-budgets.md` provides a CI summary. The ordinary verification job and the separate attested release build both run the gate, so instrumented PR bytes and the actual release build are checked independently. Reports are retained with their existing CI artifacts.

Run after building both Workers:

```sh
npm run test:worker-budgets
npm run check:worker-budgets
```

Unit regressions cover equality at the limit, independent over-limit rejection, invalid limits, empty inputs, and missing or duplicate resource coverage. The command itself checks actual built responses; it does not infer their size from source files or unused build-directory assets.
