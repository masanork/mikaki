# Worker resource byte budgets

Measured locally on 2026-10-03 against source `7097756a4772da03f163ae972167a020fbfb57ab` using the pinned release Worker build. These are regression guardrails, not a page-speed target or a Cloudflare platform limit.

`npm run check:worker-budgets` starts the actual built Rust OP in a disposable local harness and reads the seven public JavaScript/CSS asset responses. It checks HTTP status and MIME type, rejects an empty body, and hashes the measured bytes. It also measures both built **server-side** Wasm modules; those modules are not downloaded by the browser. No account login, schema migration, Vault object access, or production call is needed.

| Resource | Baseline raw bytes | Baseline gzip estimate | Raw limit | gzip limit |
| --- | ---: | ---: | ---: | ---: |
| `/login/login.js` | 82,693 | 25,839 | 103,424 | 32,768 |
| `/login/login.css` | 8,880 | 2,742 | 11,264 | 4,096 |
| `/ui/product.css` | 38,487 | 7,906 | 48,128 | 10,240 |
| `/ui/session-events.js` | 9,561 | 3,614 | 12,288 | 5,120 |
| `/enroll/complete.js` | 72,999 | 23,183 | 92,160 | 29,696 |
| `/admin/admin.js` | 76,256 | 24,293 | 96,256 | 30,720 |
| `/vault/vault.js` | 252,142 | 69,958 | 315,392 | 88,064 |
| `crates/worker/build/index_bg.wasm` | 2,944,875 | 977,689 | 3,681,280 | 1,222,656 |
| `crates/userinfo-claim-worker/build/index_bg.wasm` | 642,724 | 216,532 | 803,840 | 271,360 |

Each initial limit allows 25% growth from this baseline, rounded up to the next KiB. Both raw and gzip limits are enforced independently. Deliberate changes beyond a limit need an explicit update to [the budget file](../scripts/worker-budgets.json) with reviewed new measurements; CI never raises limits automatically. Limits are not minimum sizes or a reason to grow a bundle.

The gzip value uses local level-9 compression. It does not measure the server's HTTP Content-Encoding, actual network transfer, browser parsing, execution, or memory use. Individual asset budgets do not cover HTML, images, every route, total page requests, the landing website, or the native client. Slow-network/device testing and endpoint abuse limits remain separate work.

The command requires freshly built Workers and rejects an OP whose embedded source commit differs from the checkout. Local dirty builds are allowed and recorded; the existing release inventory and promotion checks enforce clean source for production. `artifacts/worker-budgets.json` retains the build/check source state, measured hashes, byte counts, limits and failures; `worker-budgets.md` provides a CI summary. The ordinary verification job and the separate attested release build both run the gate, so instrumented PR bytes and the actual release build are checked independently. Reports are retained with their existing CI artifacts.

Run after building both Workers:

```sh
npm run test:worker-budgets
npm run check:worker-budgets
```

Unit regressions cover equality at the limit, independent over-limit rejection, invalid limits, empty inputs, and missing or duplicate resource coverage. The command itself checks actual built responses; it does not infer their size from source files or unused build-directory assets.
