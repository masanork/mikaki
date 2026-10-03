# Browser SQLite thread-search probe

Disposable, synthetic-only qualification of the [thread-search proposal](../../../docs/vault-thread-search.md). This is not the production Vault UI, a WebAuthn unlock, a messaging implementation or an authorization service. Its ephemeral AES-GCM key and fictional AAD exercise snapshot mechanics; they do not define the production Vault envelope/key hierarchy. No real databases, messages or accounts are accessed.

## Reproduce

From the repository root, install the existing development dependencies (`npm ci`). Then:

```sh
cd design/probes/vault-search
npm ci --ignore-scripts
../../../node_modules/.bin/playwright install chromium firefox webkit
npm run probe
```

Playwright normally stores browser downloads in its user cache. To use a different cache, set `PLAYWRIGHT_BROWSERS_PATH` to the same directory for both install and probe commands. The runner serves a fixed asset allowlist on loopback at an ephemeral port, closes its server/browsers and writes ignored `report.json`. The committed `results.json` records one successful development-machine run; regeneration does not overwrite it automatically. SQLite WASM is pinned separately from production dependencies with its own lockfile and is never fetched from a CDN by the browser.

## What the probe exercises

- SQLite FTS5/trigram in a dedicated browser Web Worker, with parameterized literal predicates for Japanese short terms, AND combinations, NFKC/lowercase normalization, quotes, percent signs and supplementary Unicode characters.
- A synthetic selected-thread projection, rejected out-of-scope filters, edits, retractions represented by edits, deletes and FTS rebuild. This is a local allowlist test, not proof of owner/session or remote-agent authorization.
- Consistent in-memory image export, AES-GCM encryption/authentication, tampered ciphertext and wrong-AAD rejection, decryption and read-only deserialization with identical matching anchors. The generated database is trusted synthetic input; hostile SQLite image handling is not qualified.
- Closed-database search rejection, Worker termination, pagehide cleanup and cancellation of an active request without a late DOM result. No physical memory-erasure guarantee is made. Visibility masking closes this disposable probe; the production resume/lease policy remains separate.
- Empty localStorage, sessionStorage, IndexedDB and CacheStorage in isolated browser contexts, and OPFS directory inspection where available. An unavailable storage-inspection API is recorded, not counted as a successful inspection. All observed browser requests are loopback assets; there is no query API or telemetry.
- 1,000 / 10,000 / 100,000 repeated fictional Japanese messages, with 15 timed queries per term (nearest-rank p50/p95), image size, Worker runtime initialization, initial index build, export, encryption, restore and WASM heap capacity. The missing one-character query `無` forces a short-term scan through the corpus.

## Interpretation limits

Chromium, Firefox and Playwright WebKit are desktop engine builds. A 390px viewport changes layout only; it does not measure iPhone/Android hardware, Safari product behavior, Passkey availability or mobile memory pressure. The repetitive ~200-character fixture is not a representative user corpus. Results are a single local run, not a service-level target; a 15-sample p95 is the largest sample. FTS image size includes original/normalized text and FTS structures, not just the index. The WASM heap value is its allocated capacity at the end of the probe, not peak process/JavaScript memory; export and crypto buffers increase total memory further.

Restore timing includes decrypt/deserialization and a verifying search, but excludes network download, Passkey/key unwrap and a fresh Worker runtime startup. The probe makes no claims about production envelope migration, snapshot freshness/rollback, concurrent sync, malformed images, import deletion suppression, durable offline custody, grants, external AI processing or sender-authenticated E2EE.

The measurements inform a bounded first archive and snapshot partitioning. Real-device memory, peak allocation, cancellation deadlines and synchronization contracts remain adoption gates before production integration.
