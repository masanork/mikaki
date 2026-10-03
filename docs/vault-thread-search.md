# Encrypted thread archives and SQLite search

**Status:** integrated browser search, 2026-10-03. The v2 workspace stores encrypted imported archives and lazily builds a local SQLite FTS5 projection when the owner searches. It extends the [Vault product model](vault-product-model.md).

## Implemented search foundation

The [projection](../crates/worker/ui/vault-thread-search.ts), [Worker protocol](../crates/worker/ui/vault-thread-search-worker.ts) and [client](../crates/worker/ui/vault-thread-search-client.ts) accept a complete snapshot of already authenticated/decrypted archive records. Each snapshot is bounded to 256 unique records, 200 messages per archive and 24,000 encoded JSON bytes per archive. Titles and messages are separate items. Hits retain record revision and a zero-based message position (`-1` for the title), so a caller can validate the current revision before navigating to a message. [Excerpts](../crates/worker/ui/vault-thread-search-excerpt.ts) include the earliest matching body term with up to 40 preceding scalar values and at most 240 scalar values total, including omission markers. Short bodies remain unchanged. Speaker-only matches show the body prefix and the speaker label in the result.

The excerpt mapper preserves original grapheme segments only when their reconstructed normalization exactly equals whole-message NFKC/lowercase normalization. Context-sensitive case conversion or an oversized grapheme falls back to a bounded window of derived normalized text. This avoids pretending normalized offsets directly identify original characters. It does not split surrogate pairs; a fallback may cut a grapheme. Excerpts are escaped text, with no HTML highlighting, and do not replace the original message shown on navigation. Unicode normalization can change string length and composition; see [UAX #15](https://www.unicode.org/reports/tr15/). Tests cover late Japanese matches, compatibility characters, combining marks, family emoji, context-sensitive Greek casing and oversized graphemes.

Text uses NFKC and lowercase normalization. Queries use literal AND semantics, at most eight terms and 256 UTF-16 units. Three-codepoint terms use case-sensitive trigram FTS over already normalized text; all terms also use parameterized literal `instr` predicates. Short Japanese terms, quotes, wildcard characters and FTS operator words remain literals. Selected thread IDs must exist in the current projection and restrict the SQL before its 51-row limit. Stable thread/message order avoids corpus-wide ranking statistics; the result returns at most 50 hits with an explicit truncation flag. Coverage reports only indexed snapshot thread/message counts, not server-wide completeness or current authority.

A replacement closes the previous database first. Invalid snapshots or failed builds leave the projection unavailable rather than exposing stale results. The client allows only one outstanding request, terminates its Worker on abort, pagehide, hidden visibility, runtime/message errors or a 15-second timeout, and rejects the pending request. Reopening requires a new client and fresh authorized snapshot. Termination bounds plaintext lifetime; it does not guarantee physical memory erasure. The Worker receives no owner key or authority to fetch Vault records. The caller must still supply the owner lease's abort signal, dispose on lease replacement and validate record revisions/authority before using results.

Run `npm ci --prefix design/probes/vault-search` then `npm run test:vault-thread-search`. The [regression](../local/conformance/vault-thread-search-browser.test.ts) serves pinned SQLite 3.53.4-build2 locally with a restrictive CSP, checks real FTS results and exact anchors, scope, normalization, replacement/deletion, invalid/bounded requests, truncation, abort/pagehide and absence of localStorage/sessionStorage/IndexedDB/CacheStorage/OPFS data. CI installs and audits the isolated runtime package. This is distinct from the earlier synthetic performance probe.

The [search UI](../crates/worker/ui/ThreadSearch.svelte) loads [the bootstrap](../crates/worker/ui/search.ts) at `/vault/search.js` and the pinned binary at `/vault/sqlite3.wasm` only for a nonempty search. Both public assets are embedded in the attested Rust Worker build and served with correct MIME types, nosniff and no-store. The main Vault CSP adds only `worker-src 'self'`; the search Worker response permits WASM compilation with `'wasm-unsafe-eval'`. There are no inline scripts, eval permission on the Vault page, external runtime downloads, persistent indexes or plaintext asset generation. SQLite's upstream license/version notices survive minification; the wrapper package's Apache-2.0 license is recorded in the pinned npm dependency inventory.

The UI offers all loaded conversations or one selected conversation. Selection restricts the SQL before its result limit; changing selection reuses the index but invalidates pending results. Removing the selected conversation clears both selection and query, so deletion cannot silently broaden a search. The UI debounces input and serializes requests, reuses the in-memory index across queries, rejects obsolete query results, and discards the Worker/index/results when archive state or mutation-busy state changes. It verifies live owner/root authority before searching and before displaying results. Result navigation rechecks owner authority and the current loaded record revision, then focuses the exact message or title. The search covers the bounded, loaded archive snapshot, not records changed remotely since its last reload. There is no promise of live remote freshness. Loading, failure/retry, no-match and 50-hit truncation are distinct states; results expose no total count beyond the return bound.

Hidden visibility clears query/scope/results and terminates the Worker; returning to the verified workspace needs a fresh search but no additional Passkey ceremony. Lock, expiry, lease replacement, unmount and pagehide terminate pending work. The served [workspace regression](../local/conformance/vault-owner-workspace-browser.test.ts) checks lazy loading, mixed short Japanese terms, late-message excerpts, per-conversation filtering, deletion reset, exact message focus, hidden/resume, failed asset loading/retry and manual lock against actual workerd/D1/R2. Its PRF and hidden visibility are simulated. Intended mobile-device performance, highlighting, date filters, encrypted snapshot persistence and live messaging remain later work.

## Recommendation

Use SQLite FTS5 as an owner-side search engine. Store an authenticated, encrypted SQLite snapshot as a Vault blob to accelerate reopening, while keeping versioned message/record events as the authoritative archive. During an explicit owner unlock, decrypt the snapshot into a dedicated browser Web Worker and reconcile it with current authorized archive events. Search runs locally; lock terminates the Worker and clears displayed results and retained references. Browsers remain first-class clients; a native app is not required for search.

SQLite is useful both as a local projection of conversations and as a portable search pack. Uploading its bytes does not make encrypted text searchable by the server. Server-side D1 may route ciphertext and revisions, but does not receive message text, search queries, snippets or plaintext FTS tables. Unattended search requires a separately authorized decrypting recipient, rather than an OAuth token that somehow unlocks owner data.

## What Sorane actually does

Source inspection used local Sorane commit `b137b1c1919a9bcfeeea3afc3da58793ba8b6e80`; no private database or conversation content was opened.

| Component | Observed implementation | Relevance to Vault |
| --- | --- | --- |
| `packages/search/src/store.ts` | Node `better-sqlite3`; `chunks` with source, chunk index, text and metadata; external-content FTS5 with `tokenize='trigram'`; insert/update/delete triggers; source hashes; BM25 ranking. | Reuse the projection, chunk identity, incremental replacement and FTS approach. The Node binding is not a browser runtime. |
| `packages/search/src/search.ts` | Query splitting, including splitting on hiragana, quoted OR terms; short snippets; caught FTS errors become no results. | Do not copy query semantics unchanged: everyday Japanese searches need short terms, literal punctuation and distinguishable failures. |
| `packages/okf/src/okfc.ts` | Portable SQLite concept pack with source hashes, provenance, heading chunks and trigram FTS on concept bodies. | A useful model for a versioned portable search artifact, but its concept schema is not a conversation/event or permission contract. |
| `packages/search/src/emit-search-assets.ts` | Public website emits `search-index.json` and precaches it through a Service Worker. | This is not evidence of a deployed browser SQLite implementation. Public plaintext caches must not be copied into private Vault search. |

Schema/runtime ideas can be reused without adopting OKFC as the private thread format or assuming its public distribution permissions apply to Vault. Any copied code needs its license checked at implementation time.

## Searching Japanese conversations

SQLite's [trigram documentation](https://sqlite.org/fts5.html#the_trigram_tokenizer) states that FTS queries shorter than three Unicode characters do not match. A synthetic in-memory probe on Node 26.10.0 / SQLite 3.53.4 inserted only `住所変更の申請を準備する`: `MATCH '住所変更'` returned the row; `MATCH '住所'` and `MATCH '申請'` returned none. A parameterized `instr(body, ?) > 0` returned the row for both short terms. This verifies the tokenizer limitation, not browser compatibility or corpus performance.

Start with trigram FTS for suitable literal terms and a bounded literal substring scan for one/two-character terms. Apply the same documented Unicode/case normalization to indexed text and queries while retaining original text for display. Quote user text as literal FTS phrases; do not expose the FTS expression language accidentally. The first search UI should use explicit AND semantics for multiple terms, with an optional broader search, rather than Sorane's implicit OR/hiragana splitting. Exact behavior for mixed-length terms and punctuation must be tested against the normalized literal semantics.

Short-term scans can be expensive: restrict by selected thread/date where requested, support cancellation and enforce execution/result limits. An interrupted or partially indexed search must say so rather than imply zero matches or complete coverage. Consider a custom bigram/morphological index only after measurement justifies its complexity. Keyword matching is not semantic/vector search.

Return a thread title, a matching excerpt, participant/time and an exact message/artifact anchor. Group hits by thread while preserving access to individual matches; offer search within one conversation. Escaping and highlight rendering must treat message text as untrusted. Searchable related drafts/workflow events must retain the distinction between reported, owner-authorized and recipient-confirmed facts.

## Projection and snapshot contract

| Local table | Proposed contents |
| --- | --- |
| `threads` | Stable thread identity, decrypted title and participant display metadata. |
| `search_items` | Item identity, thread ID, kind, source event ID/revision, ordering/observation fields, original and normalized searchable text, and message/record/workflow anchor. Long bodies may have bounded chunks with offsets. |
| `items_fts` | External-content FTS over normalized title/body, maintained transactionally with items. |
| `projection_meta` | Projection/tokenizer version, owner/key generation, exact scope, authenticated source revisions/checkpoint and coverage state. |

Search indexes contain sensitive text and derived information even when the original body is stored elsewhere. Encrypt the whole exported snapshot under a fresh content key in the proposed versioned Vault envelope. Bind owner, collection/scope, key generation, format and snapshot identity through authenticated metadata; encrypted metadata carries sensitive titles and source references. Record exposed size/revision/access metadata as service-visible leakage.

Export a consistent SQLite image using a supported backup/serialization path. Sorane uses WAL locally; uploading only a live main database file could omit committed WAL content. Do not upload live main/WAL files piecemeal or merge SQLite byte ranges across devices. A checkpoint identifies source coverage, not proof of freshness against a malicious rollback: reconcile with the archive's independently validated head/checkpoint contract, whose rollback guarantees must be specified before claiming them.

Message events and explicit corrections/deletion suppression remain authoritative. Devices independently apply deduplicated authorized events to their local projection; snapshot updates use expected revision and conflicts can be resolved by rebuilding. Losing the search snapshot must not lose conversations. A stale/incompatible/corrupt snapshot is discarded and rebuilt; never substitute it for current archive authority. Rebuild clean snapshots after deletions instead of assuming removal of a row erases old SQLite/FTS/free-page data. Prior downloaded snapshots cannot be recalled.

Begin with one bounded owner snapshot for a small archive. Avoid downloading or rebuilding the entire history on every message or every unlock; retain coverage, replay deltas, and publish snapshots periodically. Partition by collection/time only when measured archive size requires it, with explicit cross-partition coverage. The current 24 KiB encrypted-attribute API is not a general blob/snapshot upload service; thread/event storage and bounded large-blob access must precede production snapshots.

## Web lifecycle and agent access

The official [SQLite WASM API](https://sqlite.org/wasm/doc/trunk/api-oo1.md) provides in-memory databases. Use a pinned, FTS5-enabled browser build in a dedicated Worker, with bounded database size/query work and browser qualification. If a snapshot is cached in IndexedDB or OPFS, cache only authenticated ciphertext; plaintext SQLite, journals, temporary files and owner keys must not persist. [OPFS support](https://sqlite.org/wasm/doc/trunk/persistence.md) is a persistence mechanism, not encryption. Native encrypted offline custody is a separate contract.

Suspend search when the Vault session is masked/hidden; drop late results unless their owner-session generation still matches. On lock/logout/expiry/session replacement/pagehide, destroy search state with the owner unlock lease. Worker termination and reference cleanup bound lifetime, not guaranteed physical memory erasure. Do not send plaintext queries/results to analytics, application logs, URLs, service caches or crash reporting.

For an AI, select the actual plaintext-processing endpoint and allowed threads/artifacts first. Prefer an owner-side search broker operating on an authorized projection and returning bounded results. Enforce scope before ranking, counts and snippets, and recheck current authority when releasing results. Remote/offline AI access may receive a separately encrypted scoped pack only with explicit recipient disclosure; do not send the owner-wide SQLite image and hide rows in the UI. A copied pack cannot be recalled on revocation. Conversation membership, search/read permission, draft proposals and submission authority remain separate capabilities.

## Next implementation evidence

After the owner-key session and first thread archive exist, build a disposable browser probe using fictional conversations and a pinned SQLite WASM runtime. Check exact Japanese short/mixed-term behavior, update/retraction/deletion/rebuild, matching anchors and scope isolation. Verify exported-image round trips, stale/corrupt snapshots, aborted unlocks and no results after lock. Inspect browser storage to ensure plaintext/index/key bytes are not persisted.

Measure 1,000 / 10,000 / 100,000 fictional messages on intended desktop/mobile browsers: image/index size, unlock-to-first-use latency, delta application, peak Worker memory and p50/p95 query latency for long and short terms. Keep the normal Vault opening path usable while indexing, expose incomplete coverage, and agree corpus/device budgets before choosing persistent partitions or a custom tokenizer. The small Node probe above does not qualify any of those gates.

## Browser probe evidence and consequence

The [reproducible browser probe](../design/probes/vault-search/README.md) and [raw results](../design/probes/vault-search/results.json) qualify the basic mechanics locally with `@sqlite.org/sqlite-wasm` 3.53.4-build2. One Apple M3 / 24 GiB development-machine run exercised Chromium 153, Firefox 155 and Playwright WebKit 26.6, each at 1440px and 390px viewport widths. Both viewports use desktop engines/hardware; no smartphone performance claim follows.

| Fictional messages | SQLite image | Initial build, engine range | Restore, engine range | WASM heap capacity | Missing one-character search p95 |
| --- | --- | --- | --- | --- | --- |
| 1,000 | 1.5 MiB | 42–64 ms | 1–3 ms | 8 MiB | 0.5–2 ms |
| 10,000 | 14.2 MiB | 302–439 ms | 5–12 ms | 30.2 MiB | 5.6–9 ms |
| 100,000 | 142.4 MiB | 2.95–4.35 s | 35–82 ms | 319.2 MiB | 63–93 ms |

Matching long-term FTS query p95 at 100,000 messages was 3.4–5 ms. The fixture is repetitive ~200-character Japanese text; image size includes original and normalized bodies plus FTS. Restore excludes network, Passkey unwrap and fresh runtime startup. Heap capacity is not peak process memory and excludes extra JS/crypto buffers. Each term has 15 measured samples, so the reported p95 is the largest sample. These are exploratory measurements, not production budgets.

Japanese one/two-character, mixed AND, literal punctuation/quotes, normalization and Unicode cases passed. Selected-thread projection/filter rejection, edit/delete/rebuild, identical restored anchors and tampered-ciphertext/wrong-AAD rejection passed. Closed DB access and terminated pending requests were rejected; late results did not repopulate the DOM. localStorage/sessionStorage/IndexedDB/CacheStorage stayed empty. OPFS directories were empty where inspected in Chromium/Firefox; WebKit's inspection API returned `UnknownError`, so OPFS inspection remains unqualified there. Physical erasure, production owner grants and hostile database parsing are not established by these checks.

This supports SQLite as the local engine but argues against a monolithic ever-growing snapshot. Start with a bounded archive/pack, measure actual phones, then qualify collection/time partitions with explicit coverage and source-delta replay before broad import. Optimize duplicate text/FTS representation only with measured query/size tradeoffs. Unified owner-key unlock and authoritative thread/event storage remain prerequisites; the probe does not complete U1–U3 or enable a production feature.
