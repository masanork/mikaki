# Encrypted thread archives and SQLite search

**Status:** investigation and proposed implementation direction, 2026-10-03. No thread storage, browser SQLite runtime or production full-text search is implemented by this document. It extends the [Vault product model](vault-product-model.md).

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
