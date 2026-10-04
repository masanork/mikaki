# Vault ciphertext garbage collection

Migration `0045` adds a durable candidate queue. This is locally implemented; the ten-minute schedule and migration have not been activated in production as part of this work.

Every new v1 attribute or v2 owner-record upload reserves its object key in D1 before R2 PUT. A successful head installation cancels that pending candidate. Head replacement/deletion queues the retired object through D1 triggers. Failed uploads and failed post-upload D1 commits therefore leave a collectible candidate rather than relying solely on R2 enumeration. Candidates are eligible after a 24-hour safety interval.

Collection atomically marks at most 256 unreferenced keys `deleting`, checks both authoritative live head tables, deletes them through R2, then removes their D1 candidates. A head cannot adopt a claimed key: both the product CAS and database triggers reject it. A crash/R2 failure retains the `deleting` candidate for idempotent retry; overlapping collectors cannot cause a live head to reference a deleted object. Object keys are unique per upload and are never reused for a new head.

Each ten-minute invocation runs up to four batches (1,024 objects) with a 20-second loop budget. Separate 128-object scans for each v1/v2 prefix, with independent cursors, discovers older/pre-migration orphans. Scan throughput is no longer the collection throughput limit. A write that stalls beyond its safety interval must fail its final head CAS rather than resurrect the collected key; the cursor scan also catches any late orphan PUT.

`vault_gc` logs collected count, candidate backlog, oldest eligibility and elapsed time; `vault_gc_failure` records retryable failures without object keys or owner IDs. An increasing oldest eligible timestamp over successive runs indicates insufficient throughput or failing collection. The configured ceiling is 147,456 candidates/day before the time budget or service constraints; actual throughput requires production qualification. Do not describe 24 hours as a deletion SLA or remove historical recovery objects outside their recovery policy.

`local/conformance/vault-gc.test.ts` exercises 700 obsolete revisions in each storage format, a failed-upload orphan, an interrupted delete, erroneous live-head candidate, recent object and rejected head resurrection. Multiple scheduled runs drain eligible candidates while preserving active/recent objects. Existing owner write tests retain R2/D1 failure and exact retry coverage.
