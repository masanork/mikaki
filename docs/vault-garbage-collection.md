# Owner Vault ciphertext garbage collection

The durable candidate queue and Owner-record-only collector are deployed in
source `140baec` with the fresh `0001_owner_vault_initial.sql` baseline. The
`*/10 * * * *` production schedule and empty R2 were verified at the
[2026-10-05 cutover](production-reset-2026-10-05.md). Historical incremental
migration `0045` and format-1 attribute collection are retired.

Every new Owner-record upload reserves its object key in D1 before R2 PUT.
Successful head installation cancels that pending candidate. Head replacement
or deletion queues the retired object through D1 triggers. Failed uploads and
failed post-upload D1 commits leave a collectible candidate, independent of
full-bucket enumeration. Candidates are eligible after a 24-hour safety interval.

Collection atomically marks at most 256 unreferenced keys `deleting`, checks the
authoritative live Owner-record heads, deletes them through R2 and removes their
D1 candidates. A head cannot adopt a claimed key: both the product CAS and
triggers reject it. A crash or R2 failure retains `deleting` candidates for
idempotent retry. Object keys are unique per upload and never reused for a new
head; overlapping collectors cannot authorize a live head for a retired key.

Each ten-minute invocation runs up to four batches (1,024 objects) with a
20-second loop budget. A separate 128-object scan, with a persistent cursor,
discovers older orphans only within `vault-owner-record/`. It does not inspect
or delete foreign/retired namespaces. Scan throughput no longer limits the
collection of recorded candidates. A stalled upload must fail its final head
CAS if its key was collected; the scan also catches a late orphan PUT.

`vault_gc` logs collected count, candidate backlog, oldest eligibility and
elapsed time; `vault_gc_failure` records retryable failures without object keys
or owner IDs. An increasing oldest eligible timestamp over successive runs
indicates insufficient throughput or failing collection. The configured ceiling
is 147,456 candidates/day before time budgets or service constraints; actual
production throughput remains measurement work under
[#106](https://github.com/masanork/mikaki/issues/106). The safety interval is not
a deletion SLA. This collector is not an old-data migration or recovery tool.

[The real Worker regression](../local/conformance/vault-gc.test.ts) creates 700
Owner-record revisions, a failed-upload orphan, an interrupted deletion,
an erroneous live-head candidate and a recent object. Repeated scheduled runs
drain eligible obsolete objects while preserving live/recent data and rejecting
head resurrection. Owner write tests cover R2/D1 failures and exact retries;
[the Owner-record store tests](../local/conformance/vault-owner-record-store.test.ts)
verify that the collector leaves foreign namespaces untouched. These checks
passed [main CI run 37256255769](https://github.com/masanork/mikaki/actions/runs/37256255769).
The reset itself verified an empty bucket, rather than a sustained production
update load.
