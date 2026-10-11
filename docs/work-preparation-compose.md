# Owner selection to a reserved preparation

**Status:** locally implemented behind a dedicated opt-in flag, 2026-10-09 JST.
This increments [ADR 0016](adr/0016-personal-context-and-workload-delegation.md)
and the [owner review design](work-request-ui.md). Productive copying and workload
delegation retain separate gates.

## Decision and owner flow

The source screen lets an owner choose one registered code repository and up to
four context repositories, inspect selected context files, and set a copy
deadline. Code contributes its registered reachable history; contexts contribute
only selected files. Creating a preparation reserves immutable metadata. The
result links to a fresh preparation review, where content inspection and explicit
copy approval are required again. Following the link never approves or starts a
copy. Approval still creates no credential, task, grant or run.

The screen supports code-only preparation. Context selection remains bounded to
32 files and 128 KiB. Deadlines must be in the future, within one hour and within
the live SSO lifetime; the UI offers 2–30 minutes. Selection/validity changes or
refresh discard the acknowledgement and establish a new deadline. An unchanged
retry retains its original absolute deadline. Hidden state, lock and session
replacement discard all displayed contents and reject late replies.

## Closed owner transport

`POST /work/preparations` requires `WORK_OWNER_API_ENABLED=true` and
`WORK_PREPARATION_COMPOSE_ENABLED=true`. Its closed, duplicate-key checked JSON
body is bounded to 16 KiB and contains only:

```json
{
  "format_version": 1,
  "code": { "source_id": "code", "source_revision": 1, "access_revision": 1 },
  "contexts": [
    {
      "format_version": 1,
      "source_id": "personal",
      "source_revision": 1,
      "access_revision": 1,
      "paths": ["preferences/writing.md"]
    }
  ],
  "expires_at": 1791500000
}
```

Context IDs use increasing ASCII order; paths use the existing native byte-order
contract. No caller supplies an owner, actor, recipient, workload, namespace,
destination name, disclosure, Git receipt, credential or file content. Live owner
SSO, same-origin checks, current independent checkpoint, current source/access
revisions and the existing reservation budgets remain authoritative.

Operator configuration fixes `WORK_ARTIFACTS_NAMESPACE`, `WORK_COPY_RECIPIENT`,
`WORK_COPY_WORKLOAD` and `WORK_ARTIFACTS_ACCOUNT`. Recipient/workload values are
planning identifiers; this endpoint supplies no issuer or launcher assurance.
Source inspection additionally needs the existing source API/screen flags and
private `WORK_SOURCE_READER`. Review/approval need their existing preparation and
copy-consent flags. The opt-in schema remains `0003`–`0013`; no new migration or
production binding is introduced.

## Native resolution and planned Git objects

Rust rereads selected contents through the fixed read-only source RPC, validates
the bounded reply, and repeats source and checkpoint checks after I/O. Service
bindings address a configured Worker directly; caller-provided hosts or binding
names are never used. See [Cloudflare's service-binding RPC documentation](https://developers.cloudflare.com/workers/runtime-apis/bindings/service-bindings/rpc/).

An opaque verified selection checks the content size, UTF-8, SHA-256 and actual
Git blob identity before the disclosure constructor accepts its metadata. Native
Rust then computes the planned tree and parentless commit from those blob IDs.
Selected paths are prefixed `context/00/`, `context/01/`, and so on. Files use mode
`100644`; tree entries use Git byte ordering, including the directory suffix.
The commit uses the existing snapshot message, fixed identity and timestamp.
Git object IDs hash the typed object header plus its bytes; see [Git objects](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects).

SHA-1 here names existing SHA-1 Git objects only. Disclosure, preparation,
request-correlation and authority commitments remain SHA-256. Tests compare the
Native tree/commit with independent local Git materialization, including Unicode
paths, directory ordering and the empty tree. Duplicate paths and file/directory
collisions fail. This computes planned object names; it does not persist a Git
snapshot, prove an upload or establish copy completion. The future productive
executor must materialize and independently verify the exact planned objects.

## Persistence and retry boundaries

The closed canonical selection, owner and current policy projection fix the
logical snapshot name. The immutable disclosure fixes the task name and existing
preparation identity. Exact retries and concurrent isolates return the same
preparation without duplicate audit or reservation charges. Changed source,
policy or owner authority fails the current guards rather than reusing authority.

The existing Native framed writes first save a disclosure and then reserve its
preparation. If reservation fails, a safe metadata-only disclosure may remain.
No consent or external effect exists; an exact retry can finish the reservation.
An audit failure rolls back the preparation and its budget charge. The response
is returned only after a final live owner read.

The browser verifies a closed response of at most 4 KiB and checks the exact
request digest and deadline before showing its link. This is display correlation,
not browser-created authority. Refreshing the preparation screen restores the
durable Native outcome. It requires fresh content review before approval.

`npm run test:work-preparation-compose` builds both the separate qualification
seed Worker and the actual product Worker before running Native/API/browser and
cold-boundary checks. Existing source UI CI/PR checks include the composition
cases. Fixtures use synthetic local SSO/configuration and real local Git bytes;
they perform no real Artifacts mutation. Exact-source results are recorded in
the [implementation ledger](work-delegation-implementation.md).
