# Explicit record-v2 UserInfo consent

This opt-in path shares only the selected `personal/name` record with the dedicated
UserInfo ClaimWorker. It does not migrate format-1 attributes, select a source just
because a v2 record exists, or permit `owner_note` disclosure as an OIDC name.
Migration `0034_vault_record_userinfo.sql` creates a separate record sharing policy,
recipient-envelope table, system-grant table and sharing audit. Its policy starts
disabled. No production policy or live grants are enabled by this implementation.

## Source identity and authority

Every v2 sharing or RP-consent request carries a strict `source` object:

- `storage_version: 2`
- canonical HTTPS `origin` and the authenticated `owner_id`
- `vault_id`, `collection_id: "personal"`, `record_id: "name"`, `kind: "name"`
- positive safe-integer content `revision`
- canonical base64url SHA-256 `ciphertext_sha256` of the actual stored bytes

Its separate `authority` object contains `key_generation` and
`owner_key_revision`. The first is the root-key generation; the second is the
current owner-key registry fence. Neither is a content revision. Both must match
live state, together with the authenticated credential's wrapper and session.

The record recipient frame is a distinct profile:
`ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-record-v2`, with `MKVR` magic, version 2,
and domain `mikaki-vault-record-recipient-envelope-v2-draft04`. Its authenticated
context includes the complete source tuple, both authority counters, recipient
identity/generation, service and purpose. The ClaimWorker decrypts the v2 content
AAD directly. It never tries the v1 envelope or content profile on failure.

The owner operation authenticates the exact source ciphertext and strict UTF-8
name before creating a recipient wrapper. The caller receives only encrypted
per-record material. No root key or owner key envelope goes to the ClaimWorker.
Mutable browser arguments are snapshotted before asynchronous work; copied key
material and temporary plaintext are cleared. The existing owner-session lease
rejects completion after suspend/dispose.

## HTTP contract

All owner mutations require the current authenticated owner session, same-origin
request, `Content-Type: application/json`, a canonical `X-Operation-ID`, and the
specified `If-Match` fence. Successful exact retries acknowledge the historical
commit; they never reactivate a revoked or expired grant.

- `GET /vault/record-recipient-keys/userinfo` returns the live verified recipient
  key and the record-v2 suite. Browser continuity checkpoints are separate from
  the v1 profile.
- `GET /vault/records/personal/name/sharing` returns policy metadata and the grant
  metadata, including its source discriminator, owner, content revision, authority,
  status, version and expiry. A stored `active` status must also be interpreted
  with its expiry and current policy/source state.
- `POST /vault/records/personal/name/sharing` takes `source`, `authority`, `key_id`,
  `generation`, `directory_revision`, `policy_revision`,
  `expected_grant_version` (0 if absent) and `frame`. `If-Match` is the content
  revision. The OP verifies the stored ciphertext digest and asks the ClaimWorker
  to validate the candidate wrapper. The atomic commit rechecks all live source,
  owner-session, policy, directory and grant-version predicates and writes both
  grant and audit, or rolls everything back.
- `DELETE /vault/records/personal/name/sharing` takes `source` and `authority`;
  `If-Match` is the system-grant version. Revocation and its audit are atomic.
- `GET /vault/records/personal/name/releases` returns policy metadata and eligible
  RP rows. Each row exposes `source_storage_version`, the selected source fields,
  `release_version`, `release_status` and `expires_at`. An absent release has no
  version; callers use 0 when creating it.
- `POST /vault/records/personal/name/releases` takes `source`, `authority`,
  `client_id`, `client_revision`, `connection_grant_version`, `policy_revision`
  and `expected_release_version`. `If-Match` is the current system-share grant
  version. Both the selected source and the single RP-consent ledger version are
  compared atomically. A concurrent replacement or withdrawal rejects a stale
  consent request.
- `DELETE /vault/records/personal/name/releases` uses the existing common-ledger
  withdrawal body `{ "client_id": "..." }`; `If-Match` is the release version.

During the source refactor, the original format-1 release POST is still present
in the OP and uses its existing ledger CAS. It no longer authorizes UserInfo
delivery: `ClaimStore` selects record-v2 releases exclusively and the recipient
Worker has no format-1 decoder. Removing the remaining legacy OP/UI routes is
tracked by #121; they must not be used as a supported disclosure flow.

## One RP consent ledger and final disclosure check

`vault_claim_release` remains the only per-owner/per-RP/per-claim consent ledger.
Historical migration gives existing entries `source_storage_version=1`, which
the current disclosure authority ignores; explicitly granting
v2 replaces that row with its full selected source. Merely creating a v2 system
grant does not change RP consent. Revocation has no v1 fallback.

The OP ClaimStore selects only record-v2 sources from that ledger in one query. It
requires a valid token/session with `profile`, live confidential RP registration
and connection, current policy, selected source, system grant, recipient and RP
consent. After decrypting, its conditional disclosure-audit insert reruns those
predicates and also compares the exact pre-decrypt source, grant, release,
recipient and envelope. If authority changes during decryption, or the audit
cannot be written, it returns no name. The OP receives no recipient secret or
content key.

Source edits/deletion, root-registry changes, system-grant changes, recipient
retirement, sharing/release policy changes and account lifecycle changes invalidate
the relevant authority. Format-1 grant changes only invalidate format-1 consent.
Expired/revoked tokens, sessions and credentials are checked again at disclosure.

## Verification

- `local/conformance/vault-record-userinfo.test.ts`: independent Node HMAC/GCM
  receiver, full source/authority/frame substitution rejection, strict owner
  source validation, content-AAD isolation, asynchronous input snapshots and owner
  lease interruption.
- `crates/userinfo-claim-worker/src/envelope_v2.rs`: Rust HPKE receiver opens the
  checked-in Noble fixture; tests v1 isolation, context substitutions, strict
  source parsing, UTF-8 and UTF-16 name limits.
- `scripts/test_vault_record_userinfo_sql.test.ts`: checked-in statements on native
  SQLite, populated v1 migration, bidirectional explicit source selection, consent
  and sharing CAS, rollback/failure injection, and final-audit invalidation gates.
- `local/conformance/vault-record-userinfo-live.test.ts`: separate real local
  workerd and browser-WebCrypto runs, each using the built Rust OP/ClaimWorker,
  disposable D1/R2 and Secrets Store, authenticated APIs, successful UserInfo,
  idempotent receipts, audit failure and post-decrypt withdrawal. The browser run
  remains mandatory in the full CI invocation; selecting only the workerd test is
  not browser evidence.

Run focused native checks with `npm run test:vault-disclosure`, `npm run test:sql`
and `cargo test --locked -p mikaki-userinfo-claim-worker`. Build the two Workers and
ClaimWorker's `conformance-gate` artifact before the live suite. Native SQLite and
Wasm compilation alone do not establish D1 or browser runtime success. This is a
protocol/backend capability; the existing preview UI is not a completed end-user
record-sharing interface.


### Local qualification status (2026-10-03)

Passed: 30 native TypeScript crypto/lifecycle cases, 63 record UserInfo SQL cases,
all 259 SQL tests, seven ClaimWorker Rust tests, native and Wasm Clippy with
warnings denied, OP Wasm check, Node/Worker UI type checks, format and documentation
checks, and both release/conformance ClaimWorker builds.

The real local workerd case passed with the built Rust OP and ClaimWorker plus
disposable D1/R2/Secrets Store. It verified successful decrypted UserInfo, separate
sharing and RP consent, exact operation retry/body drift, stale recipient-directory
rejection, share-audit rollback, post-decrypt RP withdrawal, final-audit failure,
and recipient disable without historical-receipt reactivation. The harness uses
an explicit temporary Wrangler config, `--remote=false`, disabled metrics, and
only the synthetic `mikaki.test/*` OP route. No production config or live grants
were used.

Miniflare also performs its default public metadata `GET` to
`https://workers.cloudflare.com/cf.json`; it carries no fixture credentials or
request body. This metadata lookup is separate from the synthetic disclosure test.

Browser-WebCrypto qualification remains a CI gate. Local system Chromium is
blocked by the execution environment's socket/ptrace restrictions; a native
workerd pass must not be reported as browser evidence. The preview UI remains a
placeholder for this service capability.
