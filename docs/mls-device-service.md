# Authenticated MLS device registry and journal witness

**Status, 2026-10-19:** a feature-gated Rust adapter now connects the device
profile and encrypted journal to the OP's actual SSO/D1 authority model. Nine
workerd scenarios and an integrated OpenMLS/Wasm journey in Chromium, Firefox
and WebKit qualify the adapter locally. Sessions and issuer/custody keys are
synthetic fixtures. These tests do not exercise a real Passkey ceremony, production
D1, native cookie/session transport or physical-device custody.

The implementation is [messaging.rs](../crates/worker/src/messaging.rs) and
[messaging_crypto.rs](../crates/worker/src/messaging_crypto.rs). It compiles only
with `messaging-qualification` or the opt-in `messaging-beta` feature. The
[limited product host](mls-beta.md) mounts the shared adapter only when its runtime
flag is also enabled. Default production builds keep these routes disabled.
The [schema](../crates/worker/messaging-migrations/0001_messaging.sql) is outside the production
migration ledger. The local [entrypoint](../crates/worker/examples/messaging_qualification.rs)
uses the same HTTP authorization/SQL code without a synthetic principal bypass.
[The fault wrapper](../design/probes/mls/server/worker-fixture.mjs) is local-only.
No deployment or production migration is performed by this work.
The [Vault custody manager](mls-device-custody.md) now connects enrollment and
the witness to the actual Owner Vault lease, retaining encrypted preparation
across reloads. Its state keys stay in browser custody rather than fixture memory.

## Identity, issuer keys and owner authority

The existing SSO `account_id` is an opaque random identifier, whereas the MLS
[device profile](mls-device-trust.md) requires a canonical UUID account namespace.
The server creates an immutable `messaging_account` UUID for an authenticated
owner. The caller never supplies another account/issuer or a purported SSO
principal in a registration request. Display names, pairwise OIDC subjects and
DIDs are not substituted for this mapping.

Only the `__Host-op-sso` cookie can authorize these routes. The live authority
view joins the current SSO context/session, matching active account/epoch and
active authenticated credential. Bearer/OAuth/agent credentials alone do not
qualify. Mutations require the exact canonical HTTPS Origin and exact JSON type;
read requests reject supplied nonmatching Origin and cross-site browser fetches.
There is no CORS grant, cross-origin endpoint discovery or arbitrary remote fetch.
The configured `MIKAKI_ISSUER` must exactly match the request origin.

A separately provisioned `MESSAGING_ISSUER_KEY` secret contains exactly an OKP
Ed25519 private JWK (`kty`, `crv`, canonical 32-byte `x` and `d`). The adapter
imports a nonextractable WebCrypto signing handle and checks private/public
consistency before registry operations. It neither generates an issuer key on
request nor reuses the OP's OIDC signing key. Clients must pin the corresponding
public authority independently; a successful registration response cannot
establish its own trust anchor. Issuer rotation and actual key provisioning remain
operator adoption work. Workers' [WebCrypto support](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
provides the Ed25519 primitives; no OpenMLS provider or MLS secret enters the OP.

## Bounded HTTP contract

Every response prohibits caching. Successful JSON uses `no-store, no-transform`.
Unknown fields, unsupported methods/queries, noncanonical identifiers/encodings,
oversized bodies and invalid revisions fail closed.

| Route | Contract |
| --- | --- |
| `GET /messaging/account` | Return the current owner's `{issuer,account_id}` mapping; 404 if never allocated. |
| `POST /messaging/account` | Exact empty JSON object; create the immutable mapping or return the existing one. |
| `POST /messaging/enrollments` | UUID `X-Operation-ID`; exact `{device_id,public_key,storage_id,key_id,expected_revision}` in at most 1 KiB. |
| `POST /messaging/enrollments/:id/complete` | Exact `{proof}` in at most 9 KiB; verify the profile's device-key possession JWS and atomically commit registration. |
| `GET /messaging/devices/:id/binding` | Return `{binding}` for the owner's current device generation/status. It is not a public federation directory. |
| `POST /messaging/devices/:id/revoke` | Exact `{expected_revision}`; retire that current generation and advance the registry revision atomically. |
| `GET /messaging/heads/:scope` | Return the current `{revision,hash}` for an active, current, owner-bound generation; never implicitly allocate a scope. |
| `PUT /messaging/heads/:scope` | Exact `{expected,next}` in at most 1 KiB; compare-and-set one revision forward, then return the actual current head. |

The account ID, device ID, storage ID, custody-key ID and operation ID are lowercase
UUIDv4s. A first registration requires `expected_revision: 0`. A replacement must
name the exact current registry revision; the server assigns the next generation.
The response supplies the exact identity, a random 32-byte nonce, a 60-second
challenge expiry, and the journal scope/fingerprint. Callers read/create the
account mapping before constructing their MLS identity/key.

An enrollment is bound to the exact SSO context secret, owner and authenticated
credential that created it. Another session for the same owner cannot consume
it. Retry of the same operation ID and canonical request returns its original
challenge; a changed intent conflicts. An expired unconsumed challenge requires
a new operation rather than a reset. Completion accepts only the restricted
`mikaki-device-registration+jwt` profile: exact issuer audience, device identity,
public key, nonce, `EdDSA`/Ed25519 key ID and at most 60 seconds of validity.

A valid signature alone is insufficient. The registration transaction rechecks
database current time, the active SSO/account/epoch/credential, exact prior
revision/generation, retained-key exclusion and capacity. It retires the old
generation, inserts the new generation/genesis witness, publishes its device
head and records the consumed proof digest together. A final constraint guard
rolls back the whole batch when any predicate loses, including expiry after
asynchronous signature verification. D1's [batch transaction contract](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch)
is exercised with an actual second-statement failure in workerd.

A lost D1 batch response is reconciled against the durable consumed-proof record;
an unconfirmed outcome is never reported as a definite rollback. Retry the exact
proof/operation before allocating a new generation. An identical consumed proof
can also recover a lost successful HTTP completion response
only while that enrollment still names the current generation and the original
SSO context remains authorized. Different proof bytes conflict. A superseded
registration never refreshes its old active lease. Current bindings have a
300-second lifetime, signed registry revision/status and the exact device leaf
key. The adapter checks the same current registry/authority again after awaiting
signing. Cached leases elsewhere still bound unobserved revocation freshness;
this does not provide instant global cryptographic removal.

## Witness, consistency and key generations

Each registered generation fixes exactly one storage UUID, custody-key UUID,
signing fingerprint and scope digest under the journal's canonical origin/device
AAD contract. Its witness begins at `{revision:0,hash:null}`. No general-purpose
head-creation/reset/delete endpoint exists. The service retains old generations,
public keys, scope IDs and heads as tombstones. Re-enrollment cannot recycle any
retained signing key under that owner, including under a different device ID;
a new storage UUID alone cannot authorize a reset with an old key.

Witness writes recheck owner authority and active current generation in the
conditional SQL mutation. A competing CAS returns the real current head, allowing
the journal to detect a fork. Retrying an older transition after later writes
also returns the current head; historical acknowledgments must not masquerade as
current reads. Replacement/revocation makes the old witness scope unavailable,
without deleting its retained monotonic record. Owners manage their own devices;
this slice does not issue a separate device-scoped witness token for native use.

Every authority-sensitive SELECT starts a **fresh** `first-primary` D1 session,
including the check after signing and the witness read after a mutation. A single
request-scoped session would only constrain its first query to primary and could
serve subsequent rechecks from a replica. See [D1 session consistency](https://developers.cloudflare.com/d1/best-practices/read-replication/#start-a-session-with-all-latest-data).
The local runtime has no real replica lag; remote routing, latency and failover
still need operational qualification.

[AuthenticatedHeadWitness](../design/probes/mls/http-witness.ts) implements the
journal's HTTP interface with same-origin credentials, HTTPS/origin pinning,
redirect rejection, abort support, no-store and bounded strict head responses.
401/403, missing/revoked scopes and service failures stop journal access. A 404
never becomes an empty genesis record. The journal still requires the external
service for reads/mutations; it does not gain fully disconnected operation.

The witness protects against local IndexedDB rollback, not rollback of the
witness database itself or compromise of both client and witness. Backup/restore
must preserve or independently reconcile these monotonic heads; ordinary D1
restore is not a qualified messaging recovery procedure. Signing-key loss,
custody-key loss and scope metadata loss require explicit device recovery/new
generation rather than silent enrollment. Existing old ciphertext/history is
not transferred to a replacement key by this service.

## Evidence, limits and activation work

[Server tests](../design/probes/mls/server.test.ts) cover independent Node
signature verification, namespace isolation, malformed profiles, exact retries,
CAS conflicts, replacement/revocation/tombstones, transaction rollback, lost
successful D1 responses, database
expiry, credential/account/epoch/session loss before writes and after signing,
and simultaneous last-device admission. The [integrated browser tests](../design/probes/mls/server.browser.test.ts)
use actual Wasm device proofs, pinned issuer bindings, encrypted IndexedDB state,
HTTP witness CAS, lost CAS responses, reload, real MLS wire exchange/deduplication
and revocation. A local bridge serves the test HTTPS origin and relays its
browser cookie jar to workerd; it is not a real network/TLS or Passkey test.
Custody keys remain synthetic harness memory, and those legacy journeys relay wire in their harness. The separate
[mailbox qualification](mls-device-delivery.md) now exercises authenticated
same-instance delivery through the Vault-owned client.

Each owner is bounded to eight retained device IDs, 64 retained generations,
128 retained enrollment operations and four concurrent unconsumed live
challenges. Limits are enforced at both challenge issuance and final admission
where relevant; no tombstones are deleted to reclaim an identity. Witness heads
have safe-integer revision bounds. Retention/compaction, authentication abuse
control, durable audit/monitoring and broader capacity qualification remain
product work. These conservative lifetime limits are not an unlimited registry.

Reproduce from the repository root after the MLS Wasm build and npm install:

```sh
npm run build:policy
node scripts/build-messaging-qualification.ts
MIKAKI_MLS_BROWSERS=chromium,firefox,webkit node --test --test-concurrency=1 design/probes/mls/server.test.ts design/probes/mls/server.browser.test.ts
cargo clippy --locked -p mikaki-worker --target wasm32-unknown-unknown --features messaging-qualification --lib -- -D warnings
```

Before activation, integrate intended-device custody/unlock and durable enrollment
recovery, qualify real Passkey/SSO registration and key-change confirmation UI,
provision issuer keys/trust anchors, review a production schema migration and
routing, and qualify witness operations/recovery. The
[mailbox](mls-device-delivery.md) qualifies authenticated durable delivery
and catch-up for same-instance pairs, with [initial invitation
delivery](mls-device-invitations.md) and [explicit fresh-group
recovery](mls-device-recovery.md). The product-hosted text-chat/recovery interface and
automatic competing-proposal coordination remain later work. The
[independent-instance pilot](federated-messaging.md#first-pilot) is still open.

[Explicit changed-key proposal cancellation](mls-replacement-cancellation.md) now
qualifies a pre-bilateral veto, exact outcome retry and manual selection of a
fresh shared proposal. [Admission recovery](mls-admission-recovery.md) now qualifies
closed/expired changed-key admissions and interrupted joining through explicit
stop and fresh consent. [Same-key rejoin recovery](mls-rejoin-recovery.md) also
qualifies closed/expired successors before local restart and bounded repeated
stops. Automatic coordination, healthy pending-rejoin cancellation and repeated
generation changes remain open.
