# Owner-key wrapper rollout

Issue [#114](https://github.com/masanork/mikaki/issues/114) needs an additive
operation-receipt migration before wrapper registration and removal can be
enabled. The frozen `0001_owner_vault_initial.sql` baseline remains unchanged.

Deploy the readiness bridge first, while production still has only `0001`.
The bridge accepts exactly the ordered ledger `0001_owner_vault_initial.sql`,
or that baseline followed by `0002_owner_key_wrap_operations.sql`. It rejects
missing, duplicate, reordered, historical and unknown migration names. A binary
built with `0002` requires both entries; it cannot silently run on `0001` alone.
Readiness still checks policy, signing-key alignment, R2 and the Claim Worker.

The bridge does not add the migration, expose wrapper operations or authorize a
database change. The bridge's promotion gate requires the complete singleton
baseline schema; the wrapper feature's promotion gate requires the exact
ordered `0001` and `0002` chain and its complete schema. Before applying `0002`,
review its immutable operation receipt, the atomic wrapper/head update protocol
and the feature's exact migration-chain schema gate. Normal deployments must
continue to refuse unapplied migrations.
Retain the bridge's qualified Worker version as the rollback target during this
additive transition; an older pre-bridge binary reports unavailable after `0002`.

For the feature rollout, record a fresh D1 Time Travel bookmark, apply only the
reviewed additive migration, verify the complete ledger and schema against the
reviewed bytes, then promote the already qualified feature artifact. Recheck
source/version-matched readiness and public smoke. Do not reset production,
replay the retired incremental migration series or edit `0001`.

Additional Passkey wrappers preserve the same encrypted parent key. Their head
revision is an authorization fence; it is not record encryption AAD. Advancing
it invalidates existing Agent/share grants through the baseline's triggers, so
the feature must explain reapproval and discard stale browser authority leases.
Login registration alone does not grant Vault access. Losing every usable
wrapper remains unrecoverable until a separately implemented recovery policy
exists; parent-key rotation and content-key rotation are separate protocols.

## Wrapper feature contract

The Owner workspace separates login registration from Vault access. Enrollment
uses the existing same-account discoverable Passkey API, requires a login within
five minutes and preserves the attestation response for an exact retry. A newly
registered login credential cannot open an existing Vault until explicitly
authorized. Unlocking such a credential returns `credential_not_wrapped`; it
never creates a replacement parent key.

Authorization requires an unlocked source lease, a fresh source PRF evaluation
and a fresh evaluation pinned to the added credential. `rewrapOwnerKey` wraps the
same parent key and consumes both PRF outputs. The browser sends only the opaque
envelope. Profile, note and conversation ciphertext is unchanged.

`GET /vault/owner-key/wrappers` returns the bounded current-generation registry,
including inactive login credentials with retained wrappers. `PUT` adds a wrapper
for an active credential belonging to the same account; `DELETE` removes another
credential's wrapper, including an inactive one. Both require same-origin JSON,
an exact quoted `If-Match` head revision and a 43-character `X-Operation-ID`.
The source session, account epoch, active source credential and source wrapper
are rechecked in the head CAS. The source itself cannot be removed, so at least
one usable wrapper remains. Up to ten current-generation wrappers are retained;
the same transaction limits new access changes to twenty per account per minute.
Exact acknowledgments remain available after that limit is reached.

The head revision bump, wrapper change, baseline grant-revocation triggers and
immutable operation receipt commit in one D1 batch. Receipt identity binds the
account, source credential, action, context, original precondition and exact
body. An identical retry acknowledges the original revision without replaying a
mutation; changed bytes or source conflict. Storage failure rolls back every
change, and an unknown outcome retains only public/opaque retry data in memory.
Conflicts require reopening. Successful changes lock the browser lease; editing
access is disabled while profile or note drafts are unsaved.

Feature promotion uses `scripts/production-owner-schema.ts`: reviewed SHA-256
digests for both migrations, the exact ordered two-entry ledger and a complete
schema comparison after replaying those bytes. Extra/altered SQL, missing names,
unknown objects and changed triggers are rejected. The independent reset planner
still blocks a non-singleton baseline, and Docs retains its own singleton gate.

This slice does not implement staged parent generations, content-key rotation,
suite changes or recovery after all usable wrappers are lost. Physical-device
PRF behavior remains a separate qualification; synthetic browser/API tests do
not establish real-device recovery. Issue #114 stays open for those requirements.
