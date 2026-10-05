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
database change. The current promotion gate still requires the complete singleton
baseline schema. Before applying `0002`, review its immutable operation receipt,
the atomic wrapper/head update protocol and the feature's exact migration-chain
schema gate. Normal deployments must continue to refuse unapplied migrations.
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
