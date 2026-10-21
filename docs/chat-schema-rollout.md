# Chat schema rollout

Chat uses the existing Owner database, but never its migration directory or
`d1_migrations` ledger. The migration-only
[`wrangler.messaging-migrations.jsonc`](../crates/worker/wrangler.messaging-migrations.jsonc)
selects `messaging-migrations` and `messaging_schema_migrations`. It has no Worker
entrypoint, routes, runtime variables or secrets. Its account/database must match
the reviewed production Owner binding.

The three SQL files are pinned in
[`production-messaging-schema.ts`](../scripts/production-messaging-schema.ts).
The beta release inventory binds their SHA-256 hashes, ledger name and the exact
migration configuration. Ordinary production promotion still accepts only the
default compile profile. A complete, reviewed Chat schema is compatible with a
disabled/default Worker; creating tables grants no Chat access.

## Read-only preflight

Use the repository's installed Wrangler. Select the target explicitly:

```sh
npm run check:chat-schema -- --local
npm run check:chat-schema -- --remote
```

This command only issues schema/ledger/constraint queries. It does not invoke
`migrations list` (which can create a ledger), apply SQL, upload a Worker, change
keys or enable Chat. Local checking uses the default Wrangler persistence path;
it expects the existing Owner schema there. Tests use isolated temporary stores.

The JSON result reports the number of applied Chat migrations, `complete`, and
`mutations:false`. A successful preflight permits an absent Chat ledger or an
exact migration prefix of length 0–3. `complete:true` requires all three. This
result is a point-in-time schema check, not authorization to activate Chat and
not an atomic migration lock. Repeat it immediately before an approved apply.

The checker validates the complete Owner schema and optional complete Work
schema, every Chat SQL hash, ordered Chat ledger IDs/names, all tables, views,
indexes, triggers, live foreign keys, beta version marker and seeded ingress
policy. It refuses multiple device heads per account before migration 0002.
Only the number of conflicting accounts is queried; no device identifiers or
private rows are emitted. It never deletes a device to make the index succeed.

Unledgered historical Chat objects, reordered/unknown migrations, partial DDL,
changed policy, or an unfinished Work adoption fence stop the check. Reconcile
those states before proceeding. Do not fabricate ledger rows for old tables.
For local D1 only, the exact workerd `_cf_METADATA` table is recognized; remote
schema checking retains the existing strict comparison without that exception.

## Production application gate

Before applying remotely:

1. Merge and deploy the schema-compatible normal Worker; confirm main CI,
   source/version, login/readiness smoke and the beta candidate attestations.
   Applying first can leave the previously deployed promotion code unable to
   validate the new tables on its next run.
2. Finish any Work schema adoption. Run the read-only remote preflight against
   the reviewed account/database and inspect the exact pending Chat prefix.
3. Record a D1 Time Travel bookmark and the current deployment/source, migration
   hashes and ledgers. Keep Chat disabled and prevent concurrent Chat enrollment
   or schema changes throughout the maintenance operation.
4. Through the reviewed operator process, apply only the dedicated Chat chain:

   ```sh
   npx wrangler d1 migrations apply mikaki-auth-owner --remote --config crates/worker/wrangler.messaging-migrations.jsonc
   ```

5. Repeat `npm run check:chat-schema -- --remote` and require `complete:true`.
   Verify the Owner ledger/passkey state is unchanged and repeat login/readiness
   smoke. Ordinary promotion independently rejects an incomplete Chat chain.

Wrangler rolls back a failing migration, not earlier successful files in the
same apply command. If 0002 fails, 0001 can remain applied; ordinary promotion
then remains closed until the exact complete chain is reconciled. Do not reset
the Owner database, remove device rows or alter pinned SQL to bypass the failure.

No remote apply is performed by the normal deploy job or this preflight. The
local Wrangler tests qualify successful ledger separation and a failing
multi-device unique index, including preservation of credentials/device rows
and absence of partial failed DDL/ledger entries. They do not qualify remote D1
application, populated Chat code rollback, beta key/config provisioning or real
device use. Those remain in the
[activation checklist](wallet-chat-release-readiness.md#chat-activation-dependencies).

See Cloudflare's [D1 migrations reference](https://developers.cloudflare.com/d1/reference/migrations/)
and [migration apply behavior](https://developers.cloudflare.com/d1/wrangler-commands/#migrations-apply).
