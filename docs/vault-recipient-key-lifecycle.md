# UserInfo recipient-key lifecycle

**Status, 2026-09-24:** Generation 1 (`ne7gDOPjARDMKT1Be_BZ3Qo9fWPRYsHcZBqtkg39MnE`) is active in production. Its seed is in Secrets Store, the claim Worker verified the D1 public key through a remote service binding, and D1 recorded staged and activated audit events. The temporary local seed copy was removed. No recipient envelope, Grant, or claim-sharing flow is enabled.

## Responsibilities

- **Owner browser:** Wrap only an attribute's data key to the active UserInfo recipient public key. Fetch the directory from the same-origin Worker, verify that `key_id` is the unpadded base64url SHA-256 digest of the public key, and reject a generation older than one already seen. Retain the owner's PRF envelope and Vault ciphertext.
- **OP Worker:** Own the D1 public directory and grants. It does not have the ML-KEM private-key binding and must not reuse an OIDC signing key.
- **UserInfo claim Worker:** Alone reads the ML-KEM private seed from a dedicated Cloudflare Secrets Store binding. The 64-byte seed must never enter D1, R2, logs, or responses. Authenticate its caller through an internal service binding and expose only fixed claim operations. Worker code and deployment access are part of the private-key trust boundary.

The binding uses Cloudflare's [`secrets_store_secrets` and asynchronous `get()`](https://developers.cloudflare.com/secrets-store/integrations/workers/). Adding a binding requires deployment; switching a public key to disabled in D1 must not. A secret is not a D1 policy value.

## D1 directory and local tools

[Migration 0007](../crates/worker/migrations/0007_vault_recipient_keys.sql) stores `key_id`, service `userinfo`, algorithm `ML-KEM-768`, a 1,184-byte public key, private-binding reference, generation, state, monotonically increasing revision, and timestamps. There is no private-key column. The initial directory is empty; migration alone enables no sharing.

States are `staged → active → decrypt_only → disabled`, or `staged/active → disabled`. At most one UserInfo key is active. Key material, binding reference, and generation are immutable after registration. Rows cannot be deleted or re-enabled after `disabled`. D1 checks, a unique index, triggers, and the [SQL tests](../scripts/test_vault_recipient_keys_sql.py) enforce these constraints.

Before registration, derive the public key from the seed and compare it. The [claim Worker](../crates/userinfo-claim-worker/src/lib.rs) implements internal `GET /internal/recipient-keys/{key_id}/verify`, comparing the Secrets Store seed, D1 public key, and key-ID digest on every call. It returns 204 only on a match and fails for disabled keys, missing bindings, or mismatches. The OP uses this service binding before returning an active key from owner-authenticated `GET /vault/recipient-keys/userinfo`; failures return 503 and responses are not cached.

The isolated native [`recipient_key` CLI](../design/probes/pqc/src/bin/recipient_key.rs) generates a 64-byte seed using the OS CSPRNG, writes it to an owner-only file, and writes the public key, digest, and binding reference to separate JSON. It refuses to print the seed or write it inside the repository. `verify` derives the public key again. It does not provision Secrets Store or activate D1 state.

```sh
cargo run --locked --manifest-path design/probes/pqc/Cargo.toml --bin recipient_key -- generate /private/tmp/vault-userinfo-seed.txt /private/tmp/vault-userinfo-public.json VAULT_USERINFO_MLKEM_A 1
cargo run --locked --manifest-path design/probes/pqc/Cargo.toml --bin recipient_key -- verify /private/tmp/vault-userinfo-seed.txt /private/tmp/vault-userinfo-public.json
```

Use a protected temporary location for real operation, provision the seed into Secrets Store, and securely dispose of the temporary copy. The public JSON is input to registration, which verifies the ID and key.

The [production Wrangler config](../crates/userinfo-claim-worker/wrangler.production.jsonc) is tracked with no secret bindings. The [example](../crates/userinfo-claim-worker/wrangler.example.jsonc) shows the per-key binding. `workers_dev: false`, disabled preview URLs, and no route leave the claim Worker without a public HTTP entry point. Adding a key requires a binding deployment; disabling one is a D1 operation.

For each key, use the [secret administration CLI](../scripts/recipient-secret-admin.mjs) to verify the seed and public record offline, confirm that the seed file is owned by the operator with mode `0600` and lies outside the repository, then create an account secret with `workers` scope. The CLI sends the seed to Wrangler only through standard input, never as a command argument or log value. The operator's Cloudflare token needs Secrets Store access. On success, the CLI adds the store ID and binding name to the production Wrangler config. Review and commit that config, deploy the claim Worker, stage the public record in D1, and run `activate` only after verification through the service binding succeeds. Do not put the seed in a Wrangler variable, config file, logs, or a command argument. If secret creation succeeds but config writing fails, add the binding manually; do not create a second seed without checking the secret metadata.

```sh
node scripts/recipient-secret-admin.mjs --seed /private/tmp/vault-userinfo-seed.txt --public /private/tmp/vault-userinfo-public.json --store-id STORE_ID --config crates/userinfo-claim-worker/wrangler.production.jsonc --apply no
node scripts/recipient-secret-admin.mjs --seed /private/tmp/vault-userinfo-seed.txt --public /private/tmp/vault-userinfo-public.json --store-id STORE_ID --config crates/userinfo-claim-worker/wrangler.production.jsonc --apply yes
```

The browser-side [directory validator](../crates/worker/ui/recipient-directory.ts) checks canonical encoding, the public-key SHA-256 ID, expected service and algorithm, and generation and revision continuity. It stores the highest observed generation, key ID, and revision in same-origin browser storage and fails closed if that checkpoint is invalid or unavailable. Clearing browser storage also clears this local checkpoint; the OP's verified D1 directory remains authoritative. The validator is prepared for the recipient-envelope flow and is not invoked by owner-only Vault operations.

The [management CLI](../scripts/recipient-key-admin.mjs) validates the public JSON digest and can stage, activate, rotate, or immediately disable a key. Every change is audited through D1 batches. Activation checks the staged key through the claim Worker; rotation checks both keys and atomically moves the old key to `decrypt_only`. `--apply no` is a dry run; a mismatch between `--remote` and the config's D1 binding is rejected. Activation and rotation require the [management service-binding config](../crates/worker/wrangler.recipient-admin.jsonc) and a provisioned, deployed claim Worker.

```sh
node scripts/recipient-key-admin.mjs --config crates/worker/wrangler.jsonc --remote no --action stage --input /private/tmp/vault-userinfo-public.json --actor operator --reason 'prepare recipient' --apply no
node scripts/recipient-key-admin.mjs --config crates/worker/wrangler.jsonc --remote no --action disable --key-id KEY_ID --actor operator --reason 'emergency stop' --apply no
node scripts/recipient-key-admin.mjs --config crates/worker/wrangler.recipient-admin.jsonc --remote yes --action activate --key-id KEY_ID --actor operator --reason 'activate verified recipient' --apply no
node scripts/recipient-key-admin.mjs --config crates/worker/wrangler.recipient-admin.jsonc --remote yes --action rotate --key-id NEW_KEY_ID --actor operator --reason 'rotate verified recipient' --apply no
node scripts/recipient-key-admin.mjs --config crates/worker/wrangler.recipient-admin.jsonc --remote yes --action verify --key-id KEY_ID --actor operator --reason 'check recipient binding' --apply yes
```

## Rotation and incident response

1. Generate an independent seed. Provision it through a protected route and stage its public key in D1. Keep any backup only under an explicit recovery procedure, outside logs and CI artifacts.
2. Deploy the claim Worker with both old and new secret bindings, and verify their public-key matches. In one D1 batch, move old `active` to `decrypt_only` and new `staged` to `active`. If the batch fails, the old key stays active.
3. Rewrap old envelopes only for attributes with valid grants, checking attribute revision and recipient key ID. After none remain and the recovery retention period passes, disable the old key and remove its binding and seed. Reject envelopes created offline for a retired generation.
4. On compromise, disable the key in D1 immediately and fail closed for reads, unwrap, and claim issuance. An attribute dependent on that key is unavailable to UserInfo until its owner unlocks and wraps it to a new key. Already disclosed plaintext cannot be recalled.

## Loss recovery policy

Secrets Store holds the only retained copy of the generation-1 seed. The temporary generation file was removed after deployment. If a seed is confirmed lost or compromised, disable its D1 key first, then provision an independent seed at a higher generation. Do not reactivate or reuse the old key ID. A recipient envelope under the lost key cannot be recovered by the claim Worker; the owner must unlock the still-retained PRF envelope and create a new recipient envelope. Until that happens, deny system recipient reads and omit the dependent UserInfo claim. A transient Secrets Store outage alone does not justify destroying the key; retry reads fail closed while operators investigate.

Before enabling sharing, test this recovery path with an attribute whose owner can unlock it, and document who can disable a key and deploy a replacement. The current active key has no recipient envelopes or Grants, so there is no shared attribute to migrate.

Recipient envelopes and grants remain future product work. A two-Worker local test covers the directory's authenticated 200 response and fail-closed 503 response. The positive response has not yet been checked with a production owner session. The Secrets Store copy is the only retained seed copy. Establish a recovery policy before relying on this key for shared attributes. Finalize HPKE suite and envelope version after interoperability checks against the [current working draft](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05).
