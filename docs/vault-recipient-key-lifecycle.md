# UserInfo recipient-key lifecycle

**Status, 2026-09-23:** The claim Worker verification route, OP service binding, owner-authenticated directory route, D1 constraints, and audited staging/activation/rotation/emergency-disable CLI exist. No private seed has been provisioned into Secrets Store, no key has been activated, and no grant or claim-sharing flow is enabled.

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

The [example Wrangler config](../crates/userinfo-claim-worker/wrangler.example.jsonc) reads the OP's D1 and declares a Secrets Store binding per key. It is not deployable until actual store IDs and names are set. `workers_dev: false` and no route leave it without a public HTTP entry point; the OP will use a service binding. Adding a key requires a binding deployment; disabling one is a D1 operation.

The [management CLI](../scripts/recipient-key-admin.mjs) validates the public JSON digest and can stage, activate, rotate, or immediately disable a key. Every change is audited through D1 batches. Activation checks the staged key through the claim Worker; rotation checks both keys and atomically moves the old key to `decrypt_only`. `--apply no` is a dry run; a mismatch between `--remote` and the config's D1 binding is rejected. Activation and rotation require the [management service-binding config](../crates/worker/wrangler.recipient-admin.jsonc) and a provisioned, deployed claim Worker.

```sh
node scripts/recipient-key-admin.mjs --config crates/worker/wrangler.jsonc --remote no --action stage --input /private/tmp/vault-userinfo-public.json --actor operator --reason 'prepare recipient' --apply no
node scripts/recipient-key-admin.mjs --config crates/worker/wrangler.jsonc --remote no --action disable --key-id KEY_ID --actor operator --reason 'emergency stop' --apply no
node scripts/recipient-key-admin.mjs --config crates/worker/wrangler.recipient-admin.jsonc --remote yes --action activate --key-id KEY_ID --actor operator --reason 'activate verified recipient' --apply no
node scripts/recipient-key-admin.mjs --config crates/worker/wrangler.recipient-admin.jsonc --remote yes --action rotate --key-id NEW_KEY_ID --actor operator --reason 'rotate verified recipient' --apply no
```

## Rotation and incident response

1. Generate an independent seed. Provision it through a protected route and stage its public key in D1. Keep any backup only under an explicit recovery procedure, outside logs and CI artifacts.
2. Deploy the claim Worker with both old and new secret bindings, and verify their public-key matches. In one D1 batch, move old `active` to `decrypt_only` and new `staged` to `active`. If the batch fails, the old key stays active.
3. Rewrap old envelopes only for attributes with valid grants, checking attribute revision and recipient key ID. After none remain and the recovery retention period passes, disable the old key and remove its binding and seed. Reject envelopes created offline for a retired generation.
4. On compromise, disable the key in D1 immediately and fail closed for reads, unwrap, and claim issuance. An attribute dependent on that key is unavailable to UserInfo until its owner unlocks and wraps it to a new key. Already disclosed plaintext cannot be recalled.

Recipient envelopes and grants remain future product work. The directory is unavailable until a matching seed is provisioned; browser use must also enforce key-ID and generation continuity checks. Finalize HPKE suite and envelope version after interoperability checks against the [current working draft](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05).
