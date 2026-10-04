# Explicit agent access

This separate Worker decrypts only owner-approved snapshot copies. It exposes stateless, JSON-response Streamable HTTP MCP at `/mcp`, with `mikaki_list`, `mikaki_search`, `mikaki_read`, `mikaki_propose`, and `mikaki_execute`. Remote grants require explicit `storage_version: 2` and select one saved `name` or `owner_note` record with its exact source and owner-key authority. Legacy v1 grants cannot authorize access; historical rows retain owner revocation and expiry cleanup. See the [product contract and evidence](../../docs/agent-integration.md).

## Trust boundary

The public default entrypoint accepts a separate opaque agent bearer credential; it does not accept SSO cookies, ID Tokens, UserInfo tokens, or owner identity headers. Only the OP binds to the named `OwnerAgents` entrypoint. The OP checks its owner session and same-origin POST and forwards server-derived account/session-hash headers, stripping caller headers. The named entrypoint rechecks the actual SSO, credential, and account in the shared database before owner operations. Do not bind untrusted Workers to `OwnerAgents`.

The browser encrypts a selected copy to the dedicated agent recipient. The service can decrypt that copy and release it to the bearer credential holder. Delegate/provider names are disclosure labels, not proof of bot/provider identity. In a shared Grok Bot account, a credential may be available to every Bot; bot display names do not isolate credentials. A separate connection is required for each intended access boundary.

## Local verification

The paired configs are `../worker/wrangler.agent-local.jsonc` and `wrangler.local.jsonc`. Both bind the **same** local OP D1 database. Tests provision an ephemeral recipient key and register its thumbprint; all test storage is disposable.

```sh
design/probes/workers-rs/target/tools/bin/worker-build --release crates/worker
npm run check:agent-worker
npm run test:agents
npm run test:agent-integration
```

`env.d.ts` contains Wrangler-generated binding types; runtime types come from the installed Workers types package. To regenerate after config changes:

```sh
cp -n crates/agent-worker/.dev.vars.example crates/agent-worker/.dev.vars
npx wrangler types --config crates/agent-worker/wrangler.local.jsonc \
  crates/agent-worker/env.d.ts --include-runtime=false --strict-vars=false
```

The example secret is `{}` and cannot decrypt or enable a service. Do not replace an existing local secret file when copying the example. An optional `node scripts/probe-agent-clients.ts` runs installed Codex/Grok CLIs against synthetic stdio data and writes private diagnostic output under ignored `local/generated/agent-client-probe/`.

## Provisioning and activation

`wrangler.example.jsonc` is an unconfigured template, not a production target. Set a dedicated HTTPS hostname/resource, the operator account, and the OP's actual D1 binding. Keep the database shared: authorization uses account, credential, and saved-name state in the OP database. Apply migration `0014_agent_delegation.sql` before either service queries the new tables.

Generate a **new dedicated** recipient key with exclusive creation and a mode-0600 secrets file:

```sh
node scripts/agent-recipient-key.ts local/generated/agent-recipient-secrets.json
```

This prints only the public JWK/thumbprint and output path. Never use the OP signing key, owner Vault keys, or UserInfo claim seed. Save a protected backup of the recipient key if active copies must survive Worker recovery.

An operator registers the printed thumbprint in the target D1 using an audited administrative operation:

```sql
INSERT INTO agent_recipient_key(key_id,state) VALUES('PRINTED_THUMBPRINT','active');
```

A missing/stopped registration prevents creation or disclosure. Deploy the configured recipient Worker with its dedicated secrets file, then add the following service binding to the intended OP config and deploy the OP with its existing signing/claim secrets intact:

```json
{ "binding": "AGENT_ACCESS", "service": "YOUR_AGENT_WORKER_NAME", "entrypoint": "OwnerAgents" }
```

Do not publish the owner entrypoint as a default fetch route, copy it into public routing, or use caller-supplied owner headers. The public service needs abuse controls at its hostname before activation. Production activation has not been performed by the implementation tests.

To stop a recipient, update its state through the operator's D1 administration path:

```sql
UPDATE agent_recipient_key SET state='disabled' WHERE key_id='THUMBPRINT';
```

The same transaction revokes its grants, erases snapshots, and rejects unexecuted proposals. The key tombstone cannot be deleted or re-enabled. For rotation, provision/register a new key, switch the secret, stop the previous key, and ask owners to share again. The Worker uses only its currently configured key; there is no overlapping decryption or automatic rewrap. A failed/missing secret never falls back to another recipient.

## Remote client configuration

The owner unlocks Vault, selects the saved name, sets delegate/provider, expiry and optional draft scope, approves disclosure, and creates remote access. Copy the displayed credential to a client-controlled secret store. The plaintext credential is not returned by later dashboard reads and is not stored in browser local/session storage. A lost response can retry the same request/credential while the page retains it; after a reload, revoke a connection whose credential was lost and create another.

For Codex, use its documented bearer environment variable rather than putting a token in the URL or TOML:

```toml
[mcp_servers.mikaki_agent]
url = "https://YOUR_AGENT_HOST/mcp"
bearer_token_env_var = "MIKAKI_AGENT_TOKEN"
```

Grok Build supports remote HTTP servers with environment expansion:

```toml
[mcp_servers.mikaki_agent]
url = "https://YOUR_AGENT_HOST/mcp"
headers = { Authorization = "Bearer ${MIKAKI_AGENT_TOKEN}" }
```

These are configuration examples, not recorded production connections. If a model also has shell access, an environment credential is available within that shell's boundary; it does not isolate credentials from the model's computer. An xAI API integration can pass the same header to its remote MCP tool. Grok Bot marketplace/connector onboarding has not been verified.

The owner-issued bearer path remains available. A first preregistered public-client OAuth profile now adds AS discovery, exact resource/callback binding, S256 PKCE, explicit owner selection of an existing grant, narrowed access tokens and individual token revocation. It is locally qualified with the MCP SDK and Chromium; the example production configuration defaults to disabled. Read the [OAuth setup and failure contract](../../docs/agent-oauth.md) before enabling it. Bounded Rust owner Passkey login/return is locally tested and installed Codex discovery plus a preregistered PKCE request are qualified. Deployed Codex endpoint and actual Grok Bot plugin registration/callback qualification, dynamic registration, refresh/device grants and production activation remain open; the OP confidential OIDC profile is separate.

## State, failure, and retention

Grants last 60 seconds to 24 hours with at most 20 simultaneously active grants per owner. Source revision changes, source deletion, credential stop, account stop/epoch advancement, and recipient stop irrevocably invalidate affected grants. Human SSO logout does not terminate independent delegation. Owner individual/all-grant revocation erases the stored snapshot and rejects pending/approved proposals. Validity is checked against fresh primary D1 state at authorization, audit commitment, and immediately before disclosure. Already authorized in-flight responses or delivered data cannot be recalled.

A grant creation commits the record and audit in one batch. Identical retries return the recorded outcome, changed retries fail, and audit failure rolls back. Read disclosure fails on audit failure. Proposal IDs are payload-bound; owners approve the exact title/body digest and current grant revision. Execution atomically stores one private draft and its audit/result; identical concurrent retries return that draft ID. If revocation races an operation that committed, the recorded effect can exist even if the response fails; dashboard/audit state is the authoritative outcome. There are no outbound send/publish/code-execution effects.

Draft bodies are plaintext, held outside the encrypted Vault. Unexecuted proposal bodies are cleared at proposal expiry (at most one hour), and draft copies are deleted after 30 days by an hourly cleanup trigger. Expired snapshot ciphertext is cleared on cleanup; revoked snapshots are cleared immediately. Audit contains operation/target/outcome/time, not bodies, queries, credentials, or rejected IDs. Expired metadata is collected after its 30-day audit/retry window. Backups can retain prior bytes; deletion does not promise erasure from backups or external AI providers. Audit is not protected against an operator modifying the database.
