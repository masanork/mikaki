# Remote agent OAuth: preregistered public-client profile

**Status, 2026-09-29:** VG-05 has a locally implemented authorization server, owner login/return, consent UI and SDK/workerd/Chromium qualification. Migrations `0018`–`0019` and these endpoints are not deployed. This is a bounded public-client profile, not a claim of full OAuth 2.1 or remote Codex/Grok interoperability.

## Boundary and supported flow

The separate agent Worker is both the MCP resource server and this delegated-access AS. Its issuer is the exact HTTPS origin of `AGENT_RESOURCE`; its sole resource is the exact configured `/mcp` URL. It accepts only operator-preregistered public clients, authorization code with S256 PKCE, exact registered callbacks and explicit requested operations. Supported scopes are `list search read propose execute`; the ordinary MCP challenge recommends the three read operations. Client registration and consent do not create or broaden a Vault grant.

The authorization endpoint redirects to the configured HTTPS `/vault` page with a random request ID. When the owner session is missing or expired, this page starts a separate Rust Passkey ceremony for this live, unclaimed request. It stores a canonical same-owner-origin Vault continuation, binds the ceremony to the HttpOnly browser cookie and expires it after at most five minutes. Only `agent_oauth_request` and an optional supported `lang` are accepted; caller-provided return URLs are rejected. Migration `0019` records the request's configured owner origin; older pending requests must restart to use this login path. Login completion atomically consumes the ceremony, updates the verified credential counter and creates the owner SSO session. It issues neither an OIDC code/app connection nor an OAuth grant/token. The owner then reviews consent in Vault. A request already claimed by another/expired owner session must restart; this is not account enrollment or key recovery.

The first authenticated preview binds that request to the owner account and session hash. The dashboard shows the registered client label/ID, exact return address, resource and scopes. The owner explicitly chooses one active, already-shared grant containing every requested operation, checks consent and approves, or rejects. The grant is still limited to the explicitly shared name snapshot; `propose` does not create a note capability. Note capabilities and encrypted commits retain their separate [VG-03/04 contract](vault-approved-commit.md).

The callback contains a one-time code, the original client state and `iss`. Clients must validate state and issuer before exchange. The client exchanges the code with its verifier, exact client ID/callback and exact resource; it receives only the requested operations. The AS does not disclose the underlying `mag_` credential. Public client IDs and operator labels do not authenticate a particular bot, person or running client instance.

This AS has one TypeScript/D1 transition authority inside the isolated agent service. Rust authenticates owner sessions and forwards only server-derived identity through the named service binding. OIDC login, UserInfo and owner storage remain separate Rust authorities. [ADR 0014](adr/0014-agent-oauth-authority.md) records this additional bounded exception to the Rust direction explicitly; it is not silently covered by the proposal exception.

An optional [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) `authorization_details` profile is now locally implemented for one `mikaki_agent_snapshot` object. It requires exact MCP `locations`, the same actions as the requested scopes, `document_id: "name"`, a positive `source_revision`, and a bounded human-readable `purpose`. The owner preview shows purpose and required revision and offers only matching existing shares. The request and token retain the exact validated details; the token response returns the granted details. A mismatched resource, action, revision, unknown field or type is rejected. The purpose is a consent description carried with the authorization; it cannot confine how a client uses plaintext after disclosure. This is a Mikaki-specific profile for the current single-name snapshot, not broad RAR interoperability or proof of support in Codex/Grok. Scope-only requests keep working. Migration `0024` and this profile are not deployed.

## Discovery and endpoints

| Endpoint | Contract |
| --- | --- |
| `GET /.well-known/oauth-protected-resource/mcp` | Exact resource, scopes and, when OAuth is enabled, `authorization_servers`. The MCP 401 challenge links this document. |
| `GET /.well-known/oauth-authorization-server` | Issuer, authorization/token/revocation endpoints, `code`, `authorization_code`, S256, public-client authentication method `none`, `authorization_response_iss_parameter_supported=true`, and the optional `mikaki_agent_snapshot` authorization-details type. No registration endpoint, refresh grant or metadata-document support is advertised. |
| `GET /oauth/authorize` | Requires exactly one each of `response_type=code`, `client_id`, `redirect_uri`, `resource`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`; optionally one bounded `authorization_details`. Invalid/unregistered callbacks are rejected locally without a redirect. |
| `GET /vault?agent_oauth_request=...` | With a live owner session, shows Vault; otherwise starts the bounded owner Passkey login and returns to this request before consent. |
| `POST /vault/agents/oauth-request` | Owner same-origin JSON `{request_id}`; claims/previews a pending request through the private service binding. |
| `POST /vault/agents/oauth-decide` | Owner same-origin JSON `{request_id,grant_id,approve}`; returns the server-built callback after explicit approval/rejection. Rejection uses a null grant. Public agent fetch cannot reach this route. |
| `POST /oauth/token` | Form-encoded `grant_type=authorization_code`, `code`, `client_id`, `redirect_uri`, `resource`, `code_verifier`. No client secret or Authorization header. |
| `POST /oauth/revoke` | Form-encoded `token`, `client_id`, optional `token_type_hint=access_token`. Unknown tokens and other clients' tokens return an indistinguishable success without changing them. |

Authorization requests last ten minutes, approved codes at most two minutes within that request, and access tokens at most one hour within the selected grant. PKCE verifiers follow the 43–128 ASCII unreserved-character profile. State is required, 16–512 characters; this bound does not prove entropy. Duplicate/unknown parameters, repeated/unknown scopes and alternate resources are rejected. Authorization URLs are limited to 4 KiB. Form bodies are streamed with a 4 KiB limit; owner request bodies use a 1 KiB limit.

The AS/metadata responses and redirects use no-store; redirects and owner pages use no-referrer. Native/server HTTP clients are the first profile. Cross-origin browser clients have no CORS onboarding profile yet. OAuth service routes reject foreign browser Origins; the owner uses its separate same-origin UI bridge. TLS applies to production AS/resource URLs. Registered callbacks must be canonical HTTPS URLs or HTTP IP loopback (`127.0.0.1` / `[::1]`), without credentials/fragments or reserved callback parameters. `localhost`, arbitrary HTTP, wildcard callbacks, and variable loopback ports are not supported; ports must match the registration exactly.

## Durable authorization, failure and revocation

Approval is a conditional D1 update with an audit trigger, binding the exact request, live session, client, recipient, same-owner grant, grant revision and requested scope subset. An audit failure rolls back approval. Code/token generation uses 32 random bytes; only hashes of codes and `moa_` access tokens are stored.

Token exchange performs a guarded D1 batch: insert one token from the still-approved/unredeemed/live code and grant, mark that code redeemed, require the matching token/redemption, then clear the guard. A unique request-to-token constraint and the guard permit one winner under concurrent exchange. Token audit is in the same transaction. A failed batch leaves the code unconsumed and creates no token. Wrong verifier/client/callback/resource, expiry and revoked grants cannot consume it successfully. Token exchange currently uses a generic `invalid_grant` error for rejected or unavailable exchanges; it does not classify all transient backend failures separately.

Every bearer call resolves fresh primary state: token expiry/revocation, active registered client, exact resource, grant revision and the existing source/recipient/account/credential checks. Private draft and typed proposal side-effect statements also recheck the individual token inside their durable operation; a live grant alone cannot substitute for a revoked OAuth token. Read disclosure retains audit-before-return and a final live check. Scope is taken from the token rather than the broader parent grant. The `mag_` owner-issued path remains separate and does not acquire token scope restrictions.

Token revocation and its audit are atomic and repeat safely. Grant/source/account/credential/recipient invalidation stops every derived token; client disable stops its tokens. Logout does not recall an independent delegation. As with the original grant contract, a committed in-flight effect can exist even if its later response fails, and already delivered values cannot be recalled. Owner grant revocation remains the dashboard's way to stop all attached tokens.

Raw codes/tokens are not retained for retry acknowledgment. If the consent or successful token response is lost, restart from the client; a consumed code cannot mint another token or retrieve the lost one. The owner UI does not automatically repeat approval after such a failure. Any unreachable token remains bounded by its expiry or grant revocation. Expired owner-login records are removed after an additional day; OAuth request/token records are removed after two days by hourly cleanup; audit retains the existing 30-day window. Backups and failed cleanup jobs can extend physical retention. Logs and audit do not contain raw credentials or note contents.

## Local setup

1. Apply migrations `0018` and `0019` to the same D1 database used by the OP and agent Worker. Existing owner/agent migrations remain prerequisites.
2. Keep `AGENT_OWNER_URL` empty until the intended owner origin and profile are selected. Set it to the exact HTTPS `/vault` URL to enable metadata/endpoints and OAuth bearer access. The OP needs `MIKAKI_ISSUER` matching that owner origin and the existing `AGENT_ACCESS` service binding. The example production config defaults to disabled; local config uses `https://mikaki.test/vault`. Emptying it also stops OAuth bearer use without stopping existing owner-issued credentials.
3. Prepare a registration JSON file, for example:

```json
{
  "client_id": "native-test",
  "client_name": "Native test client",
  "redirect_uris": ["http://127.0.0.1:43123/callback"]
}
```

4. `node scripts/agent-oauth-client.ts REGISTRATION_JSON NEW_SQL_FILE` validates the profile and writes quoted SQL to a new file. It does not change any database. Review/apply that file through the ordinary local D1 administration workflow. Existing registrations are immutable; disable with `UPDATE agent_oauth_client SET active=0 WHERE client_id=...` and use a new client ID to change callbacks. Disabled registrations cannot be restored/deleted.
5. Configure the native client with that preregistered ID, exact callback, public authentication method `none` and the MCP resource URL. Explicitly prepare a shared snapshot/grant in Vault before connecting; an expired owner session can now sign in and return to consent without broadening that grant.

## Named client requirements and evidence

| Client | Current requirement/evidence | Remaining gate |
| --- | --- | --- |
| Codex CLI / App Server 0.157.1; local CLI 0.159.1 | On 2026-09-29, the Linux CLI in a disposable container completed discovery, exact preregistered callback, S256 code exchange and credential-file persistence. Two fresh App Server processes read the synthetic snapshot using that saved token; a write was denied under read scopes and token revocation stopped a later read. The 2026-09-30 installed 0.159.1 local request again used preregistration, exact callback, resource and S256, with scopes only and no `authorization_details`; it stopped before token exchange. No model turn was run. | Qualify the intended deployed endpoint, intended owner device and operational setup; RAR needs a client that actually sends the Mikaki detail type. This is local workerd/isolated-client evidence with synthetic data. |
| Grok Build 1.0.41 | Official docs describe remote HTTP and browser OAuth on first use. Installed `mcp add`/`doctor` help exposes no preregistered client-ID/fixed-callback option; docs do not specify registration strategy or callback. Prior stdio handshake/tool discovery is separate evidence. | Capture actual interactive HTTP OAuth requests in an isolated Grok Build environment; establish client identity/registration, callback and token/refresh requirements. Missing documentation does not prove DCR is mandatory. |
| Grok Bot (persistent cloud-computer product launched August 2026) | Official Bot docs describe account-wide Marketplace plugins, with connector tokens on Cursor's backend; browser/files/CLI credentials on the computer are shared between that user's Bots. The installed app's Marketplace route was observed read-only on 2026-09-29. Cursor documents static OAuth `auth.CLIENT_ID`, explicit scopes and a hosted HTTPS callback. | Confirm that the Bot's actual plugin path accepts the chosen static public client and sends compatible PKCE/resource/token requests. Cursor IDE docs and Grok Build/grok.com connector evidence do not prove this. See [Bot qualification](grok-bot-integration.md). |

For the qualified Codex request profile, register the exact callback first, then configure:

```toml
[mcp_servers.mikaki]
url = "https://YOUR_AGENT_ORIGIN/mcp"

[mcp_servers.mikaki.oauth]
client_id = "YOUR_PREREGISTERED_ID"
callback_port = 43123
callback_url = "http://127.0.0.1:43123/callback"
```

Start with `codex mcp login mikaki --scopes list,search,read`. The AS advertises RFC 9207 issuer support and returns `iss` so Codex can reuse the preregistered callback. Use a free port matching the registration. Do not put a client secret into this public-client profile.

`node scripts/probe-agent-oauth-clients.ts` repeats the native installed-Codex discovery/request probe against disposable paired workerd databases and an ephemeral local TLS certificate trusted via `CODEX_CA_CERTIFICATE`. It stops before callback/token exchange and therefore does not persist OAuth credentials. It prints only version and validation results; PKCE/state/authorization URLs are not printed. This mode requires installed Codex/OpenSSL. For the complete isolated-client run:

```sh
docker build -t mikaki-codex-oauth-probe:0.157.1 local/conformance/agent-clients
npm run probe:agent-oauth-clients -- --container
```

The complete mode uses the pinned official npm Codex package in a disposable Linux container, its own default credential directory and a copied public CA certificate. It binds the temporary TLS proxy for container reachability, using Docker's `host.docker.internal` host mapping. No host HOME/CODEX_HOME override, user credential file, API key, model turn or production Vault is used. Owner consent is a synthetic authenticated fixture through the real private OP/agent bridge; the separate Chromium test qualifies the owner-facing review/login UI. App Server `mcpServer/tool/call` exercises actual reads, narrow-scope denial, persistence across new processes and token revocation. The script stops/removes the test container and deletes temporary TLS material even on failure; the pinned image stays available for reuse. Both modes are optional local qualification, not required CI tests or a Grok Bot proof.

Sources checked on 2026-09-28/29: [Codex config reference](https://learn.chatgpt.com/docs/config-file/config-reference), [Codex authentication and certificate trust](https://learn.chatgpt.com/docs/auth), [Grok Build MCP](https://docs.x.ai/build/features/mcp-servers), [Grok connector management](https://docs.x.ai/grok/connector-management), [Grok Bot computer/plugins](https://docs.x.ai/grok-bot/computer-and-apps), [Cursor static OAuth](https://cursor.com/docs/mcp), [Codex App Server](https://learn.chatgpt.com/docs/app-server). These client requirements motivate RFC 9207 metadata; they do not justify advertising unimplemented DCR/CIMD or refresh.

## Qualification and next gates

On 2026-09-29, the optional pinned Linux Codex CLI/App Server probe passed code exchange, credential persistence, synthetic MCP reads from two fresh processes, narrow-scope denial and individual token revocation. The primary D1 audit recorded exactly two authorized reads and two denied proposals, no proposal was created, and the only OAuth token was revoked. Strict Node checks, formatting, product-source and local documentation-link checks passed. The native Mac discovery/request mode also passed. No production activation or Grok Bot tool call is claimed.

On 2026-09-30, the installed Codex CLI 0.159.1 discovery/request probe passed again. Its request contained no `authorization_details`, confirming that the current real-client path exercises the scope-only fallback rather than qualifying RAR. The optional RAR type is covered by workerd owner-consent/token tests; a supporting client remains to be selected.

On 2026-09-28, the combined OAuth/agent/browser/proposal/encrypted-commit regression run passed all eight tests, including expired-session owner login/return. The separate existing enrollment/login browser regression also passed after aligning stale color/button selectors and the injected cancellation retry. The release Worker/UI build, strict Node/agent/UI checks, Rust Clippy with warnings denied, formatting, all 235 bilingual message keys, product-source checks and local documentation links passed. A registration-script smoke check applied its generated SQL locally and preserved a label containing a quote without executing additional SQL.

`npm run test:agent-oauth` validates registrations and exercises paired real workerd Workers/D1/R2, the official MCP SDK and Chromium owner consent with synthetic data. Cases cover both discovery documents, PKCE, exact callback/resource/client binding, owner/session isolation, CSRF Origin rejection, scope narrowing, missing consent, rejection, grant scope mismatch, consent/token/revocation audit rollback, concurrent one-winner exchange, code/request/token expiry, individual token revocation, client retirement, and parent-grant revocation. Read access, private-draft approval/execution and a separately enabled note proposal are exercised. The owner browser uses a Chromium virtual authenticator with a real ES256 assertion for login/return and does not unlock a PRF key for existing-snapshot consent. Login tests reject foreign/duplicate/extra/unknown requests, expired requests, mismatched configured owner origins and unbound browser cookies; they exercise bounded pending login ceremonies, SSO-insert rollback, counter rollback, one-time login consumption and login without OAuth approval/token or OIDC app connection. The existing enrollment/login regression is also checked.

Remaining VG-05 work: qualify the intended deployed Codex endpoint and actual Grok Bot plugin registration/callback flow; keep Grok Build and grok.com connectors separate; decide a bounded client metadata/DCR profile if actual clients require it; decide refresh only from client/use-case evidence; add public AS abuse controls and production provisioning/rotation/recovery/deployment evidence. The existing 100 pending requests per client and 1,000 globally are durable bounds, not a production abuse-control qualification. No deployment, real-device proof or real user data disclosure was performed.

Protocol references: [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414), [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728), [PKCE RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), [resource indicators RFC 8707](https://www.rfc-editor.org/rfc/rfc8707), [OAuth security BCP RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), [revocation RFC 7009](https://www.rfc-editor.org/rfc/rfc7009), [AS issuer identification RFC 9207](https://www.rfc-editor.org/rfc/rfc9207).
