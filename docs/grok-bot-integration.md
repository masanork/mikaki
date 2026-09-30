# Grok Bot hosted-plugin qualification

**Status, 2026-09-29:** this target is the persistent cloud-computer Grok Bot launched on August 11, 2026. It is separate from Grok Build CLI, X's reply bot and grok.com Business connectors. Official docs and the installed desktop app's Marketplace/settings were inspected read-only. No plugin was installed, bot message sent, external account permission changed or production data disclosed. Bot interoperability remains unqualified.

## Boundary that matters for Mikaki

Grok Bot's computer, browser sessions, files and CLI credentials are shared by every Bot in one user account. Marketplace connectors are also account-wide; their OAuth tokens stay on Cursor's connector backend rather than on the cloud computer. A Bot label is therefore a disclosure label, not an isolated cryptographic recipient. Design authorization for the account/connector's selected grant, and retain separate owner approval for each write. Bot deletion, uninstalling a plugin or stopping a routine must not substitute for revoking the Mikaki grant/token. Delivered snapshots and downloaded files cannot be recalled by token revocation.

The observed desktop app opens Marketplace from **Connect apps**, with packaged plugins and authentication. **Manage plugins and skills** showed installed connectors and private skills, but no custom MCP URL/import action; inspected settings also did not expose one. This limited observation does not prove that another account, team dashboard or app version has no such route. Do not apply grok.com **New Connector → Custom** instructions to this product without evidence.

Cursor documents a private distribution route on Teams/Enterprise: **Dashboard → Plugins & MCPs → Team Marketplaces → Add Marketplace → Import from Repo**. Audience access and opt-in **Default Off** installation should be reviewed before adding a synthetic test plugin. This documents Cursor distribution, not confirmed Grok Bot availability. Public marketplace submission requires a public repository and manual review; local `~/.cursor/plugins/local` loading is a separate Cursor IDE path.

### Account-route observation, 2026-09-29

Safari required sign-in, but Chrome had an existing authenticated session. No new sign-in or terms acceptance was needed. The dashboard showed **Free (with SuperGrok)**. Its sidebar exposed Overview, Settings, Integrations and Spending; the official documentation's direct [Plugins & MCPs URL](https://cursor.com/dashboard/plugins) nevertheless opened the personal plugin management page. That page showed installed plugin entries, filters, search, suggestions and **Add**. Clicking **Add** opened the public marketplace in another tab; it did not open a custom MCP form or private repository importer. The inspected account menu exposed no team selector. No Team Marketplaces/Add Marketplace/Import from Repo controls were observed.

The blocker is therefore the supported custom-plugin distribution route for the inspected account, not missing browser authentication. These observations do not prove that all personal accounts or future app versions lack a route, and do not qualify team-distributed plugins in Grok Bot. A paid upgrade is not a justified next step until actual Bot support through that route is established. The alternatives to establish are a provider-supported personal/private test route, an existing eligible team with verified Bot distribution, or a separately reviewed public marketplace submission. No purchase, repository upload, publication, installation, connector authorization or Bot task was performed.

## Candidate package and public registration

[The draft package](../integrations/grok-bot/README.md) uses Cursor's documented `.cursor-plugin/plugin.json` and `mcp.json` format, static public `auth.CLIENT_ID` and exactly `list search read`. Variables contain only the operator-approved resource URL and public client ID. There is no client secret, bearer credential, owner SSO cookie, PRF output or Vault key. Cursor documents the hosted callback:

```text
https://www.cursor.com/agents/mcp/oauth/callback
```

That exact HTTPS callback fits Mikaki's current preregistration validator. Cursor's separately documented desktop callback `http://localhost:8787/callback` does not fit the current IP-loopback-only profile. Do not loosen that profile, register arbitrary callback ports or advertise DCR merely to cover an unobserved Bot flow.

The package is a reviewable candidate, not an installed or provider-validated plugin. Static OAuth and variable interpolation are documented for Cursor plugins/MCP; acceptance and substitution through Grok Bot's hosted plugin path still need verification. Confirm the observed callback before preregistration or publication. [Registration preparation](agent-oauth.md#local-setup) writes reviewable SQL and does not apply it.

### Standalone preparation

`node scripts/prepare-grok-bot.ts CONFIG_JSON NEW_DIRECTORY` prepares a separate marketplace repository layout, concrete read-only MCP config, registration JSON/SQL and an initially pending qualification record. Start with [the example configuration](../integrations/grok-bot/configuration.example.json), replace its non-working `.example` resource with the operator-approved synthetic test service, and retain the documented candidate callback until the actual request is observed. The command requires a canonical HTTPS `/mcp` resource, validates the same public registration profile as the server, rejects unknown fields/secrets and refuses an existing output directory. It never publishes, installs, modifies a database or makes network requests.

The prepared plugin contains concrete public endpoint/client ID values and omits variables; this makes a first hosted test independent of variable interpolation support. The original parameterized candidate remains available for a later configuration-UI check. Only the explicit manifest/config/document files are packaged; the Mikaki repository, local credentials and Vault data are not copied. Upload/import and provider acceptance remain separate steps. Automated preparation tests cover credential-bearing/ambiguous URLs, unknown secret fields, unobserved callbacks, scope narrowing and preservation of existing operator files.

### Inspect the observed request safely

Use `node scripts/inspect-grok-bot-oauth.ts CONFIG_JSON < PRIVATE_URL_FILE` to inspect the actual authorization URL offline. Keep the capture outside the repository in an owner-readable temporary file; do not put the URL in command arguments, shell history, a ticket or a checked-in artifact. `CONFIG_JSON` is the approved preparation configuration, not the provider's captured input. This command makes no network requests and writes no files. It compares the authorization endpoint, public client ID, exact callback/resource, code response type, unique allowed parameters, read-only scopes, state length and S256 challenge format against the current bounded profile.

Only booleans/counts and known scope flags appear in the report. Actual URL/parameter values, including mismatched client/callback/resource, state, challenge, unknown parameter names, codes and tokens, are omitted. Parser/configuration errors are also sanitized. Exit status is `0` for a compatible request, `1` for a profile mismatch and `2` for invalid/oversized input. Neither `0` nor `authorize_request_only` proves code exchange, owner consent, token persistence or a working Bot connection; those remain independent pending checks. Unknown extensions are reported as an incompatibility to examine, rather than silently ignored or reflected into logs. A state-length/challenge-format check does not prove entropy or the subsequent verifier check.

Run `npm run test:agent-preparation` for preparation and redaction regression coverage; these checks are also included in CI. As of 2026-09-29, the inspector has passed synthetic request and negative/redaction tests only. Dashboard authentication was resolved through the existing Chrome session; custom-plugin distribution remains unresolved as recorded above. No actual Grok Bot authorization request has been captured.

## Next concrete checks

1. Establish a supported custom-plugin distribution route: the inspected personal dashboard's Add action opened only the public marketplace. Verify a provider-supported private test route or a separately reviewed distribution decision before installation. Confirm the hosted runtime accepts static public OAuth; use the prepared concrete config first and qualify the original two-variable configuration separately.
2. Use a reachable test agent service with disposable synthetic snapshots. Record actual client ID, exact callback, response type, PKCE method, state length, resource and requested scopes; log metadata/results only, never state, codes, verifiers or tokens.
3. Complete owner-device login/consent and provider callback. Prove reads contain only the selected snapshot, scope narrowing rejects writes, a new session reuses credentials, and expiry/token/client/grant revocation stops future reads. Observe cancellation, lost consent response and unavailable service behavior.
4. Check delivery boundaries: hosted connector versus manual browser/CLI, account-wide availability, connector-result logs/files and copied artifacts. Keep owner Passkey/PRF and Vault cookies off the Bot computer; that computer must not become a general owner Vault session.
5. Only then decide whether the observed flow needs DCR/CIMD, refresh or a changed callback profile. Deployed service provisioning, key rotation, abuse controls and recovery remain independent gates.

The isolated Codex success is useful evidence for the shared OAuth/resource contract; it cannot establish this hosted client's implementation or supported installation route.

Sources: [Grok Bot launch](https://x.ai/news/introducing-grok-bot), [computer and plugins](https://docs.x.ai/grok-bot/computer-and-apps), [connector credential boundary](https://docs.x.ai/grok-bot/security), [Cursor static OAuth](https://cursor.com/docs/mcp), [Cursor distribution routes](https://prod.cursor.com/docs/plugins), [Cursor plugin format](https://prod.cursor.com/docs/reference/plugins). Reviewed on 2026-09-29.
