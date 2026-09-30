# Mikaki hosted-plugin candidate

This reviewable Cursor-format package targets the new Grok Bot hosted plugin path. It is not installed, published or qualified with that provider. See [qualification and source references](../../docs/grok-bot-integration.md).

Before installation, select an operator-approved HTTPS `/mcp` endpoint and a preregistered public client ID with the observed exact hosted callback. Configure `MIKAKI_AGENT_RESOURCE` and `MIKAKI_AGENT_CLIENT_ID` through the supported plugin configuration UI. The schema intentionally has no credentials, secrets or default endpoint. The first requested scopes are `list search read`; owner consent still selects one existing shared grant.

The manifest and MCP config follow documented Cursor fields. `registration.example.json` is a candidate registration for the documented hosted callback; confirm the actual Bot callback before applying it. Generate reviewable SQL with `node scripts/agent-oauth-client.ts integrations/grok-bot/registration.example.json NEW_SQL_FILE`; this command does not modify a database. Grok Bot's actual distribution route, static public OAuth, variable substitution and callback/resource behavior remain provider qualification gates. Do not publish the candidate or add account permissions until those checks are complete. All Bots in the account can access an installed connector; per-Bot labels do not isolate credentials or approved results.

For a standalone private test repository, copy `configuration.example.json`, set its approved synthetic HTTPS `/mcp` resource and public registration, then run from the Mikaki repository:

```sh
node scripts/prepare-grok-bot.ts CONFIG_JSON NEW_DIRECTORY
node --test scripts/prepare-grok-bot.test.ts
```

The output has a root `.cursor-plugin/marketplace.json`, one plugin with concrete non-secret values, registration SQL and a pending qualification record. It contains no runtime credentials and is never uploaded or applied by this command. Existing destinations are rejected. The `.example` resource is only a preparation example, not a reachable service. Cursor documents private repo import through Teams/Enterprise Dashboard → Plugins & MCPs; actual Grok Bot distribution through that route remains unverified. Use a separate test repository and opt-in installation rather than importing the full Mikaki source tree.

After observing a real provider authorization URL, compare it offline with `node scripts/inspect-grok-bot-oauth.ts CONFIG_JSON < PRIVATE_URL_FILE`. Keep the raw capture outside the repository and out of shell arguments/history. Reports omit all received parameter values and mark evidence as request-only. See [safe capture and remaining connection gates](../../docs/grok-bot-integration.md#inspect-the-observed-request-safely). `npm run test:agent-preparation` checks both package preparation and report redaction.
