# Managed OIDC client operations

This is the mikaki operator runbook. RP implementers should start with [RP integration](rp-integration.md).

This procedure covers confidential web RPs, which use ES256 `private_key_jwt` and PKCE S256. Production also has a separate native public client with `auth_method=none` and mandatory PKCE; the current CLI supports `register-native`, with separate native callback validation. Client registration is an operator action through D1; there is no public dynamic registration endpoint. Run the web-client commands from the repository root with the correct Wrangler config and `--remote yes` for production. Each change requires an actor and reason, is written with an audit row, and defaults to validation only (`--apply no`).

Apply D1 migrations before using the CLI. The registration input is a local JSON file containing only the RP's **public** JWK:

```json
{
  "client_id": "00000000-0000-4000-8000-000000000001",
  "sector_identifier": "rp.example",
  "redirect_uris": ["https://rp.example/oidc/callback"],
  "key": {
    "kid": "rp-2026-09",
    "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
  }
}
```

Generate a fresh UUIDv4 for each client and environment. Replace the example coordinates with the RP's public P-256 coordinates. The CLI rejects private JWK fields, non-HTTPS or noncanonical redirects, duplicate redirects, and redirects outside the registered sector host. Keep the private key in the RP's secret store.

```sh
node scripts/client-admin.ts --config crates/worker/wrangler.production.jsonc --remote yes --action register --input /private/path/rp-public.json --actor operator --reason 'initial RP registration' --apply no
node scripts/client-admin.ts --config crates/worker/wrangler.production.jsonc --remote yes --action register --input /private/path/rp-public.json --actor operator --reason 'initial RP registration' --apply yes
node scripts/client-admin.ts --config crates/worker/wrangler.production.jsonc --remote yes --action list --apply no
```

Key rotation uses an overlapping public key: `add-key` with an input file shaped as `{ "kid": "new-kid", "jwk": { ... } }`, switch the RP to the new private key, verify token exchange, then `retire-key --kid old-kid`. The CLI rejects retirement of the last active key. A suspected compromise can use `disable --client CLIENT_ID` to stop the entire client; this increments the client revision and prevents outstanding codes from being exchanged.

Redirect changes use `add-redirect` followed by RP deployment and `retire-redirect`. The input file is `{ "redirect_uri": "https://rp.example/new-callback" }`. A retired URI remains in D1 for referential integrity but cannot start new authorizations. Each URI change increments the client revision, invalidating in-flight codes. The last active redirect cannot be retired. Audit the returned `list` output after each change.

Register logout destinations separately. Use `add-post-logout-redirect` with `{ "post_logout_redirect_uri": "https://rp.example/logout/callback" }` and `set-backchannel-logout` with `{ "backchannel_logout_uri": "https://rp.example/backchannel" }`; supply `--client`, `--input`, `--actor`, `--reason`, and `--apply` as above. Both URLs must be canonical HTTPS on the client's sector host. The post-logout redirect uses an exact-match list of at most eight active URLs; use `retire-post-logout-redirect` to disable an old one. `set-backchannel-logout` replaces the single active delivery endpoint; `retire-backchannel-logout` disables it. Check `list` after changes. The OP logout endpoints are deployed, but registering destinations alone does not prove that a particular RP receives and processes notifications; verify it end to end.

Before considering the RP ready, run an end-to-end Authorization Code flow from that RP with its exact redirect, PKCE S256, and ES256 `private_key_jwt`; verify issuer, audience, state, nonce, pairwise subject, and UserInfo. A CLI registration alone does not prove interoperability.

## Historical production inventory before the 2026-10-05 reset

The 2026-10-04 observation below came from the pre-reset `mikaki-auth` database. It is historical and must not be used as the current client inventory or as a source for recreating registrations or keys. The 2026-10-05 production reset replaced that database with the configured `mikaki-auth-owner` database.

| Client                                 | Method            | Exact callback                                | Active backchannel                    |
| -------------------------------------- | ----------------- | --------------------------------------------- | ------------------------------------- |
| `77551450-ec73-4222-972d-cd912d9493d4` | `private_key_jwt` | `https://demo.mikaki.org/callback`            | `https://demo.mikaki.org/backchannel` |
| `dfd936fd-f33d-4f82-ae39-f25e08ec7948` | `none`            | `https://app.mikaki.org/oidc/native/callback` | None                                  |

Both registrations were revision 1; only the confidential demo RP had a registered ES256 public key. Neither had a post-logout redirect. These rows described the deployment before reset; they do not describe the current production target.

## Current production target, observed 2026-10-06

A read-only six-query preflight of the configured OP D1 reported zero rows written and `changed_db=false`. The current Docs RP registration is:

| Client ID                              | Type / method             | Client revision / active | Key ID / algorithm / active          | Callback                           | Post-logout redirect | Backchannel logout                    |
| -------------------------------------- | ------------------------- | ------------------------ | ------------------------------------ | ---------------------------------- | -------------------- | ------------------------------------- |
| `301abb06-5573-42bb-a924-434ecf75dd06` | `web` / `private_key_jwt` | `1` / yes                | `mikaki-docs-20261005` / ES256 / yes | `https://docs.mikaki.org/callback` | None registered      | `https://docs.mikaki.org/backchannel` |

The client has `allow_missing_pkce=0` and sector `docs.mikaki.org`. The OP's managed-session policy row is lease TTL 300 seconds, app idle timeout 604800 seconds, revision 1. Main source-bound deployment CI run [37446468520](https://github.com/masanork/mikaki/actions/runs/37446468520) completed successfully for source `c6c3b05cbf0bd23db941f00f7eb3af02961b785b`. The observed active production versions are OP `7e07ca19-fd05-4034-a586-4257aff354b0` and Docs Worker `16c13bcb-d831-49c7-b788-acc0afc62ac0`. Deployment and D1-registration checks do not establish a successful browser login, owner Passkey flow, or end-to-end Back-Channel Logout. Investigation tied the Chrome attempt's generic invalid-request response before Passkey to the Docs form's no-referrer behavior: its `formOrigin` is `null` at the Docs RP's exact-origin check. The Docs RP source now inherits the shared strict-origin policy to preserve the real browser form Origin; its exact-origin and CSRF checks remain unchanged. This source update is not represented by the deployment observation above; its rollout and qualification are tracked in issues #4 and #6. Issues #4 and #6 remain open for the outstanding real-RP and session/logout qualification. No client, key, policy, or user/session data was changed by the preflight.
