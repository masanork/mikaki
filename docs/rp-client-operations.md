# Managed OIDC client operations

The normal production profile accepts `private_key_jwt` with ES256 and PKCE S256. Client registration is an operator action through D1; there is no public dynamic registration endpoint. Run the commands from the repository root with the correct Wrangler config and `--remote yes` for production. Each change requires an actor and reason, is written with an audit row, and defaults to validation only (`--apply no`).

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
node scripts/client-admin.mjs --config crates/worker/wrangler.production.jsonc --remote yes --action register --input /private/path/rp-public.json --actor operator --reason 'initial RP registration' --apply no
node scripts/client-admin.mjs --config crates/worker/wrangler.production.jsonc --remote yes --action register --input /private/path/rp-public.json --actor operator --reason 'initial RP registration' --apply yes
node scripts/client-admin.mjs --config crates/worker/wrangler.production.jsonc --remote yes --action list --apply no
```

Key rotation uses an overlapping public key: `add-key` with an input file shaped as `{ "kid": "new-kid", "jwk": { ... } }`, switch the RP to the new private key, verify token exchange, then `retire-key --kid old-kid`. The CLI rejects retirement of the last active key. A suspected compromise can use `disable --client CLIENT_ID` to stop the entire client; this increments the client revision and prevents outstanding codes from being exchanged.

Redirect changes use `add-redirect` followed by RP deployment and `retire-redirect`. The input file is `{ "redirect_uri": "https://rp.example/new-callback" }`. A retired URI remains in D1 for referential integrity but cannot start new authorizations. Each URI change increments the client revision, invalidating in-flight codes. The last active redirect cannot be retired. Audit the returned `list` output after each change.

Before considering the RP ready, run an end-to-end Authorization Code flow from that RP with its exact redirect, PKCE S256, and ES256 `private_key_jwt`; verify issuer, audience, state, nonce, pairwise subject, and UserInfo. A CLI registration alone does not prove interoperability.
