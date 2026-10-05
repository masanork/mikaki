# mikaki Docs RP

This Worker serves the bilingual public guides generated from `website/` and a
separate OIDC login-state page. Reading the guides does not require sign-in. The
RP asks only for `openid`; it does not request name, email, Vault contents, or
identity credentials. Its own D1 stores transient OIDC transactions, session
identifiers/expiry and logout tombstones. Its private ES256 key is a dedicated
`RP_PRIVATE_JWK` secret and must never be copied from Mikaki OP or another RP.

The login-state page supports explicit lease checking, Docs-local logout and
Back-Channel Logout. Docs logout removes only the Docs session; it does not end
the Mikaki SSO session. Private inquiries and live E2EE messaging are separate
future work and are not implemented here.

## Local qualification

```sh
npm run build:docs
npm run check:docs-rp
node --test local/test/docs-rp.test.ts
```

The browser test uses a disposable local OP, virtual passkey and local D1. It
does not contact or change production resources. Do not put real account data
or a production signing key in local configuration.

## Production prerequisites

Before deployment, provision a dedicated RP D1 and rate-limit namespace, register
the exact `https://docs.mikaki.org/callback` redirect and
`https://docs.mikaki.org/backchannel` endpoint with the OP, and register the
matching public JWK under a dedicated client ID. Keep the matching private JWK
only in the `RP_PRIVATE_JWK` Worker secret. Apply this app's `0001_initial.sql`
to its own empty D1. The OP and every other RP retain their separate keys and
databases. `wrangler.production.jsonc` contains no secrets; substitute only the
reviewed D1 ID, ratelimit namespace and client registration IDs during
provisioning.

The production promotion workflow must verify the source-bound Docs build,
upload a new version without activating it, verify its bindings and version
metadata, then activate the reviewed version and run `/health`, login/session,
logout and version-matched readiness checks. This repository change does not
provision resources or activate the Worker.
