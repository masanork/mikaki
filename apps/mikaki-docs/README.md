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

## Production deployment and qualification

Docs RP is deployed at `https://docs.mikaki.org` with its own D1, rate-limit
namespace and `RP_PRIVATE_JWK` Worker secret. Its current OP client registration
uses client ID `301abb06-5573-42bb-a924-434ecf75dd06`, method
`private_key_jwt`, the exact callback `https://docs.mikaki.org/callback`, and
the Back-Channel Logout endpoint `https://docs.mikaki.org/backchannel`. The
registration has no post-logout redirect. Current production inventory and
session-policy observations are recorded in the [OIDC client operations
runbook](../../docs/rp-client-operations.md). Keep the private JWK only in the
Worker secret; do not copy it from the OP or another RP.

The source-bound production workflow verifies the prepared Docs build and its
bindings before activation. On 2026-10-06, main workflow run
[37446468520](https://github.com/masanork/mikaki/actions/runs/37446468520)
completed successfully for source
`c6c3b05cbf0bd23db941f00f7eb3af02961b785b`; the observed active OP and Docs
Worker versions were `7e07ca19-fd05-4034-a586-4257aff354b0` and
`16c13bcb-d831-49c7-b788-acc0afc62ac0`. This proves deployment and configured registration, not a
successful live login. A production browser attempt returned a generic
invalid-request response before reaching the Passkey step. Investigation tied
it to the Docs form's no-referrer behavior: `formOrigin` is `null` at the Docs
RP's exact-origin check. The Docs RP source now inherits the shared
strict-origin policy to preserve the real browser form Origin; its exact-origin
and CSRF checks remain unchanged. This source update is not represented by the
deployment observation above; its rollout and qualification are tracked in
issues #4 and #6. Real-owner Passkey/browser login and end-to-end Back-Channel
Logout qualification remain outstanding. Do not describe the Docs RP as
qualified until those checks pass.
