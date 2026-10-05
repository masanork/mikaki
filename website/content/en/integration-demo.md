---
type: article
profile: sorane-okf/0.1
title: 'Check the Docs login state'
description: 'Read public documentation and see a minimal passkey login, application session check and logout example.'
lang: en
translation_key: integration-demo
updated: 2026-10-04
---

[mikaki Docs](https://docs.mikaki.org/) provides public FAQs and integration guides without sign-in. Its [login state example](https://docs.mikaki.org/session?lang=en) connects a dedicated RP to `auth.mikaki.org` and shows session rechecking and RP-local logout after passkey sign-in. You need a passkey already registered with mikaki. For a new account, see [Getting started](getting-started.md).

Docs does not require sign-in. The login example requests only `openid`, without your name, email or Vault contents. It has no ticket or note submission. The application-specific identifier and session information needed for login are temporarily stored in a dedicated database separate from the IdP.

## Sign in to Docs

1. Select “Sign in with mikaki” at `https://docs.mikaki.org/session?lang=en`.
2. Check that authentication is on `auth.mikaki.org` and the destination is `docs.mikaki.org`.
3. Confirm the initial application connection and verify your registered passkey.
4. On returning to Docs, check that “Login state” shows “Signed in”.

Registration and login are separate operations. For a new account, obtain an invitation and follow [Getting started](getting-started.md) first. Read [Passkeys](passkeys.md) for device and browser considerations.

## Check the session again

“Check session again” asks the public IdP about the current session from the RP server. A successful check returns to the login state page. A confirmed revocation or expiry deletes the RP session, even if an earlier confirmation period had time remaining.

Ordinary rendering uses a previous check within its validity period. A network failure does not extend that period. Reaching authentication or seeing a button alone does not prove successful code exchange or session verification.

The demo’s RP session lasts at most one hour and cannot exceed an earlier IdP expiry. Times are shown in UTC.

## Sign out of Docs

“Sign out of Docs” deletes its RP session and cookie. It leaves mikaki SSO active, so another login in the same browser may need fewer steps.

“Open mikaki’s sign-out confirmation” is a separate action that ends IdP SSO. Read the confirmation and consider the effect on other connected applications.

## Implementation and verification scope

Docs uses a dedicated RP Worker, HTTPS origin, D1 database and RP-specific ES256 key with an exact registered callback. Its private key stays in a Worker secret. Reading the FAQs does not depend on an RP session.

| Check                                                                   | Scope                                                                                                                                                  |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| PKCE, state, nonce, ID Token signature, issuer / audience               | Existing RP implementation and local integration tests                                                                                                 |
| Passkey login, session checks, RP logout and rejection after revocation | [Docs RP browser test](https://github.com/masanork/mikaki/blob/main/local/test/docs-rp.test.ts), using a disposable local OP and virtual authenticator |
| Public IdP client registration                                          | Dedicated public key, callback and Back-Channel receiver registered by an operator                                                                     |
| Public passkey round trip and actual notification delivery              | Require participant actions; registration or local success alone does not establish these                                                              |

This example does not indicate OpenID Foundation certification or an independent audit. See the separate [conformance results](conformance.md). For your own RP, read the [local example](integration-example.md).

## Read next

- [Application integration](integration.md): Registration and connection qualification.
- [API reference](api.md): Public OP request/response and session check contracts.
