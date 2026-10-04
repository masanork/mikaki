---
type: article
profile: sorane-okf/0.1
title: 'A login demo connected to the public mikaki IdP'
description: 'Try passkey login, application session checks and logout with the public IdP and a dedicated RP, and understand the verification scope.'
lang: en
translation_key: integration-demo
updated: 2026-10-04
---

[Open the public integration demo](https://demo.mikaki.org/?lang=en). This application connects to the real `auth.mikaki.org` and only shows login state. Use a passkey already registered with mikaki. If you need an invitation, start with [invitation and integration requests](contact.md).

The demo requests only `openid`, without your name, email or Vault contents. It has no ticket or note submission. The application-specific identifier and session information needed for login are temporarily stored in a dedicated database separate from the IdP.

## Sign in through the public IdP

1. Select “Sign in with mikaki” at `https://demo.mikaki.org/?lang=en`.
2. Check that authentication is on `auth.mikaki.org` and the destination is `demo.mikaki.org`.
3. Confirm the initial application connection and verify your registered passkey.
4. On returning to the demo, check that “Login state” shows “Signed in”.

Registration and login are separate operations. For a new account, obtain an invitation and follow [Getting started](getting-started.md) first. Read [Passkeys](passkeys.md) for device and browser considerations.

## Check the session again

“Check session again” asks the public IdP about the current session from the RP server. A successful check returns to the login state page. A confirmed revocation or expiry deletes the RP session, even if an earlier confirmation period had time remaining.

Ordinary rendering uses a previous check within its validity period. A network failure does not extend that period. Reaching authentication or seeing a button alone does not prove successful code exchange or session verification.

The demo’s RP session lasts at most one hour and cannot exceed an earlier IdP expiry. Times are shown in UTC.

## Sign out of this demo

“Sign out of this demo” deletes its RP session and cookie. Check that you can no longer open the login state page. It leaves mikaki SSO active, so another login in the same browser may need fewer steps.

“Open mikaki’s sign-out confirmation” is a separate action that ends IdP SSO. Read the confirmation and consider the effect on other connected applications.

## Implementation and verification scope

The demo uses the login-only mode of the existing [Helpdesk RP Worker](https://github.com/masanork/mikaki/tree/main/crates/helpdesk-rp). It has a separate HTTPS origin, D1 database and RP-specific ES256 key with an exact registered callback. Its private key stays in a Worker secret.

| Check | Scope |
| --- | --- |
| PKCE, state, nonce, ID Token signature, issuer / audience | Existing RP implementation and local integration tests |
| Passkey login, session checks, RP logout and rejection after revocation | [Demo browser test](https://github.com/masanork/mikaki/blob/main/local/test/demo-rp.test.ts), using a disposable local OP and virtual authenticator |
| Public IdP client registration | Dedicated public key, callback and Back-Channel receiver registered by an operator |
| Public passkey round trip and actual notification delivery | Require participant actions; registration or local success alone does not establish these |

The demo does not indicate OpenID Foundation certification or an independent audit. See the separate [conformance results](conformance.md). For your own RP, read the [operations and configuration](https://github.com/masanork/mikaki/blob/main/docs/public-rp-demo.md) and [local example](integration-example.md).

## Read next

- [Application integration](integration.md): Registration and connection qualification.
- [API reference](api.md): Public OP request/response and session check contracts.
