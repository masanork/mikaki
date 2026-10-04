---
type: article
profile: sorane-okf/0.1
title: 'Connect a Web application with mikaki OpenID Connect'
description: 'Connect a Web app to mikaki with OIDC client registration, PKCE, private_key_jwt, session checks and troubleshooting for failed integrations.'
lang: en
translation_key: integration
updated: 2026-10-03
---

To try the public IdP in your browser, open the [public integration demo](integration-demo.md).
This guide is for developers connecting a Web application whose backend holds a private signing key. It covers registration, login, code exchange and application session creation. For user sign-in instructions, read [Getting started](getting-started.md).

## Connect using OpenID Connect

mikaki acts as an OpenID Connect Provider (OP). Applications act as Relying Parties (RPs), using the Authorization Code flow with PKCE S256.

Discover endpoints and the signing key URL from:

```
https://auth.mikaki.org/.well-known/openid-configuration
```

The normal integration uses the `openid` scope and ES256 `private_key_jwt` client authentication. An administrator registers clients in advance.

## What to register

Use a separate client for each environment. Provide the operator with the application name, hostname, exact HTTPS callback URLs and an ES256 public JWK with its key ID. Keep the private key in your backend; do not send it to mikaki. Public dynamic client registration is unavailable.

Native public clients have separate registration, authentication and callback rules.

Before requesting registration, use [application integration requests](contact.md) to prepare the needed information and review steps.

## 1. Start login

Generate fresh random `state`, `nonce` and a PKCE `code_verifier` for each login. Store them in the backend with the start time and browser transaction. Restrict the post-login return path to a validated application-local destination.

Send these URL-encoded parameters to the discovered `authorization_endpoint`:

| Parameter | Value |
| --- | --- |
| `client_id` | Registered client ID |
| `redirect_uri` | Exact registered callback URL |
| `response_type` / `scope` | `code` / `openid` |
| `state` / `nonce` | Values generated for this login |
| `code_challenge` | SHA-256 of the verifier, encoded as base64url without trailing `=` |
| `code_challenge_method` | `S256` |

mikaki handles passkey authentication and connection approval. Your application does not receive the passkey or mikaki's SSO cookie.

## 2. Exchange the code on callback

Match `state` to the stored transaction and check that the response's `iss` exactly equals `https://auth.mikaki.org`. Reject errors, expired transactions and previously handled callbacks. Keep authorization codes out of access logs.

From the backend, POST `application/x-www-form-urlencoded` to the discovered `token_endpoint`. Include `grant_type=authorization_code`, the returned `code`, registered `redirect_uri`, stored `code_verifier`, `client_id`, `client_assertion` and `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.

The client assertion is an ES256 JWT signed with the registered private key. Its header's `kid` identifies the registered public key. Set `iss` and `sub` to the client ID and `aud` to the exact discovered token endpoint URL. Use a fresh `jti` for every request, with `iat` and `exp` within the operator's lifetime policy. After a lost response, restart login rather than replaying the code or assertion.

Verify the ID Token using JWKS and allowed signing algorithms. Check issuer, audience, expiry, issued-at time, the sent nonce and required `auth_time`. Map the issuer and `sub` pair to an application-local user. The subject is neither an email address nor mikaki's common account ID.

The Access Token is for UserInfo; it is not authorization for your application's API or proof of an active session. If fetching UserInfo, match its `sub` to the verified ID Token.

## 3. Create an application session

Before issuing a cookie, managed RPs call `POST https://auth.mikaki.org/session/check` from their backend. This is a mikaki-specific extension. Send JSON containing `client_id`, `client_assertion_type`, a new `client_assertion` and the ID Token's `sid`.

| Assertion purpose | URL used as `aud` |
| --- | --- |
| Code exchange | Discovered `token_endpoint` |
| Session check | `https://auth.mikaki.org/session/check` |

Create a new JWT and `jti` for the session check. A token-exchange assertion cannot be reused. For `active=true`, match `sub` and `auth_time` to the ID Token. Measure `lease_ttl` from the start of the check and cap its deadline at parent SSO `expires_at`. Use the returned values rather than assuming a fixed check interval.

Limit the application session to the earlier of the idle deadline determined by `app_idle_timeout` and parent SSO expiry. A delayed active response must never restore a revoked session.

Issue an application-host-only cookie with `Secure`, `HttpOnly` and `SameSite=Lax`. Do not share its `Domain` with mikaki. Recheck protected requests after the lease expires. An OP outage cannot extend the lease, and a failed initial check cannot create a new session.

## Connect logout

Register post-logout return URLs and Back-Channel Logout receivers separately. Validate signed logout notifications and revoke the corresponding application sessions. Verify that protected operations stop at the session-check deadline even if a notification never arrives.

## When integration fails

1. Check that issuer, client ID and callback URL belong to the same registered environment. Paths, trailing slashes and query strings matter.
2. Check that the callback belongs to the same browser's unprocessed transaction. Do not use fixed state or nonce values to make a test pass.
3. For code exchange, check the stored PKCE value, key `kid`, assertion `aud`, clock and lifetime. Keep private keys, codes and tokens out of diagnostic logs and public issues.
4. For session checks, use a fresh assertion and a `sid` issued to the same client. Treat `active=false` as failure and restart login.

## Current integration scope

The normal production scope is `openid`. Name release has separate consent, operational settings and qualification requirements; ordinary login does not provide the Vault name or note. Do not assume support for the `email` scope, dynamic registration or general FAPI integration.

Registration alone does not establish interoperability. Test code exchange, invalid state/nonce/PKCE/signatures, replay, revocation, logout and OP outage from the actual application. [Implementation status](security.md) distinguishes local test evidence from certification.

For the standard flow, see [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) and the [PKCE specification](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2). mikaki-specific details are in the [RP integration guide](https://github.com/masanork/mikaki/blob/main/docs/rp-integration.md), [client registration instructions](https://github.com/masanork/mikaki/blob/main/docs/rp-client-operations.md) and [session-check contract](https://github.com/masanork/mikaki/blob/main/docs/rp-session-check.md).

## Read next

- [API reference](api.md): Look up endpoint requests, responses and errors.
- [Runnable local RP example](integration-example.md): Exercise registration, login and revocation.
