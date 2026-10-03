---
type: article
profile: sorane-okf/0.1
title: 'mikaki API reference — OIDC and session checks'
description: 'Request fields, responses, authentication and errors for Discovery, JWKS, authorize, token, UserInfo, logout and the mikaki session/check extension.'
lang: en
translation_key: api
updated: 2026-10-03
---

This reference covers **registered server-side Web clients using ES256 `private_key_jwt`, Code and S256 PKCE**. Native public clients, FAPI and Vault APIs have separate contracts. Follow the [integration guide](integration.md) for sequencing and the [local RP example](integration-example.md) for executable code.

## Endpoint index

The issuer is `https://auth.mikaki.org`. Fetch standard endpoints from [Discovery](https://auth.mikaki.org/.well-known/openid-configuration) and require an exact issuer match. These are the public values checked on October 3, 2026.

| Method and path | Purpose and authentication |
| --- | --- |
| GET `/.well-known/openid-configuration` | Public metadata; no authentication |
| GET `/jwks` | Public signing keys; no authentication |
| GET `/authorize` | Browser authorization; registered client and PKCE |
| POST `/token` | Backend code exchange; client assertion |
| GET / POST `/userinfo` | Subject lookup; Access Token |
| GET / POST `/logout` | OP logout with user confirmation |
| POST `/session/check` | Custom session check; a new client assertion |

Keep private keys, codes, tokens and assertions on the application server and out of URLs and diagnostic logs. Do not distribute server-client private keys to a browser-only SPA.

## GET /authorize

Navigate the browser to the authorization endpoint with URL-encoded values.

| Parameter | Value or source |
| --- | --- |
| `client_id` | Registered client ID |
| `redirect_uri` | Exact registered HTTPS callback |
| `response_type` / `scope` | `code` / `openid` for the minimal profile |
| `state` | Random value bound to this browser and an unconsumed transaction |
| `nonce` | Fresh random value for ID Token validation |
| `code_challenge` | SHA-256 of the verifier, base64url without trailing `=` |
| `code_challenge_method` | `S256` |

Success returns query parameters `code`, `state` and `iss` to the registered callback. Validate state and the pinned issuer before exchanging the code. Handle `error` responses without creating a session. Invalid destinations may be rejected on the OP page rather than redirected. Never use fixed state, nonce or verifier values.

## POST /token

Send `Content-Type: application/x-www-form-urlencoded` from the backend.

| Field | Value |
| --- | --- |
| `grant_type` | `authorization_code` |
| `code` | Unused code from this callback |
| `redirect_uri` | Matching registration and authorization request |
| `code_verifier` | Saved verifier from this transaction |
| `client_id` | Registered client ID |
| `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | ES256 JWT described below |

The JWT header uses `alg=ES256` and the `kid` of the registered public key. Both `iss` and `sub` are the client ID; `aud` is the **exact token endpoint URL** from Discovery. Generate a new `jti` and short `iat`/`exp` within operational limits for each request.

Successful JSON includes `access_token`, `token_type`, `expires_in` and `id_token`. In the normal Bearer profile the Access Token is opaque, not a JWT; `expires_in` is seconds. This public profile has no refresh-token grant.

Validate ID Token signatures with the issuer JWKS and allowed algorithms, then issuer, audience, times, nonce and required auth_time. Identify users by the issuer/pairwise-subject pair. Decoding a JWT is not validation.

Common errors use JSON `error`. These are current implementation mappings, not an exhaustive catalog for every path.

| HTTP / error | Action |
| --- | --- |
| 400 `invalid_request` | Check required fields and format |
| 401 `invalid_client` | Check registered key, kid, aud, signature and time limits |
| 400 `invalid_grant` | Check code, PKCE, redirect and replay; start a fresh login |
| 400 `unsupported_grant_type` | Use the supported grant |
| 500 `server_error` | Server failure; do not create a session |

After a timeout or lost response, do not resend the code or assertion. Start a fresh login.

## GET / POST /userinfo

For the normal profile use `Authorization: Bearer <access_token>`. POST also uses this header, rather than moving the token into a URL or form. DPoP-bound tokens require the corresponding proof and authentication scheme.

The minimal success response is `{"sub":"<pairwise-subject>"}`. Require it to match the validated ID Token subject. The `profile` scope does not promise a name or email, and ordinary login does not return Vault notes.

Invalid, expired or revoked tokens return 401 with a Bearer or DPoP challenge. The implementation contract returns internal failures as 503 with `Retry-After: 5` and no-store, without a token challenge or stale claims. Do not interpret 503 as consent withdrawal. UserInfo does not replace RP session validation or authorize general application APIs.

## POST /session/check

This is a mikaki extension. Send `Content-Type: application/json` with the following shape. Angle-bracket values are explanatory placeholders, not a usable request.

```json
{
  "client_id": "<registered-client-id>",
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion": "<new-signed-es256-jwt>",
  "sid": "<validated-id-token-sid>"
}
```

Set assertion `aud` to **`https://auth.mikaki.org/session/check`**. A token-endpoint assertion cannot be reused. Use a fresh jti and do not send the user's SSO cookie or an Access Token.

An active session returns `active=true`, `sub`, `auth_time`, `expires_at`, `lease_ttl`, `app_idle_timeout`, `policy_revision` and `session_policy_revision`. Times are Unix seconds; TTL and idle timeout are seconds. Match sub and auth_time against the ID Token. Cap validity at parent SSO expires_at and measure lease_ttl from the **start of the check**. Use returned values rather than hardcoding five minutes.

Unknown, other-client, unissued or revoked sid values return 200 with `{"active":false}`. This is not a successful login. Malformed requests return 400; rejected client authentication returns 401. Those rejection paths do not promise a JSON error body. Responses are no-store.

A failed initial check cannot create a new RP session. During an OP outage an existing session is usable only until its current lease expires, without extension. Delayed responses or callbacks must not undo revocation.

## GET / POST /logout and Back-Channel delivery

Use the Discovery end_session_endpoint. Supply `id_token_hint`, a registered `post_logout_redirect_uri`, and return `state` as appropriate; not all are mandatory for every request. Invalid hints or destinations cannot authorize arbitrary redirects. POST uses form fields and proceeds through confirmation.

Clearing an RP cookie differs from ending OP SSO. When an RP registers a Back-Channel receiver, the OP sends form field `logout_token` to that RP endpoint. Validate its signature, pinned issuer, your client audience, times, events and sid; reject nonce and revoke the corresponding sessions. Handle duplicates and callbacks that arrive after revocation.

Do not depend on browser-return/notification arrival order. Continue enforcing session-check leases. The [logout test evidence](conformance.md) does not guarantee notification delivery to every production RP.

## Detailed contracts and changes

This reference follows the [RP contract](https://github.com/masanork/mikaki/blob/main/docs/rp-integration.md), [session/check](https://github.com/masanork/mikaki/blob/main/docs/rp-session-check.md), [UserInfo](https://github.com/masanork/mikaki/blob/main/docs/oidc-access-token-and-userinfo.md) and [current token error implementation](https://github.com/masanork/mikaki/blob/main/crates/worker/src/lib.rs). Consult [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html) for the standard. During this experimental phase, check current public Discovery, the target commit and operational configuration when integrating.

## Read next

- [Runnable local RP example](integration-example.md): Execute code exchange and session handling.
- [Operations and service information](operations.md): Check usage conditions, support and change information.
