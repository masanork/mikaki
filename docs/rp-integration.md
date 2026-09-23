# Integrate a relying party

This guide is for server-side relying parties (RPs), including tossa and tsudoi, connecting to the production issuer `https://mikaki.tossa.app`. No production RP is registered yet. A Mikaki operator performs registration.

## 1. Register the RP

Use a separate client for each RP and environment. Generate an ES256/P-256 signing key at the RP and keep the private key in its backend secret store. Provide the Mikaki operator with:

- the environment, RP name, and proposed `client_id` (or let the operator generate a UUIDv4);
- the RP hostname used as `sector_identifier`;
- each complete HTTPS callback URL, including any query string;
- the **public** JWK fields `kty=EC`, `crv=P-256`, `x`, and `y`, plus its `kid`.

Never send the private JWK. See [managed client operations](rp-client-operations.md) for the registration format and key or redirect changes. Pin the returned client ID, redirect URIs, and issuer in RP configuration. There is no dynamic client registration endpoint.

## 2. Start login

Read Discovery at `https://mikaki.tossa.app/.well-known/openid-configuration` and obtain signing keys from its `jwks_uri`. The normal profile uses Authorization Code, the `openid` scope, PKCE S256, and ES256 `private_key_jwt`. Client-secret methods in the isolated conformance profile are not for production RPs.

Protect the RP's login initiation against CSRF. For every transaction, generate high-entropy `state`, `nonce`, and a PKCE `code_verifier`. Store them server-side with the start time, browser binding, and a validated **RP-local** return path. The `code_challenge` is the unpadded base64url encoding of SHA-256 over the verifier. Redirect the browser to the discovered `authorization_endpoint` with:

| Parameter | Value |
| --- | --- |
| `client_id` | Registered client ID |
| `redirect_uri` | Exact registered callback URL |
| `response_type` | `code` |
| `scope` | `openid` |
| `state` | Fresh random value, required |
| `nonce` | Fresh random value, strongly recommended for the RP |
| `code_challenge`, `code_challenge_method` | Derived challenge, `S256` |

`request`, `request_uri`, dynamic registration, and `profile` or `email` scopes are outside the current integration. Mikaki handles the passkey screen and first connection approval. The RP never receives the passkey or Mikaki's SSO cookie.

## 3. Handle the callback and exchange the code

Bind the callback to the stored browser transaction and compare `state`. Only one worker may claim the transaction. Compare the OP's `iss` to the exact issuer and treat any `error` as a failed transaction. Do not exchange a code or create a session if the code is absent, the state differs, or the transaction is expired or already handled. Keep authorization codes out of access logs.

POST `application/x-www-form-urlencoded` to the discovered `token_endpoint` from the RP backend. Include `grant_type=authorization_code`, the returned `code`, registered `redirect_uri`, stored `code_verifier`, `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, and `client_assertion`.

The assertion is an ES256 JWT signed by the registered private key. Its header carries that key's `kid`; `iss` and `sub` equal `client_id`; `aud` equals the **exact discovered token endpoint URL**; `jti` is unique per request; and `iat` and `exp` are present. Keep its lifetime within the configured limit. Never replay an assertion or code. After a lost response, restart with a new login transaction.

Validate the ID Token's signature and `alg` against JWKS, then check `iss`, `aud`, `exp`, `iat`, the sent `nonce`, and `auth_time` where required. Use `sub` as the external identity mapped to an RP-local subject, and `sid` for session status. The pairwise `sub` is neither an email address nor Mikaki's common `AccountId`. The opaque `access_token` is only for UserInfo; it is not an RP API authorization token or a session lease. If calling UserInfo, match its `sub` to the verified ID Token. Current UserInfo returns only `sub`.

## 4. Establish an application session

Before issuing a cookie, call `POST https://mikaki.tossa.app/session/check` from the backend with JSON containing `client_id`, `client_assertion_type`, a **new** `client_assertion`, and the ID Token's `sid`. This is a managed-RP extension, not a standard OIDC endpoint. The new assertion's `aud` must be **`https://mikaki.tossa.app/session/check`**; a token-endpoint assertion cannot be reused. See the [session-check contract](rp-session-check.md).

If `active=true`, compare `sub` and `auth_time` with the verified ID Token. Measure `lease_ttl` from the **start** of the check and cap the deadline at parent SSO `expires_at`. The RP application session expires at the earlier of its `app_idle_timeout` and parent SSO expiry. Atomically commit the revocation check, membership decision, completed browser transaction, and new RP session in the RP store. Then issue an RP-host-only cookie with `Secure`, `HttpOnly`, and `SameSite=Lax`; do not use a shared `Domain` cookie with Mikaki.

Recheck status when a protected request arrives after the lease deadline. A failed initial check means no new session. During an OP outage, do not extend an existing lease; stop protected operations when it expires. A delayed `active=true` response must never restore a revoked sid.

## Current limits and acceptance checks

The production Worker does not yet provide `/logout`, Back-Channel Logout delivery, or logout-target registration, and Discovery does not advertise logout metadata. RPs must rely on the session-check lease for revocation. Do not promise immediate RP logout propagation before notification integration is tested.

Before connecting an RP, test login at the registered redirect, first approval, SSO reuse, rejection of invalid state/nonce/PKCE/signature/issuer/audience, code and assertion replay, another client's sid, revocation and expiry boundaries, temporary OP outage, multiple tabs, and delayed callbacks. See the [login transaction](oidc-login-flow.md), [session lifecycle](session-lifecycle.md), and [token and UserInfo contract](oidc-access-token-and-userinfo.md) for deeper design details.
