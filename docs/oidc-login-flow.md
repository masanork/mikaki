# Client authentication and login transactions

This design applies the [login experience](oidc-login.md) and [session contract](session-lifecycle.md). The Worker has passkey login, first connection confirmation, code exchange, UserInfo, and `/session/check`. Full RP callback and logout integration remain to be verified. See [RP integration](rp-integration.md) and [deployment](cloudflare-deployment.md).

## Client authentication

Server side clients use ES256 `private_key_jwt`. Separate clients and keys by app and environment. Store private keys in app backends and register public keys in Mikaki; never fetch keys from assertion supplied `jku` or `x5u`. Require `iss=sub=client_id`, an exact endpoint URL in `aud`, unique `jti`, bounded `iat` and `exp`, and the JWT bearer client assertion type. Verify the registered algorithm, key ID, key, and revision. Accept each authenticated `(client_id,jti)` atomically once through the last acceptable time, even if later code checks fail. An invalid signature must not consume another client's JTI. Rotate by registering the new public key, switching signing, waiting for old assertions to expire, then disabling the old key; stop compromised keys immediately.

## Transaction sequence

1. A CSRF protected app action creates `state`, `nonce`, a PKCE verifier, and a browser bound server side transaction. Restrict the return target to a validated local path.
2. `GET /authorize` validates Code Flow, `openid`, S256, registered client, redirect URI, and request parameters; retain an immutable transaction.
3. Reuse valid SSO and consent when allowed. Otherwise authenticate with a passkey and obtain first connection confirmation. Bind account, client/grant revisions, subject, and session ID.
4. Issue a high entropy opaque code, store its hash, and return code and state to the registered redirect URI. Default lifetime: 60 seconds, single use.
5. The callback checks browser binding, state, and deadline. The backend posts code, redirect URI, verifier, and client assertion to `/token`.
6. Validate client, code binding, PKCE, time, SSO, grant, and revisions. Atomically consume the code once.
7. Validate ID Token signature, claims, nonce, and required `auth_time`; confirm `sid`, subject, and authentication time through `/session/check`.
8. Confirm app membership and revocation. Atomically save external identity mapping, app session, and completed transaction, then set the cookie and redirect to a clean local URL.

Use host only `Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax` cookies with the `__Host-` prefix. Do not share a cookie between apps. Keep multiple tab transactions separate. Avoid logging callback query parameters; use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.

## Atomicity and failure handling

Code consumption, issued token record, and SID binding commit together, conditional on current SSO, grant, client, and signing key. Only one concurrent exchange succeeds. After authenticating the client and binding it to the code, replay revokes derivatives of that code, without revoking unrelated logins. An RP records logout for an SID even before session creation, so a delayed callback cannot resurrect it.

`POST /session/check` is a Mikaki backend API, not OIDC introspection. Authenticate the client with a fresh assertion whose audience is this exact endpoint. For a valid issued SID belonging to the client, return `active`, `sub`, `auth_time`, SSO expiry, `lease_ttl`, new session `app_idle_timeout`, and `policy_revision`. Unknown, unissued, foreign, or revoked SIDs return `active=false` without subject details. Disable HTTP caching. An RP starts its lease at request start, caps it by SSO expiry, and does not extend it for delayed responses or clock rollback. Initial check failure prevents session creation; later failures stop use when the existing lease expires.

Never automatically replay a code after a lost token response. Start a new transaction, usually reusing valid SSO. Invalid state/browser binding leaves existing sessions unchanged. Show a recoverable error for cancellation, expiry, or app rejection. Account switching replaces the app session without inheriting permissions or Vault unlock.

[Flow policy](../config/oidc-flow-policy.example.toml) proposes a 10 minute transaction, 60 second client assertion, 30 second JWT skew, and 10 second backend timeout; review these independently of the established code, token, and SSO lifetimes. Integration tests must cover concurrency, replay, key changes, late responses, and callback/logout order.
