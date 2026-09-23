# OIDC login experience

The first production app connection uses OIDC Authorization Code with PKCE S256. Users see a passkey login, without protocol configuration or an extra consent screen. [ADR 0002](adr/0002-oidc-from-first-release.md) records the decision; [implementation readiness](oidc-implementation-readiness.md) describes the current implementation.

## User journey

| Situation | Expected experience |
| --- | --- |
| First connection, signed out | Show the registered app name and information shared, then authenticate with a passkey. Record consent only after binding it to the authenticated account. |
| First connection, signed in | Show the account and app, allow account switching, and confirm the connection. |
| Previously approved connection, signed in | Complete a top level redirect without another prompt unless reauthentication is required. |
| Previously approved connection, session expired | Authenticate again without repeating unchanged consent. |
| New account | Validate an invitation and enroll a passkey in the login journey. Public self registration is outside scope. |
| First Vault use | Explain the requested operation, then unlock/create the Vault and obtain a separate grant. |
| Cancellation or expiry | Return safely to the app, preserve unsaved input where possible, and offer a retry without a redirect loop. |

The first connection decision is integrated into authentication. Display names and destinations come from registered client data, never request supplied labels. Ordinary login does not ask for an email address, password, IdP, issuer URL, or PRF output. Browser and authenticator passkey steps still vary by platform.

## Separate boundaries

Mikaki SSO, each app session, and Vault unlock are independent. An OIDC token neither unlocks the Vault nor grants a Vault operation. Apps decide their own membership and roles. Start with `openid`; do not request profile or Vault permissions by default.

Respect `prompt=login`, `prompt=consent`, `prompt=select_account`, `max_age`, and `prompt=none` semantics. Account switching must be available. Credential management requires fresh proof beyond an SSO session. Disconnection stops later automatic login; session termination follows [session lifecycle](session-lifecycle.md). A single app logout must not immediately trigger automatic SSO login.

## Initial protocol profile

- Register server side clients statically. Require exact redirect URI matching, transaction bound `state`, `nonce`, and PKCE, and single use authorization codes.
- The app backend exchanges the code and validates signature, algorithm, issuer, audience, applicable `azp`, expiry, nonce, and `auth_time` when reauthentication was requested.
- Identify an external account by `(iss, sub)`, never by email equality. See [identity and signing keys](oidc-identity-and-keys.md).
- Use protected app session cookies. Do not put ID/access tokens or client secrets in browser localStorage.
- Publish Discovery and JWKS consistent with the actual issuer and deployed algorithms.
- Implicit/Hybrid Flow, dynamic registration, refresh tokens, `offline_access`, and unrestricted third party clients are outside the initial profile.

A successful login must work without PRF or an existing Vault. Initial consent must not be duplicated. Reject cross app code confusion, mismatched state/nonce/PKCE, invalid token claims, and concurrent code exchange. See [login transactions](oidc-login-flow.md), [access tokens](oidc-access-token-and-userinfo.md), and [session lifecycle](session-lifecycle.md).

## Standards

[OIDC Core authorization requests](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest), [OIDC Core consent](https://openid.net/specs/openid-connect-core-1_0.html#Consent), and [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1) inform this profile. The combined first connection screen is Mikaki's UX decision.
