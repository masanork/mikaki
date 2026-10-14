# OIDC login experience

The first production app connection uses OIDC Authorization Code with PKCE S256. Users see a passkey login without protocol configuration. When the login screen is shown, first or changed connections receive a separate confirmation within that screen after the Passkey operation. [ADR 0002](adr/0002-oidc-from-first-release.md) records the decision; [implementation readiness](oidc-implementation-readiness.md) describes the current implementation.

## User journey

| Situation | Expected experience |
| --- | --- |
| First connection, signed out | Show the app identifier and destination, perform the Passkey operation, and confirm an unfamiliar connection before sending its response. The server then verifies the credential and binds consent to the authenticated account. |
| First connection, signed in | Show the account and app, allow account switching, and confirm the connection. |
| Previously approved connection, signed in | Complete a top level redirect without another prompt unless reauthentication is required. |
| Previously approved connection, session expired | Authenticate again; skip the extra local confirmation only when this browser recognizes the selected Passkey, app, destination and scopes. |
| New account | Validate an invitation and enroll a passkey in the login journey. Public self registration is outside scope. |
| First Vault use | Explain the requested operation, then unlock/create the Vault and obtain a separate grant. |
| Cancellation or expiry | Return safely to the app, preserve unsaved input where possible, and offer a retry without a redirect loop. |

The first connection decision stays in the login journey, with a distinct confirmation step for an unfamiliar or changed connection. Display names and destinations come from registered client data, never request supplied labels. Ordinary login does not ask for an email address, password, IdP, issuer URL, or PRF output. Browser and authenticator passkey steps still vary by platform.

The login page tries to open the Passkey prompt when it loads. Browsers that require a fresh user gesture may reject that attempt; the visible Passkey button then starts authentication with one click. The button also cancels a pending automatic attempt before starting its own. Starting invitation registration cancels a pending automatic attempt. This username-free screen does not use conditional autofill, which requires an input annotated for WebAuthn autofill. Device and browser coverage must be recorded separately from the Chromium virtual-authenticator test.

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

## Local connection recognition

The woven gate retains its origin-derived appearance. Below its plate, the login screen shows whether this browser remembers an accepted sign-in to this app, the previous local sign-in time, or an explicit unknown/unavailable state. The address-bar and Passkey-domain instruction remains visible independently of the record. No successful visit or trust record is created by rendering or reloading the screen.

`login-history.ts` stores at most 32 records and 65,536 JSON characters under `mikaki.login-history.v1`. A record contains the page origin, app identifier, destination origin (or private-use scheme and path), normalized requested scopes, local time, and an issuer-scoped SHA-256 digest of the selected credential ID. It contains no raw credential IDs, ceremony responses, session secrets, invitations, PRF output or Vault keys. Before selection the screen can show this browser's most recent record for the app; the decision to omit review is re-evaluated against the actual selected credential. A new Passkey requires confirmation even for the same account. Site-data deletion, an invalid record or disabled/quota-limited storage never blocks login; unavailable history requires explicit RP connection confirmation.

For first, changed, or unavailable RP connections, the browser holds the assertion or registration attestation in memory while showing the app, destination, operation, and any changed destination or scopes. It sends the response to the existing finish endpoint only on Continue. The server performs the existing verification and atomic single-use commit at that point; displaying this confirmation does not establish a server-verified identity. The local record is written only after a successful, parseable finish response with a same-origin continuation. A rejected, lost or malformed response leaves the previous record unchanged. Declining discards the proof, uses `/login/deny` to consume the transaction when reachable, and returns to the issuer home instead of visiting the RP. The pending proof is discarded on reload, navigation or expiry (at most two minutes, bounded by the transaction's remaining lifetime). No automatic finish retry is added.

This is a client-side recognition aid, not a new server authorization policy or an authenticity indicator. A forged page can imitate these messages. Existing SSO redirects that do not show the login screen do not consult local history or receive this confirmation. First-party Web/Agent-owner sign-in and direct invitation enrollment keep their existing separate approval boundaries; RP invitation registration receives the connection confirmation before its finish request. Profile, Vault, identity disclosure and Work grants remain separate decisions. Ordinary login still does not require PRF. Browser extensions, server-side SSO change review and cross-device history synchronization are not implemented by this increment.

`npm run test:login-recognition` (after building the Worker) covers the history contract and the actual UI bundle with Chromium virtual Passkeys and mocked finish responses. The enrollment and product-journey browser suites additionally exercise real Rust verification, connection creation, OIDC code exchange and single-use denial. Desktop/mobile screenshots are written to `artifacts/login-recognition/`; these are synthetic evidence, not a real-user phishing-effectiveness or physical-device qualification.
