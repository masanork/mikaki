# Session and logout contract

**Revision 2, 2026-09-22.** This contract elaborates the initial OIDC user experience and [ADR 0003](adr/0003-session-lifecycle.md). It defines accepted defaults and invariants; [status](status.md) and deployment records, not this design alone, establish implementation. Durations are defaults in [runtime policy](runtime-configuration.md), not immutable code constants. Single use, parent-session binding, and stopping protected operations after an expired validation lease remain invariant.

## Default lifetimes

| State | Initial value | Renewal and end |
| --- | --- | --- |
| Mikaki SSO | At most 30 days from passkey authentication | Neither SSO use nor background traffic extends absolute expiry |
| RP application session | Seven-day idle limit, never past parent SSO absolute expiry | User activity may renew idle time; polling alone may not |
| Managed RP status-check result | At most five minutes | Recheck server-to-server without showing another login screen |
| Management authorization | Once within five minutes of operation-bound passkey verification | Bind account, action, and target; SSO alone is insufficient |
| Authorization code | Single use, 60 seconds | Restart login after a lost exchange response |
| ID Token | Five minutes | Validate at app-session creation; do not use as app-session lifetime |
| Vault unlock | 15-minute idle, one-hour absolute | Lock locally; do not reuse secrets after page close/reload |

These are Mikaki defaults, not standards-mandated values. Expiry uses `now >= expires_at`; token clock skew is separate and does not extend a session. A valid SSO plus connection grant can establish another app session without a passkey, unless the RP explicitly requests reauthentication or the user just logged out. Normal login does not evaluate PRF or unlock a vault. `auth_time` remains the actual user-authentication time, not code issuance or lease check. A new passkey authentication creates a new SSO ID; it does not lengthen sessions derived from the old one.

## Logout scope

| User action | Revokes | Does not revoke |
| --- | --- | --- |
| “Log out” | This browser's Mikaki SSO and connected app sessions derived from it | Other browsers/devices, passkeys, or connection permission |
| “Log out everywhere” | All account SSO and derived app sessions | Passkeys, stored data, connection permission |
| “Disconnect application” | Its connection grant, all sessions from that grant, and that app's Vault grant | Common account, other apps, Vault data |

Make the ordinary action's scope visible, e.g. logout from this browser's tossa and tsudoi. RP-Initiated Logout is confirmed once at Mikaki, not separately by every app. Revoke the initiating RP session before navigating to OP confirmation. If the user cancels OP logout, report the actual result and do not silently restore SSO.

“Everywhere” and disconnection require management reauthentication. An RP request cannot revoke the entire account. Everywhere logout does not disable a stolen passkey; credential removal is separate and revokes SSO authenticated with that credential and its derived app sessions, leaving sessions from other credentials intact. “This browser” denotes cookie-bound scope, not physical device identity. Closing a browser is not guaranteed logout. Show login/last-check time and browser description as hints, never use a device label or User-Agent as proof of identity.

## OIDC logout and revocation

Initial managed tossa/tsudoi integration includes RP-Initiated and Back-Channel Logout. RPs map ID Token `iss`/`sid` to their server sessions. Mikaki links SSO, per-client sid, and connection-grant revision without publishing the secret browser cookie as sid.

RP-Initiated Logout validates ID Token hint and current session and restricts post-logout redirects to registered destinations. The initiating RP uses a CSRF-protected POST and checks callback state. Clearing a cookie alone is not server-side revocation.

For Back-Channel Logout, validate signature, issuer, client audience, time/expiry, events, and sid/sub; reject Logout Tokens containing a nonce. The receiving RP invalidates its server session before acknowledging, without relying on a visible browser. Mikaki atomically records SSO revocation and a durable notification outbox. Retry transient failures and record permanent ones; do not display “all apps complete” while notifications remain undelivered. Repeated signed delivery or an already-invalid session may be acknowledged safely.

## Lease when delivery is lost

Notifications alone cannot bound propagation after delivery failure. Managed tossa/tsudoi RPs therefore check app-session status server-to-server at most every five minutes when serving protected operations. This is a Mikaki-specific contract, not standard OIDC or a guarantee for arbitrary clients.

- A client can query only a sid issued to itself, not another app's state by claiming an `AccountId`.
- Check SSO and connection-grant revision before first app-session commit; afterward recheck on a protected request when the prior lease expired. Idle sessions need no polling.
- Measure the lease from **check start**, not delayed response arrival, and cap it at parent SSO expiry.
- Read revocation from fresh authoritative state, not a stale replica or added cache. RP storage must serialize notification and status-result writes so a late `active=true` cannot restore a revoked sid.
- If Mikaki is unreachable, an existing confirmed session lasts only until its existing lease expires. Then stop protected work, preserve user input, and offer retry. Do not extend the lease or repeatedly ask for passkeys.
- Reevaluate long-lived WebSocket-like connections at revocation notice or lease expiry; initial connection approval is not indefinite authorization.

With default policy, new protected operations are rejected within at most five minutes after revocation commitment. In-progress operations and already disclosed data cannot be recalled. The availability cost is that a prolonged OP outage also pauses protected RP work. Changing this trade-off requires updated contract and acceptance tests.

## Races and Vault boundary

Never reuse a revoked sid. Preserve tombstones long enough to cover related code/token/app-session lifetimes and notification retries. A delayed old callback must not recreate an app session. Account-wide revocation advances an epoch and targets sessions committed before it; a new SSO from later passkey authentication receives a different sid and must survive old notifications. Disconnection advances the grant revision so an old notification cannot undo a new connection.

Bind a management ceremony to fixed operation contents before reauthentication. Atomically consume its one-time authorization, check target revision, and commit the change. A recent OIDC `auth_time` alone does not authorize arbitrary management.

On same-browser logout or account switch, discard Vault secrets and decrypted display where possible and notify other tabs. A suspended tab must recheck time and session on resume. Remote logout stops future server access but cannot erase offline memory or plaintext/keys already given to an app. Vault unlock lifetime is independent of 30-day SSO and is not extended by sync or background work.

Acceptance tests should cover default expiry boundaries, unchanged `auth_time` under SSO reuse, ordinary/everywhere/disconnect scope, missing/duplicate/reordered notifications, delayed code/callback, revocation and lease races, OP outage and persistent connections, malformed Logout Tokens and cross-client sid, old notification after new login, no automatic relogin after logout, and locked/unlocked/offline Vault guarantees.

References: [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html), [Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest), and [MDN Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie).
