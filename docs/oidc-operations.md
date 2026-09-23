# OIDC limits, delivery, and recovery

The [runtime policy example](../config/runtime-policy.example.toml) supplies initial values. The active revision is managed in D1 under the [configuration contract](runtime-configuration.md). Deployment domains, secrets, client registration, and crypto profiles have separate typed configuration. Tune limits from measurements.

## Input and capacity limits

Apply byte limits while reading, not solely from `Content-Length`. Reject compressed request bodies initially, malformed UTF-8, duplicate protocol parameters/JSON keys, excessive nesting, unsupported JWT extensions, and `alg=none`. Count unknown OAuth parameters toward size limits even when specifications say to ignore them.

| Input | Initial limit |
| --- | --- |
| Request target / headers | 8 KiB / 32 KiB; use 414 / 431 when exceeded |
| Form or JSON body | 32 KiB; 413 when exceeded; unsupported media/encoding: 415 |
| WebAuthn body | 64 KiB; JSON/CBOR depth 8 |
| JWT / JWKS | 16 KiB / 64 KiB; at most 16 JWKs |
| Other JSON | Depth 16 |
| State / nonce | 256 bytes each; generated from 32 random bytes |
| Redirect URI | 2048 bytes plus exact registration match |

PKCE verifier length remains 43–128 characters by specification. Review all limits when adding larger cryptographic signatures.

Rate limit only using trustworthy ingress IP information and server issued browser identifiers. Do not let a caller exhaust an authenticated client's or account's quota by merely asserting its ID. Cloudflare rate limiting is approximate across locations; D1 constraints enforce one time use and security critical counters. Initial active caps: eight pending logins per browser, 32 SSO sessions per account, and 64 client sessions per SSO/client. Check counts atomically with creation; refuse new sessions at the cap without silently deleting valid ones. Return 429 with `Retry-After`, and fail closed with 503 when the entry limiter is unavailable.

## Endpoints and keys

Publish only actually supported Discovery, JWKS, authorization, token, UserInfo, session check, and logout behavior. Registration uses exact HTTPS redirect, post logout, and backchannel URLs, explicit signing algorithms, and statically registered keys; no wildcard, fragment, userinfo URL, dynamic key URL, or arbitrary outbound target. Localhost exceptions belong to development configuration. State changes use POST with origin/CSRF checks. Cache Discovery/JWKS as appropriate; authentication and token responses are `no-store`. Browser authentication pages use restrictive CSP and no external script.

For RP JWKS fetching, use one in flight request per issuer, an unknown kid refresh no more often than every 30 seconds, a 30 second negative cache capped at 64 entries, and a five second timeout. A known unexpired key can survive a fetch outage, but an expired cache cannot be extended indefinitely; a compromised kid deny rule takes precedence.

## Logout outbox

Create durable revocation before delivery. Expand at most 100 targets per batch. Scan at least every minute; acquire leases immediately before sending and cap concurrent delivery at four per client. Initial send timeout is 10 seconds and lease 30 seconds. Retry with bounded jitter between five seconds and one hour, at most 48 sends and no later than 24 hours from revocation. Accept 2xx; retry timeouts, network errors, 408, 429, and 5xx. Do not follow redirects. Treat other 4xx as configuration failures. Honor valid `Retry-After` within the final deadline; read no more than 4 KiB of response body and do not log it. Resend a newly signed Logout Token with the same SID. The RP validates signature, audience, issuer, events, SID, and time before idempotent revocation.

Alert on oldest pending delivery over 15 minutes, backlog over 10,000, permanent failure, or deadline exhaustion. These thresholds never permit dropping revocation. Default audit retention is 30 days, delivery results seven days, GC hourly in batches of 500 with a 24 hour grace. Compute `retain_until` from the longest session, token, replay, and notification window; never shorten it merely because policy changes. Logs omit bearer credentials, cookies, raw assertions, email, and full IP addresses.

## Recovery

D1 uncertainty stops new authentication/exchange/UserInfo with 503; RPs stop use after their existing lease. A client key compromise stops that client and revokes derivatives. An OP key compromise stops issuance, distributes a kid denial rule, and may require all sessions revoked. Outbox recovery resumes from persisted cursor and leases. A bad configuration does not silently fall back to defaults. Code rollback must not reactivate retired keys or grants.

For historical DB restore, stop ingress, change an externally held recovery generation, invalidate old SSO/codes/tokens/admin grants and RP sessions, rotate signing keys, and reconcile account/credential/client/grant state from independent audit or registration backups. A restored database alone cannot prove that deleted credentials or revoked grants remain invalid. Rehearse this before claiming production recovery readiness.

See [Cloudflare rate limiting](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/), [OIDC Back Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html), and [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html).
