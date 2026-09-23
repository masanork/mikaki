# Managed RP session check

For the full RP login sequence, start with [RP integration](rp-integration.md).

`POST /session/check` is a mikaki extension for managed RPs. It is separate from OpenID Connect Session Management and OAuth token introspection. The RP sends JSON with `client_id`, `client_assertion_type`, `client_assertion`, and `sid`. The assertion is ES256 `private_key_jwt` with a fresh `jti` and `aud` set exactly to `https://mikaki.tossa.app/session/check`; a token endpoint assertion cannot be reused. Do not send the user's browser cookie or an Access Token.

For a valid, token-issued sid belonging to the authenticated client, the response contains `active: true`, pairwise `sub`, `auth_time`, parent SSO `expires_at`, `lease_ttl`, `app_idle_timeout`, runtime `policy_revision`, and `session_policy_revision`. An unknown, other-client, unissued, or revoked sid returns only `{ "active": false }`. Responses use `Cache-Control: no-store` and must be fetched from the primary D1 state.

The RP measures the lease from the **start** of its check and caps it at the parent SSO expiry. A delayed response does not extend the lease. Before creating an app session, it must check the sid and reject a callback racing with a revocation. If mikaki is unavailable, the RP can use a previously confirmed session only until its current lease expires. A new login cannot be committed without a successful check.

The initial D1 policy sets `lease_ttl_seconds=300` and `app_idle_timeout_seconds=604800` (seven days). `0006_session_validation_policy.sql` applies it before the Worker deploy. An operator can shorten the lease through a revisioned D1 update without redeploying the Worker; existing RP leases retain their earlier expiry, so the old maximum bound still applies during an incident. This check API does not send logout notifications; that work is tracked separately.
