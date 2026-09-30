# Access tokens and UserInfo

This is the initial OIDC profile for [login](oidc-login.md). The access token exists only to call UserInfo; it is not an app session, Vault key, storage capability, or general API credential.

## Token contract

Issue a CSPRNG generated, 32 byte opaque bearer token. Persist only its digest, issuer/client/subject and SID binding, creation and expiry, and revocation state. Default lifetime is five minutes; there is no refresh token. Return it from a successful code exchange with `token_type=Bearer`, `expires_in`, and the ID Token. Never put it in a URL or browser storage. The RP backend can omit UserInfo during ordinary login when the ID Token contains the required subject.

A code replay revokes its issued access token. SSO, client, account, or relevant session revocation must invalidate it. Validate current state when serving UserInfo; a digest match alone is insufficient. Bound token retention and garbage collection to replay and audit needs. Do not treat an opaque token as a JWT.

## UserInfo endpoint

Offer `GET` and `POST /userinfo` with an Authorization Bearer header. Successful JSON contains only `sub` in the initial profile, matching the ID Token for the same login. Do not return email, name, Vault data, or app membership without a separately specified claim and consent policy. Reject missing, malformed, expired, revoked, or wrong purpose tokens. Use `Cache-Control: no-store`; avoid token values in logs.

The locally qualified, default-disabled `openid profile` path may add an explicitly shared and RP-consented Vault `name`; absent consent returns a successful `sub`-only response. Invalid access tokens return 401 with the Bearer or DPoP challenge. Internal UserInfo failures, including D1 or Claim Worker unavailability, return 503 with `Cache-Control: no-store` and `Retry-After: 5`, without a token challenge or a stale claim. An RP must not interpret 503 as consent withdrawal or an invalid token. This is an operational response contract, not a claim that real-service outage timing has been qualified.

The endpoint and Discovery metadata must describe only implemented behavior. Client authentication is at `/token`; a UserInfo bearer token is a different credential. The [store contract](oidc-store-contract.md) defines atomic issuance and revocation, and [operations](oidc-operations.md) defines limits.
