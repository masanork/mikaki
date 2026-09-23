# OIDC identity and signing keys

This design separates the shared Mikaki account from app identities and describes signing key rotation. See [login](oidc-login.md), [session lifecycle](session-lifecycle.md), and [current readiness](oidc-implementation-readiness.md).

## Identity model

| Identifier | Meaning |
| --- | --- |
| AccountId | Internal owner of credentials; never an ordinary OIDC claim. |
| issuer | Fixed HTTPS namespace of the instance. |
| sector | OIDC sector identifier derived from registered redirect URI hosts. |
| sub | Stable opaque identifier for one AccountId and sector. |
| SubjectId | App owned identifier for membership and data. |
| sid | Session correlation for logout and validity checks, never a permanent person ID. |

Use pairwise subjects. Give tossa and tsudoi separate redirect URI hosts and sectors; different paths on one host are one sector. Initially restrict each client to one redirect host and do not fetch arbitrary `sector_identifier_uri`. Generate and persist an independent UUIDv4 subject per account/sector, with unique constraints on both `(account_id,sector)` and `sub`. Reconnection reuses the subject but creates a new grant version and SID. Do not publish AccountId, VaultId, or a common user DID in normal login. Apps identify users by `(iss,sub)`, not email, display name, or parsing the subject string.

A DID is for its defined key/controller/resolution method. Do not invent `did:mikaki` solely for identifier syntax. A common DID claim would defeat pairwise separation. Federation DID binding requires proof of account authentication and DID control, to be designed for G3. An OIDC issuer remains HTTPS.

Mikaki stores client registration, pairwise subject, and app connection separately. The app stores a unique `(issuer,sub) → SubjectId` mapping. First consent atomically resolves the pairwise subject and grant; concurrent callbacks must not create duplicate app users. Disconnection revokes permission and sessions but does not delete the stable subject or app data. Rejoining a suspended app follows app policy. Account linking and merging are separate, proof based operations outside the initial profile.

Changing a client key or redirect path within a sector preserves the subject. Changing sector or issuer changes external identity and requires an explicit migration. Do not carry consent across a new client ID or reinterpret an in flight transaction after registration changes.

## Signing and verification

ES256 is the normal JOSE signing profile; RS256 is supported for the required compatibility profile. WebAuthn keys, OP signing keys, client keys, Vault keys, and messaging keys have separate purposes. Public JWKs include `kty`, `use=sig`, `alg`, unique `kid`, and algorithm specific parameters. Never rely on RSA fields for every key. Clients fetch only their configured issuer's Discovery/JWKS, reject assertion supplied key URLs, and validate algorithm, key type, signature, issuer, audience, time, and purpose specific claims. Unknown `kid` refreshes are rate limited. Keep ID Token and Logout Token validation paths distinct.

Key lifecycle: `prepared → published → active → verify_only → retired`; an active key can instead become `compromised`. Record key format, purpose, algorithm, public JWK, secret reference, timestamps, and configuration generation. Private material stays outside ordinary DB exports, repository, logs, and JWKS. Conditional activation and generation checks prevent an old deployment from resuming a stopped key.

The [key policy example](../config/oidc-key-policy.example.toml) proposes rotation near 90 days, JWKS cache up to five minutes, 24 hours of prepublication, and at least 32 days of old public key retention after signing stops. These are operational proposals, not OIDC constants. Expired ID Tokens may remain usable as verified logout hints during a 30 day SSO period. Retries sign a fresh Logout Token for the same old SID. A compromised key receives no normal retention grace: stop signing, distribute a `kid` deny rule to RPs, and revoke affected sessions if the exposure cannot be bounded. A valid signature alone never creates an RP session without server side SID confirmation.

Verify stable pairwise subjects across concurrency, disconnection, reconnection, and rotation; reject old grants after client changes; test old/new JWKS caches and unknown keys; check compromise response and absence of private keys from exports. See [store contract](oidc-store-contract.md) and [crypto agility](crypto-agility.md).
