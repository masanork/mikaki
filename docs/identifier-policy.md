# Identifier policy and UUIDv4/v7

**Draft recommendation, 2026-09-22.** Do not use a DID merely because a value is an identifier. Follow a protocol's mandated format where one exists; prefer UUIDs for ordinary Mikaki-issued entity IDs. Reserve DIDs for federation, where identity connects keys, controller, and delivery endpoint. This comparison does not imply a data migration or completed implementation.

| Property | UUIDv4 | UUIDv7 |
| --- | --- | --- |
| Size | 128 bits; canonical string 36 characters | Same |
| Contents | 122 random bits excluding version/variant | 48-bit Unix milliseconds plus 74 bits random or permitted monotonic values |
| Time disclosure | No encoded creation time | Generator timestamp is readable |
| Generation | CSPRNG without clock/order management | Clock and randomness; inspect same-millisecond and rollback behavior of chosen generator |
| Ordering | Not creation ordered | Approximately time-local, not a global commit order |
| Index locality | Scattered inserts | Potentially more local; measure in the actual DB |
| Candidate use | Public subject, object, and operation references | Internal high-volume append-only audit/outbox row IDs |

Format and index considerations follow [RFC 9562 §§5.4, 5.7, 6.11](https://www.rfc-editor.org/rfc/rfc9562.html); allocations below are Mikaki design choices. Both need unique constraints and collision handling. Do not assume every UUIDv7 implementation uses 74 independent random bits.

## Initial allocation

Use UUIDv4 by default to avoid encoding creation time and minimize generator types in initial authentication and Vault code. Consider UUIDv7 for high-volume internal append-only records when implemented and measured, not as a reason to create extra audit tables or primary keys. Do not add both private-v7 and public-v4 IDs to every entity. Separate internal and public identities only for a real semantic/disclosure distinction, such as `AccountId` versus OIDC `sub`.

| Value | Recommended format | Constraint |
| --- | --- | --- |
| `AccountId`, application `SubjectId` | UUIDv4, independently issued | Do not expose `AccountId` as OIDC `sub` or derive a subject from display name |
| Pairwise OIDC `sub` | Independent UUIDv4 per sector | Stable across disconnect/reconnect; public durable ID without creation time |
| Managed `client_id` | UUIDv4 initially | OIDC itself does not mandate UUID; do not derive from app name/domain |
| OIDC `sid`, Logout Token `jti` | UUIDv4 | Public references, distinct from secret cookies |
| Vault/collection/object/grant IDs; message/device IDs | UUIDv4 | Potentially public; bind owner and purpose separately; do not replace protocol key/MLS formats |
| `operation_id`, `delivery_id`, ceremony reference, own signing-key `kid` | UUIDv4 | Retain stable retry IDs; bind ceremony to browser; use a mandated key-reference format where applicable |
| Separate internal audit/outbox row ID | UUIDv7 candidate | Private append-only record only if an additional key is needed and measurements support it |

An internal v7 outbox row ID is not the delivery protocol ID. If an existing delivery ID/composite key identifies the row, do not add another primary key.

## Values that must not become UUIDs

Use independent CSPRNG values with their required entropy and format for bearer cookies, authorization codes, access/client secrets, CSRF state, OIDC nonce, PKCE verifier, and WebAuthn challenge. Do not reduce a 32-byte challenge to a UUID. Preserve external WebAuthn credential IDs and source-message IDs as opaque values; `userHandle` is a byte string bound to an owner, not inherently a UUID. Keep issuer, redirect URI, RP ID, origin, keys/fingerprints/hashes/AEAD nonce/MLS references, revisions/epochs/grant versions/cursors/policy hashes, and federation DIDs in their protocol-defined forms. A UUID is a reference, not proof of authentication, authorization, or key ownership.

## Representation, storage, and retries

For Mikaki-issued UUIDs, prefer lowercase canonical hyphenated 36-character strings in external APIs, including pairwise `sub`, without switching sometimes to `urn:uuid:`. Treat an incoming foreign `(iss, sub)` exactly as issued, including case; do not assume another issuer's subject is a UUID. Validate version, variant, and canonical form at Mikaki boundaries; do not silently normalize signed or AAD-bound strings. Choose a maintained generator with the same format contract on native/Wasm.

Use thin Rust types where account, vault, or other ID mix-ups matter, without making every internal use a new UUID implementation. Parsing an ID does not authenticate its owner. Compare 16-byte versus 36-character DB representation and use one adapter convention. Measure any v7 index benefit; avoid extra IDs on tables already identified by composite keys.

On collision, unique constraints reject insertion rather than overwrite. A never-published newly generated ID can be regenerated; a published ID or retry ID must not change opportunistically. Reject reuse of one operation/delivery ID with different request contents. UUIDv7 timestamp is not authoritative auth, expiry, or commit time. Keep `created_at`, `auth_time`, `expires_at`, and a true commit sequence separately. Do not implement sync as `WHERE id > cursor` if clock rollback or concurrent inserts can be missed.

Tests should cover canonical versions/variants and CSPRNG on native/Wasm, sector-separated stable subjects under concurrent first issuance, v7 same-millisecond generation and clock rollback if adopted, collision and changed-content retry rejection, response-loss retry ID preservation, opaque non-UUID external IDs, and no accidental exposure of internal v7 IDs.

References: [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html), [OIDC Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken), and [pairwise subjects §8.1](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg).
