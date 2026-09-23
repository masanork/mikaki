# Trusted WebAuthn inputs and ceremony contract

**WG-02, 2026-09-23.** This document separates checks in the portable core and auth layer from the caller's durable responsibilities.

## Inputs to the core

`Context`, `StoredCredential`, and `Ceremony` represent trusted server state. Do not merge browser credential responses into them. Deserializability does not establish trust. HTTP accepts a credential response and transaction reference; the server supplies policy, saved key and owner, time, and consumption state.

`Context::validate()` checks nonempty canonical base64url challenge; nonempty origin and RP ID without surrounding whitespace; positive size/depth bounds; and a nonempty, deduplicated supported-algorithm list. Identified authentication additionally requires bounded, nonempty canonical base64url user handle and allow list. Both `register` and `authenticate` call it and return `configuration` on failure; issuers can call it too. Later mutation of public fields cannot bypass entry-point validation.

This is not a URL parser or deployment-schema validator. Deployment owns HTTPS versus local-development origin choice, origin/RP ID relationship and ownership, sensible operational limits, challenge entropy/reuse, and attestation source/freshness. The core checks exact origin and RP ID hash against supplied trusted values; data shape cannot prove those values were trustworthy.

## Responsibility table

| Concern | Core / auth | Caller and store |
| --- | --- | --- |
| Challenge | Compare saved challenge to client data | Generate using CSPRNG and persist with ceremony; local OP uses 32 bytes |
| Purpose | Require create for register, get for authenticate; auth checks saved purpose | Save issued purpose, never adopt response purpose |
| Browser, time, attempts | Auth checks nonempty matching browser binding, unused state, expiry, and attempt limit | Authenticate browser transaction, pass trusted now, persist failures |
| UV, algorithm, ceremony mode | Verify against saved policy | Keep issuance and completion policy consistent |
| Discoverable assertion | Match response user handle to stored credential's handle | Return consistent key, owner, and active state for credential ID |
| Identified assertion | Match saved user handle and allowed credential ID; match response handle if present | Build handle/allow list from the account selected at issuance |
| Registration owner | Verify response key and attestation, not account ownership | Bind invitation and issued ceremony to the account |
| Verified result | Nonconstructible/non-deserializable Rust type | Do not accept serialized result JSON from HTTP |
| Single use / concurrency | In-memory verification does not consume a challenge | Atomically commit challenge consumption, credential state, and session issuance |

Calling the verifier directly omits auth browser/expiry/attempt checks; calling auth still does not create durable single use. A successful verification followed by a losing or failed store commit is not a successful login.

The local OP rechecks unused state, browser, expiry, and attempt count in SQL and checks affected rows. On assertion it rechecks credential revision, active state, and account epoch; on registration it batches invitation consumption, bootstrap, and credential uniqueness. The native conformance SQLite adapter also tests transaction races and rollback. Types cannot substitute for these store properties.

In a durable deployment, save issuance-time policy revision, deadline, and limits. Do not silently change an outstanding ceremony when runtime policy changes; immediate emergency-stop rules are separate. The disposable local OP stores challenge, purpose, browser, account, and expiry but rebuilds origin/RP ID, UV/algorithm, input, and attempt bounds from a fixed environment. It has no hot reload and recreates DB at restart. It did **not** establish policy snapshots across durable DB and mixed deployments; persist and test those before claiming that guarantee.

The WG-02 change chose validation at both entry points rather than adding purpose-specific state types or builders without a concrete misuse to solve. Constructor-only validation would not cover later public-field mutation or deserialization. A private type cannot make a dishonest trusted caller honest. Native/Wasm shared tests reject bad config through both entry points and verify owner, allow list, and UV; auth tests cover wrong purpose, empty/wrong browser, expiry, consumption, and attempts. Store and browser tests cover concurrent completion, retry, and rollback; JS tests cover the configuration-error boundary. The official FIDO GUI suite was not rerun for WG-02.
