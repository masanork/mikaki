# HAIP age receipt pool

The provisioned Android Wallet can request two to eight age-only receipts in one explicit authorization and save them together. This uses sequential single-credential OID4VCI requests: every slot has its own fresh holder key, attester challenge, issuer nonce, key attestation, proof and encrypted request/response. It does not implement or advertise an OID4VCI multi-proof batch. The Wallet still defaults to one receipt.

Enable only in an experimental deployment with the existing complete HAIP issuer/client/attester/certificate/encryption configuration, `IDENTITY_HAIP_AGE_POOL_ENABLED=true` and an age-only `IDENTITY_ISSUANCE_CLAIMS` profile. Discovery adds `mikaki_age_pool: {"max_size":8}`. Absent capability, mixed/raw profiles, oversized counts or unknown claim names fail before enrollment. The native Wallet also checks that the selected count fits its existing eight-slot inventory before starting. No production flag or device qualification is enabled here.

## Authorization and issuer budget

The native protocol freezes a `mikaki_age_pool` JSON string in authenticated PAR, containing `size` and the canonical `claims_json`. Browser parameters cannot replace it. The review shows the requested count, format and age predicates. The issuer copies this budget into the existing grant's `holder_json` before approval, so it survives consumption/erasure of the PAR request. No database migration is needed.

The grant retains the immutable baseline sixteen-slot schema ceiling, but the runtime enforces the narrower approved budget. `holder_json` contains the versioned budget and up to eight previously issued holder thumbprints; raw credentials and proofs are not retained. Each request rejects an already issued holder or a holder equal to the client-instance/DPoP key. Receipt preparation still clips validity to document/source/signing-certificate/key-attestation deadlines (the native broker's holder attestation is at most sixty seconds).

A conditional D1 update checks the complete previous grant snapshot, count, live account/document/policies and unused nonce, increments exactly one slot and records the new holder. The existing trigger consumes that nonce. A second statement closes the access token at the approved count; both statements run in one [transactional D1 batch](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch). An error in closing rolls back the count, nonce and holder changes, and no prepared credential is returned. The result is determined from the consume statement, so a stale concurrent request cannot return another receipt. Ordinary grants without this extension retain their existing budgets.

The enabled age-pool policy includes a new client-policy fingerprint and the exact age profile. Withdrawal or profile changes block use of pooled PAR/grants while they differ from the bound policy. Older binaries compute the previous fingerprint and cannot redeem or use a pooled grant, even if they ignore an unknown request parameter. Retained deployment gates and migration inventories are unchanged.

## Native receiving and failure

After token exchange, the Wallet enrolls and verifies one independently attested holder per slot. It validates every received credential against the configured credential trust and exact age-only profile before acknowledging that slot in its protocol state. Only then can the next fresh holder be bound; previous holder keys cannot be rebound. The protocol closes locally at the requested count.

Receipts remain private in Rust until all slots succeed. The Wallet rechecks expiry, distinct keys, inventory capacity and cancellation before one complete encrypted inventory write. A partial/unknown response, failed attestation, changed profile, expired earlier receipt, cancellation or storage error stops the operation and discards uninstalled keys. Successfully issued server slots remain consumed; there is no background refill or automatic retry of an uncertain issuance. Only an explicit DPoP nonce challenge permits the existing bounded transport retry before successful issuance. Another attempt requires a fresh explicit authorization. Existing inventory entries remain available when a receive cannot be installed.

## Qualification and privacy

Tests cover both formats, eight independently attested keys in the native protocol, exact two/eight-slot server budgets, concurrent final requests, D1 rollback on close failure, sender/holder-role separation, key reuse with a fresh attestation, disabled/changed policy, UI consent/count locking and existing receipt/consent regressions. Real Android Keystore, card and crash qualification remains under #117; the DF31 intake decision remains under #116/#208.

Local single-use retirement applies to each installed age-only receipt. This pool reduces repeat presentation of the same holder key/credential bytes through this Wallet; it does not establish cryptographic unlinkability. The issuer can correlate the authenticated issuance session, and shared provenance, evaluation/expiry times, issuer keys/certificates and small predicate cohorts remain correlation sources. Static assurance and `government_credential=false` remain unchanged; no qualified OID4IDA `verified_claims` are emitted.

The [OID4VCI 1.0 Final repeated-endpoint model](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-14.3) and the [HAIP profile](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html) remain the protocol baseline. Standard `batch_credential_issuance` metadata and a multi-proof HAIP response require separate implementation and qualification.
