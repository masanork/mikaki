# ADR 0005: Invitation enrollment, first administrator, and initial recovery

**Status:** Accepted, 2026-09-22. This record is a product decision; consult [status](../status.md) for implementation evidence.

## Context

Public self-registration is outside the initial scope, but the first administrator and loss of every passkey needed explicit rules. Email, phone, or manual identity recovery would introduce additional identity checks and operational duties.

## Decision

- A verified Mikaki administrator issues a one-time invitation for each ordinary new account. Application membership is separate. General RPs cannot issue invitations or manage credentials.
- Administrator status is an explicit Mikaki role, not automatically an OIDC claim or application role. Creating or revoking invitations and changing administrator status require a one-time, operation-bound management authorization with user verification.
- An operator issues the first administrator's bootstrap invitation through a trusted deployment or CLI boundary. Public HTTP cannot create it. A single bootstrap state in the initial DB gates issuance and consumption.
- Consume the bootstrap invitation, create the account and credential, grant the administrator role, and permanently close the gate in one atomic operation. Concurrent registration must not create two first administrators. An unused expired invitation may be replaced only while the gate is open; replacement revokes the earlier invitation.
- An ordinary invitation creates a new account only. It cannot grant an administrator role or reset an existing account's credentials. Adding a credential to an existing account uses the existing authentication and management contract.
- The first version has no recovery path after loss of every passkey. Operators cannot rebind keys or merge accounts by matching email, and a new invitation does not inherit the old account or pairwise subject.
- Do not allow removal of the last active credential or normal demotion/suspension of the last active administrator. Arrange an explicit handover first. Service-wide incident shutdown is a separate operation.

## Invitation handling

An invitation secret is 32 CSPRNG bytes. D1 stores a hash, kind, issuer, expiry, single-use state, and cancellation state. Initial defaults are 24 hours for an ordinary invitation and 15 minutes for bootstrap, subject to operational configuration.

The initial UI accepts a code and binds it to that browser's registration transaction. Do not place the secret in a URL query, log, or external analytics. Possession allows enrollment; it does not prove a person's real-world identity. The issuer must deliver it through an appropriate trusted channel.

Do not consume an invitation when registration begins. Recheck expiry, use, and cancellation and consume it atomically when the credential is committed. A valid WebAuthn response alone is not successful enrollment. After a lost registration response, use the newly registered passkey to check the result; never reuse the invitation to create another account.

Do not reopen bootstrap merely because account count later becomes zero. Restoring an old DB is a separate recovery event, and the bootstrap gate cannot replace a lost administrator credential.

## User impact and acceptance

Explain that losing every passkey prevents return to the same account, and recommend another authenticator. Synced passkeys mean credential count does not necessarily equal the number of independent recovery routes. Account login recovery would not automatically recover vault keys. Any future recovery design needs a new ADR addressing identity proof, audit, delay and notice, session revocation, and subject continuity.

Acceptance tests cover concurrent bootstrap consumption with one winner; rejection of administrator grants through ordinary invitations; expiry, cancellation, and registration races; reuse and RP issuance rejection; protection of the last credential and administrator; and no duplicate account after a lost response.
