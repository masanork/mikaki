# Passkey web sign-in and Owner Vault opening

First-party web sign-in requests the public, versioned Vault PRF input alongside
its normal WebAuthn assertion. After the server validates that assertion, the same
browser document mounts the Vault and consumes the credential-bound PRF output.
The output stays in document memory for at most 60 seconds and is cleared on
consumption, failure, hiding or navigation. Locking/reloading requires fresh PRF.

A legacy random-input wrapper needs one owner-present unlock to add immutable
same-credential login custody. Its original wrapper, root, record ciphertext,
registry revision and existing grants remain intact. Later web sign-ins open it
with one assertion. Login still succeeds when PRF is unavailable or that login
credential lacks Vault access. Ordinary RP connection review is preserved.
The [owner-key contract](vault-owner-key-contract.md#combined-web-sign-in-and-vault-opening)
describes the supplemental resource and its authority checks.

## Additive production migration, 2026-10-15 JST

At the user's request, repository-pinned Wrangler 4.148.0 applied only
`0006_owner_login_wrap.sql` to `mikaki-auth-owner`
(`d0258938-0d27-4110-8aa9-c82e20f3885b`) in account
`4b749427a0c80c547e726a42aff4b6fc`. Its reviewed SHA-256 is
`5a991fbb3c7b7c531d52dba6ec00f8b635b852f8e504b3074fa5ba06bc6e5b6f`.
The fresh pre-application D1 Time Travel bookmark is
`000001c8-00000006-00005104-ba193a7a1b917cb1ebcadca6e0103561`. It identifies a recovery point; no restore was performed.

Preflight at `2026-10-14T15:22:07.631Z` verified the exact ordered Owner
ledger through `0005_login_connection_review.sql`, all reviewed Work migration
bytes and ledger, and the complete combined schema. Postflight at
`2026-10-14T15:22:13.848Z` verified the exact six-entry Owner ledger and
complete schema against the reviewed migrations. Schema objects increased from
464 to 466: the supplemental table and its immutable-update trigger. Removing
those two new definitions reproduces the original schema digest
`4ce6a2526eb3d4cce8692baf6ef1dd386bfe9179565c8bf4124c1ebc09fb68b6`.
The complete postflight schema digest is
`36053991e632a1847a7cc68911bff9fb906e864b82699741fcbbbe1691b9dd61`.
The new table is empty, `PRAGMA foreign_key_check` returns no rows, and Wrangler
reports no pending Owner migration. No existing table, key or record was rewritten.

Worker `mikaki-auth` stayed at version
`5912fbd5-3e91-47ce-a6a1-9945f344b4ac`, clean source
`a19d30d78300894d38c3e54ac029cec3539a322b`. Health, Discovery and the login
asset returned 200 before and after. Authenticated readiness changed from 204 to
503 because this old binary recognizes the ledger only through `0005`.
**The feature is not activated; code/schema alignment remains pending.**
Promoting this PR's qualified artifact must restore version-matched readiness 204
and public smoke through the normal deployment gates. Recheck those results after
activation. A pre-bridge Worker also rejects `0006` at readiness; a code rollback
does not remove the table or supplemental custody. This additive operation does
not authorize a database reset or a Time Travel restore.

Local qualification includes actual virtual-authenticator login/PRF, legacy-root
adoption and preserved saved records; the existing RP review browser suite, Owner
Vault tests, migration/schema gates and Rust readiness tests also pass. Physical
device PRF and a production authenticated-owner journey remain unqualified.
