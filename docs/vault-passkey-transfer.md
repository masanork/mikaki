# Owner passkey addition and Vault transfer

**Implementation evidence:** local source and tests, 2026-09-28; saved-note UI added and tested 2026-09-29. This is the first VG-01 delivery from the [fit/gap backlog](vault-fit-gap.md), not a completed real-device recovery gate or production deployment.

## Supported operation

An authenticated owner with a working saved attribute key can add another discoverable ES256 passkey to the **same account** and move the saved name or owner note to that credential, one item at a time. Both passkeys must be usable on the transferring browser and return PRF output. The browser decrypts the saved record, creates a fresh data key/ciphertext at the next revision, wraps it under the target credential's PRF-derived key, and reopens the candidate locally to compare the plaintext before sending ciphertext.

The version-1 record format and single owner envelope remain unchanged. This is a replacement at a new revision, not multiple simultaneously valid owner envelopes or an in-place wrap update. Unsaved field edits are excluded. The original passkey remains registered for login; it cannot open the new ciphertext using its old envelope/key. Previously delivered plaintext, keys, old ciphertext, or backups cannot be recalled.

The owner should keep the original passkey until the transferred item has been reopened with the selected credential. All current system/RP/agent disclosures bound to the old name revision are invalidated by the existing head-update triggers. Re-sharing the new revision requires separate consent. The note has a separate transfer panel and does not move with the name. There is no general multi-attribute UI or all-or-nothing collection transfer.

## Credential addition

- `GET /vault/passkeys` returns at most ten active credential IDs belonging to the current account, with no public/private keys or other owners' IDs.
- `POST /vault/passkeys/start` requires same-origin authenticated SSO, authentication within five minutes, and remaining capacity. It returns a fresh 32-byte transaction/challenge, the existing account user handle, RP ID, and exclusion IDs. At most five unconsumed registration transactions and ten active credentials are allowed per account.
- `POST /vault/passkeys/finish` accepts only the transaction ID and WebAuthn registration response. The server validates origin/RP/challenge and user verification through the existing Rust verifier, binds the transaction to the same account and SSO secret hash, bounds requests at 64 KiB, and permits at most five verification failures.
- The D1 batch rechecks live session/account/credential and five-minute authentication before consuming the transaction and inserting the credential/public key. A failed guard or duplicate credential rolls back consumption. Repeating the identical recorded request returns its credential ID while the transaction is retained and unexpired; a changed payload under that transaction fails. No new account or role is created and no existing credential is disabled.

The UI requests resident credentials, `credProps`, and PRF capability. PRF support is tested by an actual evaluation during transfer, rather than assumed from registration success. A successfully registered login credential without usable PRF cannot receive the saved data through this UI. Successful registration does not itself move or recover Vault data.

## Storage commit and retry

`POST /vault/attributes/{attribute}/transfer` uses the existing ciphertext/envelope body and requires `If-Match: "<base revision>"`, same-origin SSO, and a 32-byte `X-Operation-ID`. It never creates an absent attribute or restores a deleted head. The version-1 target envelope must be structurally valid and name a different active credential on the same account. Its stored base envelope must also have a valid version-1 structure.

The endpoint shares the existing Rust attribute-write authority: immutable R2 upload, conditional D1 head update, quotas, rate checks, and retry ledger. The final D1 write rechecks both the current session and target credential, and inserts a content-free transfer audit in the same batch. Audit failure rolls back the head, retry record, and grant invalidation; a newly uploaded unreferenced blob remains for normal GC. The server sees no plaintext/PRF/data key, and cannot prove a caller preserved plaintext or created decryptable ciphertext; preservation and candidate decryption are owner-client checks.

The operation digest distinguishes `TRANSFER` from ordinary `PUT` and includes target attribute, expected revision, and the exact request body. Identical retries acknowledge the recorded revision without replacing a newer head; changed retries fail. The page retains the exact prepared encrypted body and operation ID in memory when a response is lost. Forgetting it or reloading does not cancel a committed operation; reload the authoritative record to determine the outcome. A conflicting transfer must be prepared again from a newly loaded saved record.

Migration `0015_vault_passkey_transfer.sql` adds the owner registration transactions and transfer audit. Apply it before deploying source that uses these endpoints. The transfer audit follows the existing mutation-ledger retention, with cascading removal when its retry record is collected after 90 days. Expired registration transactions are eligible for bounded cleanup after another 24 hours. Production migration/deployment has not been performed for this delivery.

## Saved-note UI, 2026-09-29

The owner note reuses the same Passkey registration/transfer component with its own saved envelope and revision. It evaluates the source credential from that envelope, independently of the account login or name key. The client validates the saved note's type, schema version, title/text bounds and self-asserted provenance before preparing the encrypted candidate, then reopens and byte-compares the candidate. Unsupported notes cannot be transferred through this UI. Unsaved edits never enter the transfer.

The note editor is locked during registration/transfer. After a lost response the exact encrypted body, base revision and operation ID remain available for retry; adding another Passkey is disabled while that transfer is pending. Explicit note reload discards editor/transfer retry state and reloads the authoritative head; it does not cancel an already committed operation. A successful transfer reloads the note and requires a separate open action with the selected credential to confirm it. Concurrent head changes yield a conflict rather than overwriting the new value.

Transferring the note does not rewrite the name or its envelope. Observing the new note revision clears prepared local MCP downloads, but downloaded plaintext files and local grants remain independent copies. Exporting the new saved revision requires fresh selection/consent and PRF. Existing remote MCP reads remain name-only.

## Verification and remaining recovery work

The 2026-09-29 note tests additionally cover saved title/text/provenance preservation, a different login/source/target credential, missing/cancelled PRF, exact operation/body retry after lost response, unchanged name, fresh-page reopening, stale-base conflict and unknown-schema blocking. Browser PRF remains mocked.

After building the OP Worker, run `npm run test:vault-transfer`. Tests use real local workerd/D1/R2, generated WebAuthn registration fixtures, real envelope cryptography, and a browser with mocked PRF output. They cover fresh-login gating, registration replay/payload changes/failure bounds, different-account/inactive-target rejection, audit rollback, old-base/delete conflicts, grant invalidation, saved-versus-unsaved data, absent target PRF, lost-response retries, and reopening from a fresh browser page. Existing storage and agent-browser regressions also passed during implementation.

Before marking VG-01 complete, exercise the supported same-account flow on intended real passkeys/devices. A second browser with synthetic PRF output is not second-device hardware evidence. Qualify synchronized-passkey behavior and cross-device availability explicitly; do not assume every device/transport returns the same usable PRF result. Test real cancellations, expired authentication, and credential removal separately.

The initial recovery policy remains **no recovery after every usable owner key is lost**. There is no encrypted recovery-file export/import, full account recovery, overlapping owner envelopes, or collection-wide migration in this delivery. Adding a passkey before loss and moving one saved attribute provides continuity; it does not establish backup recovery. Protected-backup format/recipient custody, restore validation, credential retirement UI, and malicious-store rollback guarantees remain VG-01 follow-ups. VG-02 schema design can proceed, while broad new write activation retains the VG-01 device/recovery gates.
