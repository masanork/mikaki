# Waiting list rollout

## Single-email code update

After the initial rollout below, the single-email invitation flow uses the same
`0001`–`0003` ledger and schema. Run the ordinary verified release and promotion
workflow without applying a migration, resetting D1, reopening bootstrap or
replacing `WAITLIST_MAIL_KEY`. Existing invitation codes and unexpired confirmation
links remain valid. Unsent confirmation jobs are cancelled; new requests queue
without email, and administrator approval sends the invitation link.

Local qualification must cover zero mail on request, unverified requests in the
administrator list, fresh Passkey approval, invitation-link registration, refresh,
language changes, cancellation, expiry and replay. Production delivery of the new
email and a recipient's actual Passkey ceremony require explicitly authorized test
participants. Previous two-email receipt evidence does not qualify the new flow.

## Initial schema activation

Deploy the owner-schema bridge before activating the waiting list in PR #171.
The bridge keeps the existing Worker ready with either the complete `0001`–`0002`
ledger or its reviewed additive `0003_enrollment_waitlist.sql` extension. It does
not expose waiting-list endpoints, change account authority or loosen the
deployment verifier's complete-schema check. Unknown or incomplete ledgers still
fail readiness.

## Prepare and deploy

1. Verify Email Sending is onboarded for `mikaki.org`, including sending DNS and
   `no-reply@mikaki.org`. Keep the existing DNS mail configuration intact. See
   [Cloudflare domain setup](https://developers.cloudflare.com/email-service/get-started/send-emails/#set-up-your-domain).
2. Provision `WAITLIST_MAIL_KEY` in the GitHub `production` environment. It must
   be a random 32-byte value encoded as canonical unpadded base64url. Keep its
   value out of command arguments, logs and source control. The feature's
   production workflow supplies it to the uploaded Worker version; do not use
   an immediately activating `wrangler secret put` to stage this change.
3. Merge and deploy the bridge through the existing attested main CI path.
   Record the active version ID and confirm authenticated `/ready` returns 204.
   Preserve this version as the compatible code fallback after migration.
4. Merge the waiting-list feature after its checks pass against the bridge.
   Let main CI verify and prepare the release. The existing deployment gate
   stops before upload while `0003` is pending; it does not migrate the DB.
   Wait for the verified release artifacts before changing the schema.
5. Immediately before applying the reviewed migration, record a fresh D1 Time
   Travel bookmark, the complete ledger/schema, foreign-key status, the closed
   bootstrap gate and aggregate account/credential/administrator counts. Apply
   only `0003_enrollment_waitlist.sql` from the reviewed feature commit using
   the production configuration. Do not reset the DB or reopen bootstrap.
   If the command fails or its response is lost, inspect the ledger and schema
   before deciding whether any further action is needed; do not blindly retry.
6. Verify the complete `0001`–`0003` schema against the reviewed SQL, account
   counts and closed bootstrap. Confirm the bridge remains ready. Rerun the
   failed promotion jobs so the already verified release is staged, its
   bindings inspected and its recorded Worker versions activated.
7. Confirm the exact source/version public smoke and authenticated readiness.
   Qualify invitation mail, administrator approval and recipient enrollment
   with explicitly authorized test participants before declaring the email
   flow operational. Local simulated mail and public endpoint smoke alone do
   not prove production mail delivery or an owner's Passkey ceremony.

## Recovery

If feature upload or activation fails after the additive migration, the bridge
can continue serving the existing account flows on the upgraded DB. Use the
recorded compatible bridge version for a reviewed code rollback if necessary.
Keep the migration and the mail key stable; a code rollback does not restore
D1 or undo mail jobs. Do not restore an older DB or re-enable bootstrap as part
of this rollout. Follow the [release recovery procedure](release-and-recovery.md)
for separate recovery decisions.
