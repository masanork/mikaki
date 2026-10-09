# Account enrollment

Account creation requires an invitation and a discoverable, user-verified Passkey. The browser cannot choose an account ID or an administrator role. Invite verifiers are stored as SHA-256 hashes in D1. A successful registration consumes the invitation, registration transaction, and login transaction in one D1 batch.

## First administrator

Use the current migrations in `crates/worker/migrations` and deploy the Worker before issuing an invitation. The reset database uses `0001_owner_vault_initial.sql`; do not reapply the historical pre-reset enrollment migration. The bootstrap gate can create exactly one administrator and closes permanently when that account is registered. On an operator machine, issue the short-lived invitation into a new file (mode 0600):

```sh
node scripts/bootstrap-admin.ts \
  --config crates/worker/wrangler.production.jsonc \
  --remote yes \
  --actor masanork \
  --reason 'initial administrator enrollment' \
  --output local/generated/bootstrap-admin.json \
  --apply yes
```

The output contains `invitation` and `expiresAt`. Open `https://auth.mikaki.org/enroll` on the intended administrator's device and enter the invitation before it expires. The invitation is shown only in the private output file. A new bootstrap invitation can be issued after an unused one expires; the closed gate cannot be reopened by this CLI. Delete the private file after use.

## Further accounts

The home and enrollment screens link to `/waitlist`. An applicant submits an email address and confirms it using the link in the confirmation email. The link alone does not confirm the address: the applicant presses the confirmation button. Only confirmed requests appear in the administrator's waiting list. Submissions return the same response for an address that is already waiting, invited or registered.

An active administrator with a current SSO session opens `/admin`, selects a person and presses **Invite**. A fresh, user-verified Passkey assertion approves that particular person and action. The Worker atomically commits the one-time invitation, audit entry and mail job, then sends the invitation email. The recipient enters the code at `/enroll` and creates their Passkey. Email is used only to contact the applicant: it is not an account identifier, login credential or recovery method.

The administrator list shows waiting, invited, expired and registered requests, as well as sending and failed delivery states. It supports pagination. **Resend** requires another fresh Passkey approval, keeps the existing code and expiry, and is available after a 60-second cooldown. A replacement for an expired invitation has a new code and revokes the old unused invitation. A successful registration consumes the invitation once, as in the manual flow.

Invitations expire according to `enrollment_policy.invite_ttl_seconds` (initially 24 hours). Only an active administrator can issue or back an invitation. The administrator operation expires according to `management_ttl_seconds` (initially five minutes). **Give an invitation code directly** remains available as a secondary option for administrator-assisted enrollment.

## Waiting list operations and activation

This feature adds `0003_enrollment_waitlist.sql` after `0002_owner_key_wrap_operations.sql`. Apply these additive migrations in order using the production configuration; do not reset the database or reopen the bootstrap gate. The deployment verifier pins the complete migration ledger, SQL bytes and schema. Feature activation also requires:

- Cloudflare Email Sending onboarding for `mikaki.org`, including verified sending DNS and permission to send from `no-reply@mikaki.org`. `ENROLLMENT_EMAIL` restricts the allowed sender to that address. See [Workers sending API](https://developers.cloudflare.com/email-service/api/send-emails/workers-api/) and [sender bindings](https://developers.cloudflare.com/email-service/configuration/send-bindings/).
- A random 32-byte `WAITLIST_MAIL_KEY`, encoded as unpadded base64url, provisioned as a GitHub Actions repository secret and Worker secret through the production deployment workflow. Generate it into protected secret storage; do not put it in source control or command output.
- The ordinary production release gates and deployment checks. The October 9 local implementation has not activated these changes in production: the available Cloudflare token cannot inspect Email Sending (`10000 Authentication error`).

Follow the [ordered waiting-list rollout](enrollment-waitlist-rollout.md). Deploy the existing Worker's readiness bridge before applying `0003`, prepare the verified feature release first, record a fresh recovery bookmark and then promote the feature. The bridge preserves a compatible code fallback on the upgraded database.

Mail jobs store an opaque job ID and token hash, never the plaintext confirmation or invitation token. The secret key deterministically derives each job's token so a retry sends the same code. Keep the key stable while mail jobs or invitations are live; replacing it invalidates the verifier for outstanding jobs. No applicant address, token or provider error body is logged.

The Worker attempts delivery immediately and the scheduled handler retries due jobs, with a lease to prevent concurrent sending, a 30-second send deadline, exponential backoff and at most five attempts. An abandoned final lease becomes a failed job so an administrator can resend. Provider acceptance followed by a lost database response can deliver the same message twice; it cannot grant a second account. Administrators can retry a failed invitation explicitly. Confirmation expires in one hour, and another confirmation request is allowed after ten minutes. An expired or superseded confirmation is cancelled. The initial limits are five requests per source and 100 requests per deployment per hour, with a separate confirmation budget four times as large and a maximum of 10,000 stored contacts. Limits are held in `enrollment_waitlist_policy`.

Unconfirmed contacts with no confirmation request in the last 30 days, and contact details for registrations completed more than 30 days ago, are removed in bounded scheduled batches. Confirmed applicants awaiting an invitation remain on the list. The invitation audit retains the opaque waiting-list ID rather than the email address.

Local development uses `send_email.remote=false` and simulates delivery without sending mail. Browser integration tests use a disposable mail sink and synthetic `example.test` addresses, and separately exercise the native local email binding. Never record browser evidence or mail bodies from production applicants.

`enrollment_policy.registration_ttl_seconds` controls the `/enroll` browser ceremony (initially five minutes). D1 policy values can be changed without redeploying the Worker. SSO lifetime remains in the separate versioned runtime policy. The [same-account additional Passkey and saved-data transfer flow](vault-passkey-transfer.md) is included in the current owner Vault baseline. All-key-loss recovery is still unavailable. Retain another trusted administrator before depending on this service for other users.

If the browser loses the registration response after submitting the Passkey, the account and invitation may already be committed. Do not issue a replacement invitation immediately. Open a fresh login and try the newly created Passkey. A repeated registration request cannot create another account from the same invitation. If the Passkey is unavailable and there is no other credential for that account, this deployment cannot recover it; an administrator may invite a new account, which has a distinct subject and no automatic transfer of the old account's data or grants.

The locally updated [registration completion and invitation screens](product-ui-preview.md) preserve these authorization boundaries. Registration completion links to the owner Vault and, for an administrator, invitation management; that navigation does not approve sharing or require PRF for ordinary login.
