# Account enrollment

Account creation requires an invitation and a discoverable, user-verified Passkey. The browser cannot choose an account ID or an administrator role. Invite verifiers are stored as SHA-256 hashes in D1. A successful registration consumes the invitation, registration transaction, and login transaction in one D1 batch.

## First administrator

Apply `0005_account_enrollment.sql` and deploy the Worker before issuing an invitation. The bootstrap gate can create exactly one administrator and closes permanently when that account is registered. On an operator machine, issue the short-lived invitation into a new file (mode 0600):

```sh
node scripts/bootstrap-admin.mjs \
  --config crates/worker/wrangler.production.jsonc \
  --remote yes \
  --actor masanork \
  --reason 'initial administrator enrollment' \
  --output local/generated/bootstrap-admin.json \
  --apply yes
```

The output contains `invitation` and `expiresAt`. Open `https://mikaki.tossa.app/enroll` on the intended administrator's device and enter the invitation before it expires. The invitation is shown only in the private output file. A new bootstrap invitation can be issued after an unused one expires; the closed gate cannot be reopened by this CLI. Delete the private file after use.

## Further accounts

An active administrator with a current SSO session opens `/admin`, confirms with their Passkey and user verification, and obtains a one-time invitation. Give the invitation to the intended person through a trusted channel. They register at `/enroll`; the invitation expires according to `enrollment_policy.invite_ttl_seconds` (initially 24 hours). Only an active administrator can issue or back an invitation. The administrator operation expires according to `management_ttl_seconds` (initially five minutes).

`enrollment_policy.registration_ttl_seconds` controls the `/enroll` browser ceremony (initially five minutes). D1 policy values can be changed without redeploying the Worker. SSO lifetime remains in the separate versioned runtime policy. There is no account recovery or additional Passkey enrollment flow yet, so retain a second trusted administrator before depending on this service for other users.
