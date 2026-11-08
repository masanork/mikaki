# Cloudflare Access integration: implementation and acceptance plan

This plan targets the existing Cloudflare OS Access application while keeping
monban available until the new path has been qualified. It is not evidence that
Mikaki has been registered with Access or is ready for production traffic.

## Isolated Cloudflare qualification, 2026-11-08

The dedicated `mikaki-access-qualification` Worker, D1 database, R2 bucket and
Queue use synthetic data and separate signing/client secrets. The Access IdP is
`Mikaki Access qualification`; its dedicated Access application protects the
separate `mikaki-access-qualification-target.masanork.workers.dev` Worker with
an allow policy for one synthetic address. The original Cloudflare OS app and
monban configuration were not changed. An Access IdP is account-wide: apps
which permit all IdPs can display it. At this checkpoint the existing WARP app
permits all IdPs but its policy selects explicit emails that do not include the
synthetic test addresses. Reassess other policies before leaving this IdP enabled.

Worker version `ac7148a2-1e3b-4ec5-8085-2ce4a36a581e` was built from the local
uncommitted checkout and is qualification evidence, not an attested release.
Its public Discovery advertises email, the secret methods and S256. A synthetic
Chromium virtual Passkey registered against this issuer. An actual Cloudflare
Access request used `openid email profile`, S256 and a 1,567-character `state`;
the dedicated-client bounded state allowance was required. After approval, the
browser completed the Access callback and loaded the protected test Worker.
The isolated D1 recorded `client_secret_basic`. Changing the test binding to a
different synthetic email caused Access to deny that identity; restoring it
allowed login again.

When the synthetic binding was revoked after login, the existing Access session
continued to reach the app, while a fresh browser context could not establish a
new Access session. The binding was restored. This demonstrates a session
revocation gap, not a measured maximum delay or a production logout result.
Access global and application session durations and an operator-driven
revocation procedure must be qualified for the real application.
In a further immediate check, the same browser still reached the test app after
calling that app's Access `revoke_tokens` endpoint while its Mikaki binding was
revoked. The experiment did not distinguish propagation delay from renewal via
an existing global Access session. Do not treat app-token revocation alone as
qualified for immediate access removal; qualify user/global-session revocation
and any required propagation delay separately.
An additional synthetic-user revocation returned success; after 30 seconds the
existing browser did not reach the app, but encountered a redirect loop. In a
follow-up with a new session, the Access user-revocation API again returned
success; after 30 seconds a direct protected request returned 302 rather than
the application, and neither that browser nor a fresh context reached the app.
The IdP binding was revoked during both checks and restored afterwards. This
qualifies neither the minimum propagation delay nor the user-facing recovery
from the redirect loop; use an independently rehearsed per-user procedure for
production.

The test used one synthetic account, one browser and a virtual authenticator.
It does not verify a physical Passkey, the real owner's mailbox binding, current
Cloudflare OS data continuity, deployment recovery or an attested production
release. The qualification resources remain provisioned for further testing.

The production Worker recorded before this work was built with the 0008 ledger.
Its deployed readiness implementation cannot be assumed to accept 0009 or 0010.
Do not apply these migrations directly to the production database under the old
Worker. Prepare and qualify an ordered bridge release and compatible rollback,
including the rebuilt `code_context` table and retained scope-immutability
trigger, before making a production migration decision.

On 2026-11-08 a separate Cloudflare Worker and D1, both named
`mikaki-bridge-qualification`, rehearsed that order with a synthetic account
and Chromium virtual Passkey. The bridge version
`fe0f5ab4-46ff-4c89-9169-2e8efb737fa9` returned readiness 204 and completed
OIDC authorization/code exchange with the same account on each 0008, 0009 and
0010 ledger. Feature version `0c81ef19-acdf-4751-8639-1f45a0d9dc08` then
returned 204 and completed the exchange on 0010. An explicit Cloudflare version
rollback to the bridge again returned 204 and completed the exchange; one
synthetic account and credential remained active. This environment used a
readiness-only mocked Claim Worker (`mikaki-bridge-qualification-claims`) and
the qualification R2 bucket. The staging builds are not attested, and the
exercise did not test production data, Claim delivery, Vault recovery, logout
delivery or a physical authenticator. Both bridge Workers and their separate D1
remain provisioned for review.

## Observed baseline

On 2026-11-07, a read-only Cloudflare API inspection found that the existing
Cloudflare OS application selects only the monban OIDC provider. Its allow
policy uses an email selector. The monban integration requests `openid email
profile`, enables PKCE, and requests the `email` claim. The registered Access
callback is under the team's `cloudflareaccess.com` domain. Do not copy a client
secret or an Access token into this document or test output.

Cloudflare OS resolves its Access identity from the verified Access JWT's email
using `UserDurableObject.idFromName(email)`. Consequently, an exact email
string mismatch can select a different user and data set. The deployed app's
version, email value, policies and effective session settings still require
confirmation at qualification time; repository source alone is not deployment
evidence.

Mikaki's normal discovery advertises `openid profile` and `private_key_jwt` or
public-client `none`; secret authentication is confined to the isolated
conformance profile. Enrollment contact addresses are removed after retention
and are not account identifiers. Do not reuse a transient enrollment row or
enable the conformance deployment in production to bypass these boundaries.

## Intended bounded profile

1. Add an explicitly registered, confidential Access client using the observed
   token endpoint authentication method and mandatory S256 PKCE. Keep it
   disabled by default. Check the exact Cloudflare callback, client, method and
   redirect; never permit missing PKCE for this profile. Preserve native,
   private-key and conformance clients' existing behavior.
2. Add operator-managed account-to-email bindings for this client only. Require
   an explicit trusted account selection and verified ownership process, audit
   changes and revocation, enforce uniqueness within the intended client, and
   preserve the exact email string used by the current Access identity. Do not
   derive or invent an email from a subject or unverified user input.
3. Accept the Access scope combination only for a client explicitly authorized
   for this profile. Issue an email claim in its ID token only after the account,
   client, binding and requested scopes have been checked. Do not claim
   `email_verified` unless the binding's recorded verification supports it.
   Ordinary clients must not gain email access.
4. Couple issuance to the current binding and client revisions in the existing
   atomic authorization-code exchange so that revocation or replacement cannot
   race with token issuance. Handle cached tokens and Access sessions separately.
5. Add operator tooling for registration, secret rotation, disablement and
   binding management with dry-run, audit and secret-safe input/output. A secret
   must never appear in command arguments, logs, source files or CI artifacts.

This is a proposed profile, not a claim that Cloudflare's exact token request
authentication method or email handling has already been observed. Qualify both
against an isolated Access application before relying on them.

## Local operator tooling

`scripts/access-client-admin.ts` supports `register`, `rotate`, `revoke-secret`,
`bind-email`, and `revoke-email`. It requires the same explicit local/remote D1
configuration check as the existing client administration script. Input is an
owner-only, user-owned JSON file; never place secrets or email addresses in
arguments, shell history, logs, or source control. The default operational
practice is `--apply no` first; it checks the target and input shape, but does
not establish database eligibility or verify email ownership.

The registration JSON contains `client`, `redirect`, `secret`, and `method`.
The secret must be a base64url encoding of 32 cryptographically random bytes;
`method` must be `client_secret_basic` or `client_secret_post`. The email-binding
JSON contains `client`, `account`, `email`, `expected`, and
`verified_by_operator: true`. The operator must independently verify that the
exact email belongs to that account and matches the existing Access identity;
the tool does not verify mailbox ownership. `expected` is zero for a new binding
and the current revision for replacement or reactivation. Revocation uses
`client`, `account`, and the current `expected` revision. Secret rotation uses
`client`, `expected`, and a fresh `secret`; secret revocation omits `secret`.
Audit records omit the email and secret. A stale revision or failed audit rolls
back the mutation. The tool returns identifiers and revision, never the secret.

Example invocation after preparing the private file and reviewing the target:

```sh
node scripts/access-client-admin.ts --config crates/worker/wrangler.jsonc \
  --remote no --action register --input /secure/path/access-registration.json \
  --actor operator --reason 'test Access integration' --apply no
```

Do not activate `MIKAKI_ACCESS_SECRET_CLIENT_ID` or use `--remote yes` until the
build, migrations, reviewed registration, backup/rollback and separate Access
test are ready. One active administrator is currently recorded; that does not
establish administrative recovery.

## Acceptance

- Local tests cover successful exchange, scope ordering, bad and rotated secrets,
  replay, PKCE and redirect failures, disabled clients, absent/unverified/revoked
  bindings, cross-account/client isolation and concurrent binding changes.
- Existing normal, native, FAPI and conformance tests remain valid. Verify that
  no email appears in unrelated ID tokens, logs, or diagnostic artifacts.
- In an isolated Access app, record the version and configuration, perform an
  actual Passkey login, verify the expected email without publishing it, and
  confirm an unapproved user is denied. Test both Access and Mikaki sessions;
  do not assume an IdP logout revokes an existing Access session.
- Before changing the existing application, preserve its current IdP and
  policy settings, verify a separate administrative recovery route, and test
  that an existing synthetic workspace and its data remain visible with the
  exact same Access email. Confirm how the deployed app validates its JWT.
- Retain monban as a working login method throughout the trial. Record how to
  restore the original allowed-IdP list and policy, and exercise rollback
  without weakening the Access policy.
