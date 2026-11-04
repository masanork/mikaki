# Cloudflare Access OIDC interoperability plan

Status: experimental implementation in this worktree. Normal-profile Basic is
disabled by default and has not been qualified or activated in production.
Verified email schema, eligibility view and experimental, default-disabled
start, confirmation and owner grant/revoke endpoints exist. Experimental
email scope and claims are wired into ID Token and UserInfo and tested locally.
An experimental owner UI is present. A local browser test exercises its controls
against the Worker, D1 and simulated email with a seeded session. A deterministic
test runs the production commit SQL after a consent revoke/regrant; a concurrent
test also races code exchange with withdrawal. These do not qualify a real
Passkey ceremony, real delivery or Cloudflare Access interoperability.

Cloudflare Access can use its generic OIDC connector alongside other identity
providers. It documents a client ID and secret, authorization, token and JWKS
URLs, optional PKCE, an email claim and a connection test. See the
[Cloudflare integration guide](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/generic-oidc/).
The exact token authentication method, requested scopes and handling of missing
email must be observed with the intended Access tenant before claiming support.

## Current boundaries

- The normal issuer advertises `private_key_jwt` and `none` by default. The
  experimental `MIKAKI_CLIENT_SECRET_BASIC=on` switch adds Basic to the normal
  profile; it does not enable POST or alter FAPI. The conformance profile also
  supports POST. The existing verifier stores SHA-256 secret
  verifiers, enforces a fixed registered authentication method and checks
  credential and client revisions during code exchange. Its no-PKCE exception
  is exclusively for conformance clients.
- The experimental operator registration stores a verifier and an audit row;
  it accepts only a 32-byte base64url secret and fixes PKCE on. Operators must
  generate that value with a cryptographically secure random generator and
  protect the input file and delivery channel. The `client_secret` table has
  one row per client. Experimental rotation is an immediate cutover guarded
  by the expected secret revision, with an immutable audit entry. It increments
  the client revision and invalidates earlier authorization codes; it cannot
  provide overlapping secrets or uninterrupted cutover. Secure delivery and
  incident procedures need qualification before normal-profile activation.
  The experimental CLI reads secret inputs only from owner-owned, owner-only
  regular files (no final symlink) on POSIX and does not print the secret. A
  registration input uses `client_id`, `sector_identifier`, `redirect_uris` and
  `secret`; a rotation input uses `secret` and `expected_revision`. Generate a
  fresh 32-byte random value and encode it as unpadded base64url; the CLI can
  validate the encoding but cannot establish the quality of its randomness.
  Rotation has no overlap: coordinate the RP update and expect in-flight codes
  to fail. Disable the client for a suspected compromise; separately revoke
  Access sessions because client disable does not revoke them automatically.
- Enrollment waitlist email is an invitation contact, not an account identity.
  Its `verified_at` must not be interpreted as a current verified account email.
  Separate email and challenge records, an eligibility view, and start and
  confirmation endpoints are present. An accepted mail request is not proof of
  inbox delivery; an ambiguous send result is not retried automatically. Email
  Email scope and claims are available only under the experimental switch and
  an active account-specific grant. The issuance transaction rechecks the email
  and consent revisions after signing. UserInfo rechecks current authorization.
- Access does not implement mikaki's managed RP `/session/check` contract.
  Do not claim immediate propagation of mikaki logout or account revocation to
  an existing Access session. Verify Access session duration and revocation
  independently.

## Implementation sequence

1. Capture the actual Access authorization and token request in a disposable
   integration environment, without retaining secrets or codes. Confirm Basic
   versus POST authentication, PKCE S256, scopes and ID-token claim needs.
2. Complete normal-profile, per-client explicitly registered secret support while
   preserving mandatory PKCE, the native and FAPI boundaries, and the existing
   `private_key_jwt` path. Provision high-entropy secrets securely, store only
   verifiers and audit without recording secret material. Design overlapping
   rotation and atomic revision checks, including in-flight exchange races.
   Do not enable this merely by setting the conformance deployment profile.
3. Build an account-bound email verification and change/removal lifecycle:
   authenticated initiation, one-use time-limited possession challenge,
   bounded attempts and delivery, atomic confirmation, replacement and
   revocation. Bind verification to the precise account and address. Treat
   delivery failure and replays as failures; never promote an invitation contact.
4. Add client-level permission and explicit user consent for `email` scope,
   scoped to the exact RP and attribute. Release only a currently verified
   address, with `email_verified: true`, under the configured policy and active
   consent. Determine from the Access test whether ID token, UserInfo, or both
   need the claims. Keep `sub` pairwise and never link accounts by email alone.
   Withdrawal, email replacement and client disable must affect future issuance.
5. Test locally with real Worker/D1 and browser flows: positive exchange and
   claims, wrong/mixed credentials, replay, missing PKCE, wrong redirect,
   verifier and client revision races, rate limits, consent denial/withdrawal,
   unverified and replaced email, and unrelated-client non-disclosure. Then
   test the Access connector and a protected test application, including policy
   denial, logout and expiration. Record the exact deployed candidate and keep
   local, staging and production evidence separate.

This plan does not authorize production configuration changes. Deployment and
claim release follow the repository's existing release and verification gates.
