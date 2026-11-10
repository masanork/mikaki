# Access and verified-email integration

## Production status on 2026-11-10

The integrated code landed in #351 and was deployed; Owner migrations `0011_access_email_bindings.sql` and `0012_access_email_scope.sql` were applied. See the [rollout record](owner-email-bridge-rollout.md) for the source, version, audit and recovery boundaries. The production configuration does not set the Access client ID, and public discovery does not advertise the email scope. Deployment and schema application do not qualify a real Access client, verified owner-email mapping, session revocation, or existing Cloudflare OS data continuity.

## Historical integration evidence

The original isolated worktree merged the #349 candidate with #346 head `3acac060`. At that stage the migration names were provisional and the experiment was not a release candidate.

The structural merge preserves the 0001–0010 email chain, pins the two candidate Access SQL files after it, extends retained authority-packet generations, and retains both branches' Worker contract suites. Owner/Work packet and schema tests pass locally (26 tests), as do the four Access SQL tests. These tests do not qualify the combined application behavior.

The shared ID-token signing implementation retains both sets of tests and rejects ASCII whitespace in emitted email addresses. The existing verified-email enrollment validator rejects such whitespace as well; this compatibility observation is not production qualification.

The integration selects a distinct scope profile for generic verified-email consent and the configured Access client. It preserves the general canonical review scope while retaining the Access-specific stored authorization scope, separately checks both disclosure paths, and adds Access binding identity/revision to the final guarded token exchange. A real local Worker/D1 test exercises both profiles together, generic `client_secret_post` denial, Access `client_secret_post` success, stale binding and mixed-marker denial, and independent withdrawal. The original Access and verified-email suites also pass locally. Actual integrated Cloudflare Access client qualification and independent security review remain open; a successful local test does not establish them.

The integrated code adds update/delete guards to both Access audit tables. The 0011 SHA-256 is `fba07c7f4b3208ac33d8de87f275d9f7af36efc2ffa9f9a555981a37a9d09a73`, replacing the original #346 bytes used in the #350 bridge experiment. The final SQL was rehearsed in isolated D1 and applied in production; this does not qualify historical restore or all external state. The guards prevent ordinary SQL update/delete of audit rows, not privileged schema changes or database restoration.

The read-only `node scripts/audit-email-bridge-schema.mjs --remote --stage 11` and `--stage 12` checks compare the complete Owner, Work and Messaging schema, ordered ledgers and foreign keys against the pinned candidate migration bytes. They do not apply migrations. Their separate remote reads are not an atomic snapshot, do not fence concurrent writes and do not establish recovery readiness.

For a local staged rehearsal, build the bridge and integrated Worker in separate checkouts, then run `MIKAKI_ACCESS_FEATURE_CHECKOUT=/path/to/integration node /path/to/integration/scripts/probe-access-final-chain.mjs` from the bridge checkout. The disposable workerd/D1 harness checks bridge readiness and a synthetic existing-account OIDC exchange at 0010, 0011 and 0012, then feature readiness and exchange at 0012. It compares existing authorization context rows and the token-issue count across the 0012 table replacement. Claim readiness is mocked. This does not exercise production data, physical Passkeys, or a Cloudflare rollback.
