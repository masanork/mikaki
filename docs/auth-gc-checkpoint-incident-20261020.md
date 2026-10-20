# Auth GC network failure and login outage, 2026-10-20

Android returns a Passkey assertion, but `POST /login/finish` returns HTTP 500
with `authority_unavailable`. Production logs identify a pending authority
checkpoint, rather than an Android RP-validation error, as the current blocker.

## Evidence

At 2026-10-19 22:13:17.602 UTC, the scheduled authentication-state retention
batch reported `Network connection lost.`. At 22:13:30.337 UTC, the coordinator
recorded `authority_checkpoint_failure`, stage `d1_batch`, category
`network_lost`, sequence 9705. Its subsequent observation recorded
`previous_marker_quarantined`, followed by `auth_gc_failure`. The deployed
Worker version was `40c16bfd-e615-4f86-b07d-9c929c77a8ca`, annotated with source
`ad7189e7bcd8a52b8f288a4f7a349c1c5143219b`.

Read-only inspection found both D1 and the independent checkpoint at sequence
9704, matching the pending permit's exact previous marker, including epoch and
tip. The pending permit advances 9704 to 9705. The authority is not frozen,
the release floor is 1, and the last completed permit advances 9703 to 9704.
Later login attempts fail at `permit_begin` because this permit remains pending.

The network error does not establish whether the original write aborted.
Ordinary automatic recovery must continue quarantining the previous marker.
The failed invocation is the scheduled, expired-state-only deletion batch in
`crates/worker/src/auth_retention.sql`, not a login, live revocation, credential
change, or external effect. Its SQL is unchanged from the incident source.

## Prepared operator settlement

The existing [operator tool](../scripts/settle-reviewed-auth-gc.ts) is repinned to
this one incident. It no longer accepts the permit from the
[earlier incident](auth-gc-checkpoint-incident-20261019.md).

- Authority: `mikaki-auth-work-v1`
- Object: `1d06c242fcae199a9308facb664bdf3544d6a31cf9b96ef21d9a59f5a9ae46c3`
- Permit SHA-256: `fe59bfb978fc59e75a333e2e9e51a9c67b1f1e3c6f6e74a2b8fbf00dd29f160d`
- Exact transition: 9704 to 9705

The default command only inspects and produces a plan. The privileged execution
path requires a new private journal, rechecks the exact permit and both markers,
refuses open transaction frames, and advances only the existing marker with CAS.
It then observes the exact next D1 marker and commits that same permit through
the ordinary private service. A late original batch cannot pass its leading
CAS and guard afterward. The recovery replays no retention SQL and changes no
account, credential, session, grant, or consent rows. It creates no new permit,
public endpoint, migration, deployment, reset, or general recovery exemption.

An operator must explicitly choose execution of this incident-specific plan.
Technical preparation and a passing read-only plan do not mean production
settlement has run. The coordinator's treatment of unknown outcomes is unchanged.

## Qualification

The actual D1/SQLite Durable Object operator suite passed all 10 cases with
`node --test local/conformance/reviewed-auth-gc-recovery.test.ts`. Formatting and
diff checks passed. The default CLI inspected the fixed production targets and
returned `status: ready`, previous sequence 9704, next sequence 9705 and
`fence_required: true`, matching the exact permit digest above. No execution
flag was supplied and neither marker was advanced.

The temporary Android diagnostic APK was replaced with the original signed
release, independently verified by pulling the installed APK and comparing its
SHA-256. The ADB debugging port was removed and the original screen preference
remained off. App data was retained.

## Production result

The user explicitly approved the incident-specific settlement. The private
operator journal records the exact next D1 marker at 2026-10-20 03:29:01.053 UTC
and completion of the existing permit at 03:29:01.160 UTC, sequence 9705.
No retention SQL or other business changes were replayed by the operator tool.

Independent post-recovery reads found D1 primary and the separate checkpoint
equal at sequence 9706, with no pending permit, floor 1 and `frozen: false`.
The normal scheduled collector recorded `auth_gc` at 03:29:19.432 UTC and
reclaimed 44 expired rows. These observations confirm that subsequent ordinary
updates resumed; they do not qualify real-device login or Vault unlock.

Fresh authentication in the normal signed Android release then succeeded.
Production `POST /login/finish` returned 200 at 03:32:33.633 and 03:32:52.041 UTC;
a read-only aggregate confirmed fresh SSO authentication timestamps. The Pixel
displayed the Vault with its profile and private-note sections marked unlocked.
This qualifies the observed device login and Vault unlock, not document reading
or any external disclosure or copy operation.

The initial failure is now identified as a lost D1 network connection. The
coordinator's quarantine policy remains unchanged, so another unknown storage
outcome can require operator review again. This recovery does not claim a
general automatic cure for that availability problem.
