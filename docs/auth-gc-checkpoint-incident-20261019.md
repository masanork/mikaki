# Auth GC checkpoint incident, 2026-10-19

This is a historical incident report. The operator CLI is now pinned to the
distinct [2026-10-20 recurrence](auth-gc-checkpoint-incident-20261020.md); the
earlier permit is no longer accepted by its current command.

Passkey verification succeeded, but `POST /login/finish` returned 500 with
`authority_unavailable`. A separate Cloudflare analytics beacon CSP warning
did not explain the server failure.

## Evidence

The production D1 authority marker and the independent checkpoint both remained
at sequence 8829. The checkpoint held one pending permit for 8829 → 8830. D1
matched that permit's exact previous marker, including epoch and tip. The
independent authority was neither frozen nor above the supported release floor.

The first failed invocation was scheduled auth retention GC at
2026-10-17 11:12:30 UTC (20:12:30 JST), on Worker version
`cf12772f-0d04-4c66-818a-b31be785418b`, source
`ff24024db5e69ab63ac21ace491ae7f1b8fecc0d`. Its trace contains a successful
checkpoint `begin` response, followed by `auth_gc_failure`, without a checkpoint
commit. The scheduled invocation itself completed normally. The preceding GC
and checkpoint commit succeeded at 11:11:28 UTC. Later GC and login attempts
were refused by the same pending permit.

The operator reports no manual database restoration or checkpoint manipulation.
The available D1 control-plane audit query contains database queries and no
restore event for the relevant interval. This is supporting operational evidence,
not a proof about every possible privileged action.

The original underlying D1 error was not retained: scheduled GC logged only
`auth_gc_failure`, and settlement can replace the original error with the
authority refusal. All 19 retention statements compile against production.
The production GC tables and incoming foreign-key references were copied through
read-only queries to a private local fixture. The full framed transaction succeeds
locally both at the original invocation time and at investigation time. A transient
D1 failure is possible; the precise initial failure remains unproven.

## Reviewed operator settlement

The ordinary coordinator must continue quarantining an unknown result at its old
marker. This incident uses an explicit privileged operator exception for one
reviewed expired-state GC operation; it does not change automatic recovery policy.
No general reset, timeout, unfreeze, epoch replacement, or replay API is added.

The reviewed SQL is `crates/worker/src/auth_retention.sql`, SHA-256
`66dc723227ea124136de0a5df9dfc48e4b3a5cf3899448d729ad3d9129877368`, unchanged
between the original invocation and the investigated deployed source. It only
deletes expired protocol state; it does not perform a live revocation, login,
credential change, or external effect. Omitting this GC invocation preserves the
same active authority. The operational evidence identifies its pending permit.
This reasoning does not authorize settlement of an arbitrary unknown operation.

[`settle-reviewed-auth-gc.ts`](../scripts/settle-reviewed-auth-gc.ts) pins the
production account, D1 database, checkpoint service, object, authority, sequence
and exact permit digest. The CLI takes a private Wrangler remote-binding config
and produces a read-only plan by default. It exposes no public Worker or route.
`--execute <new-private-journal>` performs only these steps:

1. Refuse a foreign permit, changed epoch/tip, frozen authority, unsupported floor,
   or open transaction frame/guard.
2. Persist and sync a private journal before writing.
3. CAS the exact existing D1 previous marker to that permit's exact next marker,
   with no business SQL. A delayed original batch cannot pass its leading
   CAS/guard afterward. If the original batch wins first, accept only its exact
   next marker and never replay it.
4. Read the exact next marker from D1 primary, then commit the same existing
   permit through the ordinary private checkpoint service.

Lost responses remain resumable through this exact permit. Any unrelated state
refuses further changes. Subsequent unrelated permits are never settled by this
tool. It should be retired after this incident.

## Verification

`npm run test:auth-gc-recovery` exercises actual workerd D1 and the production
SQLite Durable Object implementation. Ten cases cover a read-only plan, both
CAS race winners, no business SQL replay, lost D1/commit responses, journal failure,
foreign permit/object/marker refusal, frozen/release-floor refusal, and open-frame
refusal. The operator suite also runs in `test:work-checkpoint`.

The focused TypeScript check passes. A full fresh-checkout `check:node` additionally
requires the separate design-probe dependencies and generated browser Wasm/policy
artifacts; those unrelated prerequisites were not built for this operator-only
change.

## Production result

The pinned read-only plan matched the incident. The operator tool advanced only
the exact pending marker to 8830 and committed that existing permit. No product
deployment, migration, business SQL replay, credential change, or session deletion
was performed by the recovery tool.

Scheduled GC resumed successfully. A subsequent stable observation found D1 and
the independent checkpoint equal at sequence 8836, with no pending permit, floor
1 and `frozen: false`. A new browser sign-in then completed: `/login/finish`
returned 200, `/authorize` redirected normally, `/token` and `/session/check`
returned 200, and the CFOS home screen was visible. Read-only RP/OP checks found
one new CFOS session with a fresh authentication time and a new parent attached
only to CFOS. Existing baseline sessions were preserved.

The initial storage failure remains unresolved. Checkpoint writes now emit
`authority_checkpoint_failure` with a fixed stage, sequence and closed category
before settlement can mask the original D1 error. The category recognizes known
D1 reset, network, quota, overload and SQLite/guard errors, including nested
JavaScript causes. Raw provider messages, SQL, bindings, account/session IDs,
permits and credentials are omitted. Unrecognized D1 errors become `d1_unknown`;
other unrecognized messages become `unknown`.

The diagnostic category does not determine whether a write aborted. The existing
definitive-abort conditions are unchanged; unknown results at the previous marker
remain quarantined. A runtime regression test injects an unknown D1 error and
checks the original category is logged before quarantine, without business
changes or the private cause text in the diagnostic. The existing definitive
constraint-abort case also checks its category and settled state.

This incident-specific tool does not automatically cure a future unknown write
failure.
