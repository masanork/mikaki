# Authentication resource limits and retention

Deployed in the fresh `0001_owner_vault_initial.sql` baseline and OP source `140baec` on 2026-10-05; the telemetry fix was deployed as `210567e`. The minute schedule, exact baseline and active storage bindings were verified at [cutover](production-reset-2026-10-05.md). The historical incremental migration `0046` is retired; do not apply it to the fresh DB. The policy row is mandatory; missing policy/storage fails closed.

A post-cutover tail observed repeated `auth_gc_failure` events. Read-only
production D1 execution rejected the six-way compound backlog SELECT, although
the two-way control query passed. Cleanup and its telemetry are separate steps:
this failure occurs after the cleanup batch in the source and does not establish
that participant cleanup stopped. PR #130 corrected the query by preparing the
six product SQL statements independently in one D1 batch. Source `210567e`
passed all main CI, attested promotion and public smoke checks. Production
`auth_gc` succeeded at 20:54:20.014 and 20:55:20.014 UTC on 2026-10-05, with all
six kinds expired=0/oldest=null and reclaimed=0; no auth failure was captured.
#99 is complete. These empty-baseline observations are not throughput evidence.

## Admission

`/authorize`, `/token`, `/par`, `/signin`, `/enroll`, `/login`, its cue/finish/deny operations and `/enroll/complete` reserve a durable fixed-minute budget before protocol processing. Cloudflare's `CF-Connecting-IP` is hashed with a purpose prefix; absent addresses share an `unknown` source budget. Static JavaScript/CSS assets do not consume ceremony budget. No cookie can reset this source limit. D1 commits source and deployment counters atomically across isolates. Rejected/invalid requests also spend budget. Limits return HTTP 429, `Cache-Control: no-store`, `Retry-After: 60`, and `temporarily_unavailable` without identifiers.

| Policy                                     | Default | Adjustment bounds |
| ------------------------------------------ | ------- | ----------------- |
| Requests per source per minute             | 120     | 1–10,000          |
| Requests per deployment per minute         | 600     | 1–10,000          |
| Pending transactions per browser           | 5       | 2–100             |
| Pending login transactions per client      | 100     | 10–1,000          |
| Pending transactions per transaction table | 1,000   | 100–10,000        |

Capacity triggers apply independently to RP, first-party web and Agent owner-login transactions. Pending means unconsumed with expiry strictly after now. Consumed/expired rows release capacity; browser rotation still spends source/deployment budget. Multiple legitimate tabs are permitted within the browser limit. Registration is tied to an existing login transaction. The request ledger additionally has a 10,000-row ceiling. Protocol body limits, assertion/DPoP replay protection and existing PAR/client constraints remain in force.

## Retention and collection

The minute cron executes one atomic, child-before-parent D1 batch. Each table deletion selects at most 1,000 oldest eligible rows. Failure rolls back that batch; the next invocation retries. Auth GC failure does not suppress back-channel delivery. Data is removed only after its security retention boundary, never to make room for a fresh authorization request.

| State                                                                            | Earliest cleanup                                                                |
| -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Request budget windows                                                           | More than 120 seconds old                                                       |
| JWT assertion/client receipts and DPoP proof receipts                            | Strictly after their `retain_until`, preserving inclusive replay deadlines      |
| Login, registration, web/owner login, invitation management, logout confirmation | Expiry plus 1 day                                                               |
| Authorization code, issued token and their contexts                              | Expiry plus 90 days; retained children pin parents                              |
| PAR                                                                              | At expiry; request/cron cleanup is bounded to 1,000 rows                        |
| SSO/client sessions and their contexts                                           | SSO expiry plus 90 days, after retained code/consent/logout references are gone |
| Logout delivery and event                                                        | Delivery deadline plus 90 days, including failed/expired outcomes               |

Account, credential, client registration, runtime-policy history and immutable administrative/disclosure audits are retained. This collector does not change token expiries or resurrect revoked sessions.

At defaults, the 1,000-row per-table minute budget exceeds the 600-request deployment ingress ceiling. That is a capacity envelope, not a guarantee during cron outages or unusually high configured limits. Monitor `auth_request_limited`, `auth_gc` (reclaimed plus expired counts/oldest expiry for login, code, token, SSO, logout and DPoP), and `auth_gc_failure`. A backlog whose oldest eligible timestamp grows across successive runs needs investigation before increasing admission limits. Logs contain no accounts, IPs, codes or token values.

`local/conformance/auth-resources.test.ts` exercises two real Worker instances sharing D1, parallel source limits, source isolation, window rollover, browser capacity and repeated cleanup beyond a batch. It also verifies expired token/session dependencies, retention of pending delivery, transactional cleanup failure and recovery. These regressions passed [main CI run 37256255769](https://github.com/masanork/mikaki/actions/runs/37256255769). Production alert wiring and mixed-load measurements remain separate operational work under [#106](https://github.com/masanork/mikaki/issues/106); public smoke is not a throughput measurement.
