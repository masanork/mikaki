# Logout delivery Queue operations

The OP commits session revocation and the `sso_logout_event` / `logout_delivery` outbox rows together in D1. `mikaki-logout-wakeups` is only a prompt to run the existing D1-backed sender; it is not delivery truth. The minute scheduled D1 scan remains enabled and recovers a missed enqueue, a stopped consumer, a dead-lettered wake-up, or an expired lease. A logout is successful when the D1 revocation transaction commits, regardless of Queue or RP availability.

The logout transaction snapshots eligible active RP sessions and their then-active back-channel URI into D1. Disabling a client or changing its URI before logout prevents/changes which rows are snapshotted; changing or disabling it after the logout transaction does not cancel or rewrite an already-snapshotted delivery. The snapshot is the logout event's delivery target, while D1 state, deadline, and lease remain authoritative for whether it can still be sent.

The production Worker config declares the producer binding `LOGOUT_QUEUE` and the worker consumer. The strict message body is `{ "version": 1, "event_id": "<opaque id>" }`. Do not put a SID, subject, cookie, logout token, callback URL, or other user data in a Queue message. D1's existing lease and `jti` logic remains the duplicate guard. Queues are at-least-once, so duplicate wake-ups are expected. Malformed or unknown IDs are acknowledged with sanitized counters; only transient failures before durable D1 completion should request Queue retry.

## Provision and attach

Queue resources are account-level resources. `wrangler versions upload` records the producer Queue binding in the Worker version; it does not create the Queue resource or attach the Queue consumer. Create the two named resources once in the intended Cloudflare account before deploying the feature:

```sh
npx wrangler queues create mikaki-logout-wakeups --message-retention-period-secs 86400 --config crates/worker/wrangler.production.jsonc
npx wrangler queues create mikaki-logout-wakeups-dlq --message-retention-period-secs 86400 --config crates/worker/wrangler.production.jsonc
```

These commands are provisioning steps, not part of local verification. Confirm the names and Queue metadata before deployment; do not reuse an unrelated project queue. The checked-in production config is the source for the consumer target and its bounded settings (`batch_size=1`, `max_batch_timeout=1s`, `max_retries=3`, `retry_delay=30s`, `max_concurrency=2`, and the named DLQ).

After the qualified version is deployed, the existing release step runs:

```sh
npx wrangler triggers deploy --config crates/worker/wrangler.production.jsonc
```

Wrangler reconciles the Queue consumer from the config during this trigger deployment: it looks up the named Queue, then creates or updates the OP Worker consumer. The Queue must exist first. This is separate from version upload/traffic promotion; verify the consumer afterwards with `npx wrangler queues consumer worker list mikaki-logout-wakeups --config crates/worker/wrangler.production.jsonc` and confirm the DLQ name and exact bounded settings. Do not manually add a second consumer when `triggers deploy` is the release path.

For a rollback, keep the Queue consumer attached only when the active Worker version includes the Queue handler. Before returning traffic to a pre-Queue version, remove or reconcile the consumer using Wrangler and confirm the D1 scheduled recovery remains enabled. Unprocessed Queue messages are wake-ups only; D1 rows remain recoverable by the scheduled scan. Re-enable the source-configured consumer after deploying a Queue-aware version.

## Monitoring and recovery

Use `GET /accounts/{account_id}/queues/{queue_id}/metrics` for backlog count, oldest-message age, and backlog bytes for both the wake-up Queue and the DLQ (using each Queue's own ID). The sanitized `logout_delivery_backlog` log reports pending, due, active lease, retry, terminal failed, and expired row counts; `oldest_pending_at` is the oldest event creation time among pending or leased rows before deadline, while `oldest_due_at` is the earliest due `next_at`. `attempts_total` sums attempts across all outbox rows, and `earliest_deadline` reports the next deadline among unfinished rows. The release inventory verifies the OP producer binding and exact live OP consumer settings/DLQ via metadata-only reads. Never log message bodies or identifiers. Investigate DLQ messages without treating them as authoritative state. A manual replay re-enqueues only the event identifier; the normal D1 sender checks current state, deadline, next-at time, and lease before sending.

Test a slow/unavailable RP separately from the browser logout response. Test D1 commit failure, Queue send failure after commit, duplicate/concurrent Queue delivery, consumer failure before and after external RP success, retry/backoff, expiry, DLQ, scheduled recovery, and fan-out above the delivery page limit before calling the path production-qualified. External exactly-once delivery cannot be guaranteed if an RP accepted a request and the Worker failed before persisting that result; stable `jti` lets a conforming RP deduplicate that retry.

The current Wrangler config caps consumer invocations at two. D1 atomically enforces at most two active delivery leases globally and one per RP, and selects at most one due row per RP per page. Queue continuations are enqueued immediately only when another due row is currently claimable under those same capacity and lease conditions; the minute cron remains the recovery path when capacity is occupied, a wake-up is lost, or Queue delivery is unavailable. Validate these limits under representative production load before increasing concurrency.

Eligible RPs are ordered by their latest recorded `next_at` among rows with prior attempts (clients without history go first), then by their oldest due row; this is a bounded scheduling rule, while issue #106's measured throughput/capacity qualification remains pending.

Cloudflare documents Queues as at-least-once delivery, provides consumer batching/retry/DLQ controls, and charges per 64-KB message operation. As of the current pricing documentation, a normal message typically consumes one write, one read, and one delete; retries add reads. Re-check account plan and current pricing before any cost estimate or resource provisioning: [delivery guarantees](https://developers.cloudflare.com/queues/reference/delivery-guarantees/), [consumer configuration](https://developers.cloudflare.com/queues/configuration/configure-queues/), [retries and batching](https://developers.cloudflare.com/queues/configuration/batching-retries/), [pricing](https://developers.cloudflare.com/queues/platform/pricing/).
