# OIDC data and atomic operations

This is the logical persistence contract for [login transactions](oidc-login-flow.md), [sessions](session-lifecycle.md), and [access tokens](oidc-access-token-and-userinfo.md). Mikaki authentication and OIDC state use one D1 database. Apps have independent databases; no cross database transaction is assumed. The [SQL probes](../design/sql/oidc-critical-schema.sql) are a model, not a production migration.

## Commit boundary

Perform cryptographic verification and signing outside the database, then recheck expiry, revisions, revocation, and key state in a final conditional write. Return HTTP success or a cookie only after commit. Expose business operations such as `ResolveSubject`, `CompleteAuthentication`, `ExchangeCode`, and `RevokeSession`, distinguishing success, failed preconditions, and unknown commit outcomes.

Records include AccountSecurity/login epoch, Credential state, client/key registrations, PairwiseSubject, AppConnection/grant version, SSO session, authorization transaction/code, accepted client assertion JTI, issued ID/access token records, client session, revocation event, logout delivery, signing key, and operation/audit records. Use unique constraints for one time values and stable mappings. Store hashes of bearer codes, cookies, and access tokens. Retain revocation and replay records through all possible validity and retry windows.

A client assertion is reserved once independently of code exchange. Its authenticated receipt contains client/key revision, JTI, and retention deadline. In `ExchangeCode`, one D1 batch conditionally consumes the code, inserts the issue record, and uses a database guard to require a valid client session and current revisions. A zero row conditional UPDATE must fail the whole batch through a checked constraint; merely inspecting the batch result after commit is too late. Exactly one concurrent exchange succeeds. Do not hold an interactive transaction open across external signing.

Read revocation sensitive state with a fresh `withSession("first-primary")` session whose first SQL statement performs the complete validity join. A prior read can consume that first primary guarantee. Do not interpret an old bookmark as proof that another request's latest revocation was observed. Key stop races are resolved at final commit; after a response has left the server, use key denial and session revocation.

## Revocation and delivery

Commit the revocation condition and durable `RevocationEvent` together. Expand affected old SIDs in resumable batches into unique `LogoutDelivery` rows. New epoch/grant sessions must not enter the old event. Commit the expansion cursor with deliveries and retain parent records until expansion completes. A worker conditionally acquires a timed lease, sends outside the DB, and records completion only for its lease generation. Delivery can repeat after a lost acknowledgement; the RP must make duplicate logout idempotent. A retry signs a new token for the same SID. Exhausting delivery attempts never reverses revocation.

Each RP atomically completes its local callback: validate token and `/session/check`, recheck browser transaction, lease, membership, and revoked SID, then create/get ExternalIdentity, create AppSession, and finish the transaction. A logout stores RevokedSid even before AppSession creation, and prevents a late callback from reviving it. A lost code exchange response starts a new login rather than replaying a possibly consumed code.

Use operation IDs to recover unknown outcomes of administrative commands; reject the same ID with different contents. Keep retention deadlines monotonic when configuration changes. A historical DB restore needs an externally managed recovery generation, app session invalidation, and reconciliation of lost revocations; restoring D1 alone is insufficient.

Test each SQL failure position, zero row updates, concurrent exchange, logout/auth races, callback/notification order, outbox interruption, lease transfer, primary versus replica reads, and lost DB responses in isolated D1 as well as local SQLite. See [D1 Database API](https://developers.cloudflare.com/d1/worker-api/d1-database/) and [read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/).
