# Production Owner Vault reset, 2026-10-05

The reset and public cutover completed using source
`140baec376116cffa6118dff6cde73af4064309d` from
[PR #129](https://github.com/masanork/mikaki/pull/129).
[Main CI run 37256255769, attempt 4](https://github.com/masanork/mikaki/actions/runs/37256255769)
passed verification, the attested build, all production promotions and the
version-matched public smoke. This record supersedes earlier deployment and
migration observations for these resources; earlier device results remain
historical evidence.

## Running services and storage

Each listed application version received 100% of traffic at cutover.

| Service | Public origin             | Version ID                             | Storage authority                                                  |
| ------- | ------------------------- | -------------------------------------- | ------------------------------------------------------------------ |
| OP      | `https://auth.mikaki.org` | `c27f2ed5-382e-4fb5-a2f7-06bc69fdd3db` | Owner D1 and Vault R2; default HTTP plus named service entrypoints |
| Claims  | OP service binding only   | `bf606b14-e0a0-4ef0-a76f-fd43956272d2` | OP `ClaimStore`; no D1/R2 binding; dedicated Secrets Store key     |
| Docs RP | `https://docs.mikaki.org` | `f8001aba-db40-4940-b245-2e2601bf7aa5` | Dedicated Docs D1 and dedicated RP signing key                     |

The website at `https://mikaki.org` was also deployed by this main run.
`https://app.mikaki.org` retains the native application association. No Agent
Worker was deployed and no `AGENT_ACCESS` binding or Identity activation flag
was added.

| Database            | ID                                     | Exact migration ledger              | Schema objects |
| ------------------- | -------------------------------------- | ----------------------------------- | -------------- |
| `mikaki-auth-owner` | `d0258938-0d27-4110-8aa9-c82e20f3885b` | `0001_owner_vault_initial.sql` only | 236            |
| `mikaki-docs-rp`    | `8527823b-5417-425d-8028-0532464e39e7` | `0001_initial.sql` only             | 8              |

The OP baseline includes the retained Identity schema. Do not apply historical
`0036`–`0044` migrations to this fresh database. Identity keys, issuer trust,
attestation/verifier settings and profile activation remain work under
[#116](https://github.com/masanork/mikaki/issues/116).

## Cutover evidence

Before deleting old state, the OP and Claims were replaced by storage-free
maintenance versions, scheduled writers were stopped, and active service
bindings and all traffic-bearing versions were inspected. The public
maintenance routes remained in place while the new databases were initialized
and the attested application versions were promoted.

At the final pre-opening check (2026-10-05 07:14 UTC), all 71 non-public OP
tables and all three Docs session/transaction/tombstone tables had zero rows.
`mikaki-auth-vault` contained zero objects. The exact ledgers and all schema
objects matched source; active bindings, service entrypoints, version tags,
domains and cron schedules matched reviewed configuration. Private OP/Docs
health and version checks and authenticated OP readiness passed while public
health still returned maintenance 503.

Only public registration/policy/signing metadata was seeded. The final three
OP clients were the internal enrollment client, the retained native client and
the new dedicated Docs client. No accounts, passkey registrations, grants,
recipient authorization, tokens, sessions or encrypted records were restored.
Public smoke subsequently creates fresh test transactions; the zero-row counts
above describe the pre-opening checkpoint, not a perpetual empty database.

The Docs Worker was initially created with storage-free 503 code because
`versions upload` requires an existing Worker. CI then verified and activated
the prepared, source-attested Docs bundle. The first public smoke encountered
maintenance 503; after all private gates passed and the recorded maintenance
routes were removed, only that smoke job was rerun. Its final success covers
OP health, Discovery/JWKS, readiness, login asset digests, Docs source identity
and bilingual entry, website findability, bilingual enrollment, Web signin,
protected Vault entry and Android association.

## Retired resources and retained keys

The former `mikaki-auth` D1 (`f9299d62-2dbf-4bae-ae49-8b75674572d4`), the
old `mikaki-op` D1 (`f84e650a-b4d9-42a1-9ccd-6d1b27ca74a1`) and Demo D1
(`ce11d383-758b-4574-8bcc-7febc505a408`) were deleted. The old `mikaki-op`,
`mikaki-userinfo-claim-worker` and `mikaki-demo-rp` Workers, the `mikaki-vault`
bucket and the old `mikaki.tossa.app`, `mikaki-native.tossa.app` and
`demo.mikaki.org` endpoints were retired. The Demo client was disabled before
retirement and omitted from the new seed.

The maintenance front, authenticated diagnostic/storage Worker and rehearsal
D1 were removed after public smoke succeeded. At cleanup (07:17 UTC), the only
project Workers were `mikaki-auth`, `mikaki-auth-claims`, `mikaki-docs-rp`,
`mikaki-site` and `mikaki-app-links`; the only project databases were the two
fresh databases above.

OP signing/readiness secrets and the existing UserInfo ML-KEM Secrets Store
material were retained. Docs uses a separately provisioned key; it does not
reuse Demo credentials. Secret values and bootstrap invitations are excluded
from this public record. A fresh administrator invitation was issued separately
with the existing 15-minute policy. Account and Vault access require fresh
registration; registration cannot recover deleted records.

## Follow-up boundaries

Source and deployed resource separation are established. Recipient/RP sharing
policy and hosted Agent activation remain disabled. Real-passkey/PRF reopening,
Docs OIDC callback/logout completion, intended-device recovery, physical-card
flows, load/alert qualification and formal certification are separate checks.
The passing public smoke does not complete those checks. Use the
[roadmap](roadmap.md) for the next work and the [reset runbook](owner-vault-reset.md)
for a future cutover; another reset would require its own resource inventory.

## Post-cutover scheduled telemetry

A subsequent read-only production tail observed ten `auth_gc_failure` events
and one successful `vault_gc` event (collected 0, pending 0, duration 1,235 ms),
with no sampled `vault_gc_failure`. This CLI output retained no invocation
timestamp or cron metadata. The raw tail was discarded after sanitized review.

The auth collector's six-way compound backlog SELECT was independently rejected
by a read-only production D1 query (`too many terms in compound SELECT`); its
two-way control passed. This is a post-cutover runtime telemetry defect, not a
failed public smoke or a reason to repeat the data reset. The correction and
subsequent production qualification are recorded below.

## Telemetry correction and production qualification

[PR #130](https://github.com/masanork/mikaki/pull/130) corrected the auth backlog
query by running six independent prepared statements in one D1 batch. It also
requires the complete binding inventory, including service entrypoints, to
match the reviewed configuration before promotion. Retention, cleanup, schema
and participant data were not changed.

Source `210567e88ec0e2dcfae0a56e1937f9db8b8f0d3e` passed
[main CI run 37321367592](https://github.com/masanork/mikaki/actions/runs/37321367592),
including attested OP/Claims and Docs promotion and the source/version-matched
public smoke. Read-only Cloudflare metadata inspection at 20:52 UTC confirmed
100% active versions with tag `210567e88ec0` and exact approved bindings:

| Worker | Active version                         |
| ------ | -------------------------------------- |
| OP     | `baf674d8-13a1-46cf-aeac-5aa62adcdc4c` |
| Claims | `4b5008a5-ec54-46cd-8539-c99d5a2b45db` |
| Docs   | `8018b250-fe68-4102-a131-63b95857fe72` |

A private production tail beginning at 20:53:06.927 UTC on 2026-10-05
captured two minute-cron events at 20:54:20.014 and 20:55:20.014 UTC. Both had
exact event name `auth_gc`, reclaimed=0, and login/codes/tokens/sso/logout/dpop
backlogs each expired=0/oldest=null. No `auth_gc_failure` or `vault_gc_failure`
was captured in this window. The raw logs were discarded after independent
parsing and sanitized receipt validation. #99–#101 and #103 were closed with
acceptance evidence. Empty-baseline telemetry is not a load measurement; #106
retains mixed-load and alert qualification.
