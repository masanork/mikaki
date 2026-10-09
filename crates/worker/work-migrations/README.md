# Managed-work additive schema

This opt-in migration ledger follows the current OP baseline in `../migrations`
(`0001_owner_vault_initial.sql` and `0002_owner_key_wrap_operations.sql`). It is
separate from the production migration directory and is applied explicitly by
the local work qualification fixtures. No Wrangler binding, deployment or
production enrollment is supplied by this integration.

Numbering continues at 0003 after the production baseline. The eight initial migrations preserve the earlier managed-work schema while
using the fresh Owner Vault baseline. They create no owner sources, disclosures,
grants, issuer identities, credentials or external resources automatically.

Migrations 0011 and 0012 add checkpoint and covered OP transaction frames without
automatic enrollment. Applying the schema alone enables no managed-work effects.

Migration 0013 adds retained, explicit copy consent without backfilling existing
preparations. New product copying requires this schema and current consent. The
owner confirmation endpoint separately needs `WORK_COPY_CONSENT_ENABLED=true`
and a fixed `WORK_ARTIFACTS_ACCOUNT`. Older qualification fixtures explicitly
stop at 0012; the product consent lane installs 0013 with an enrolled independent
checkpoint. This historical fixture exemption is absent from product builds.

Owner selection composition reuses the same schema and adds no migration. Its
metadata-only `POST /work/preparations` separately requires
`WORK_PREPARATION_COMPOSE_ENABLED=true`, fixed namespace/recipient/workload/account
configuration and the existing private source reader. It does not approve or
dispatch a copy; see [the composition decision](../../../docs/work-preparation-compose.md).

Run `npm run test:work-delegation` from the repository root to build the actual
Rust/Wasm fixture and exercise the additive schema with workerd/D1/R2. The
fixture uses synthetic verifier facts; its successful cases do not qualify a
production issuer, real-device authentication or remote Artifacts effects.
