# Managed-work additive schema

This opt-in migration ledger follows the current OP baseline in `../migrations`
(`0001_owner_vault_initial.sql` and `0002_owner_key_wrap_operations.sql`). It is
separate from the production migration directory and is applied explicitly by
the local work qualification fixtures. No Wrangler binding, deployment or
production enrollment is supplied by this integration.

The eight initial migrations preserve the earlier managed-work schema while
using the fresh Owner Vault baseline. They create no owner sources, disclosures,
grants, issuer identities, credentials or external resources automatically.

Run `npm run test:work-delegation` from the repository root to build the actual
Rust/Wasm fixture and exercise the additive schema with workerd/D1/R2. The
fixture uses synthetic verifier facts; its successful cases do not qualify a
production issuer, real-device authentication or remote Artifacts effects.
