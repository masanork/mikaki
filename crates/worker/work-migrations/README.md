# Managed-work additive schema

This opt-in migration ledger follows the complete current OP baseline in
`../migrations`, including Owner Vault and the waiting-list/single-email invitation
migrations. It is
separate from the production migration directory and is applied explicitly by
the local work qualification fixtures. No Wrangler binding, deployment or
production enrollment is supplied by this integration.

The separate Work ledger retains its original numbering from 0003; its numeric
prefixes are not part of the production ledger. Qualification applies the complete
production ledger first and then this explicit Work ledger. Never combine the two
directories into a production Wrangler migration chain. The eight initial migrations preserve the earlier managed-work schema while
using the fresh Owner Vault baseline. They create no owner sources, disclosures,
grants, issuer identities, credentials or external resources automatically.

Migrations 0011 and 0012 add checkpoint and covered OP transaction frames without
automatic enrollment. Applying the schema alone enables no managed-work effects.

Run `npm run test:work-delegation` from the repository root to build the actual
Rust/Wasm fixture and exercise the additive schema with workerd/D1/R2. The
fixture uses synthetic verifier facts; its successful cases do not qualify a
production issuer, real-device authentication or remote Artifacts effects.
