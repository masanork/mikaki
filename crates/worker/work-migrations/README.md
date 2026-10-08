# Opt-in managed-work schema

These additive migrations extend the current Owner Vault baseline. They are kept outside `../migrations/`, so existing development/production configuration, compiled schema readiness and release inventories continue to select the supported Owner Vault ledger.

The local qualification fixture explicitly applies the baseline followed by these files. No deployed Worker opts into this profile. Before activation, qualify independent checkpoint/OP framing, exact profile readiness, schema inventories, service/key provisioning and the product/effect entrypoints under the [main integration plan](../../../docs/work-delegation-implementation.md).

| Current profile file | Retained pre-main contract |
| --- | --- |
| `0003_work_delegation.sql` | `0047` |
| `0004_work_disclosure_budget.sql` | `0048` |
| `0005_work_sources.sql` | `0049` |
| `0006_work_registered_disclosures.sql` | `0050` |
| `0007_work_preparation_intents.sql` | `0051` |
| `0008_work_prepared_authority.sql` | `0052` |
| `0009_work_credential_custody.sql` | `0053` |
| `0010_work_candidate_payload.sql` | `0054` |
| `0011_work_authority_checkpoint.sql` | `0055` |

Numbering continues after the baseline's `0001`/`0002`; the work files are not an alternative standalone baseline. No retired OP/Vault migration, credential backfill, source copy or external allocation is included. The checkpoint table starts unenrolled; this is not a trusted outside-OP floor. The historical OP-framing migration `0056` is pending adaptation to current OP mutations and is not part of this increment.
