# ADR 0004: Separate operational values into configuration

**Status:** Accepted, 2026-09-22

Collect session-related durations and counts in typed configuration. Retain the accepted design values as defaults and allow deployment-specific TOML changes without editing code or duplicating constants between applications.

Each deployment has one active input source; secrets are managed separately. Reject invalid values, unknown keys, and inconsistent combinations before activation. Configuration cannot disable safety properties such as single use, user verification, or denial after revocation.

Apply ordinary changes to newly issued state. Do not silently lengthen or shorten existing sessions. New status-check responses use the new configuration; while old leases remain valid, the larger of the old and new limits bounds revocation propagation. Retain policy versions and change history, and never let a rollback restore revoked state.

The values in [ADR 0003](0003-session-lifecycle.md) are initial configuration defaults, including a five-minute default status-check lease. The [runtime contract](../runtime-configuration.md) describes changes to issued state. This decision does not resolve unrelated proposals about IDs or signature algorithms.

At the time of this ADR, the deliverables were the configuration example and contract, with loading and activation left for later implementation. [ADR 0011](0011-d1-runtime-policy.md) subsequently chose D1 for the active version. The typed validation, versioning, and existing-state rules remain in force.
