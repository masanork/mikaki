# ADR 0003: Session lifetime, revocation, and logout scope

**Status:** Accepted, 2026-09-22

## Decision

Adopt the [session and logout contract](../session-lifecycle.md) for the initial integration:

- An SSO session lasts at most 30 days after user authentication. An application session has a seven-day idle limit and cannot outlive its parent SSO session.
- Ordinary logout revokes this browser's SSO session and derived application sessions. “Log out everywhere” and disconnecting an application are separate management actions.
- Include RP-Initiated Logout and Back-Channel Logout in the initial integration. Managed tossa and tsudoi additionally use a server-to-server status check whose result is usable for at most five minutes.
- Once a status-check lease expires without confirmation, stop protected operations. Do not extend the deadline during an outage; retain user input so an operation can be retried.
- Credential management requires user verification bound to the operation. Its authorization lasts at most five minutes and can be used once.
- Vault unlock has a 15-minute idle limit and a one-hour absolute limit, separate from SSO lifetime.
- An authorization code is single-use and lasts 60 seconds; an ID Token lasts five minutes.

## Rationale and scope

The contract reduces repeated authentication while bounding the effect of a missed logout notification. Status checks need no new user action, but a connection outage beyond the lease temporarily prevents protected application operations. The five-minute bound concerns authorization of new protected operations; it cannot recall an in-progress operation or plaintext already disclosed. It does not automatically apply to arbitrary OIDC clients.

[ADR 0004](0004-runtime-policy-configuration.md) makes these numbers configurable defaults. Existing-state behavior and the overlap of old and new leases follow that ADR and the runtime-configuration contract. Implementation still needs durable status and notification state, response-race handling, cookie properties, retry, and retention checks. Acceptance of this ADR did not complete those tasks.
