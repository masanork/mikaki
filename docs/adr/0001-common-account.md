# ADR 0001: Use a common Mikaki account for normal login

**Status:** Accepted, 2026-09-22

## Context

An earlier plan would have verified authentication separately for each application in P0 and introduced the common account with the vault in P1. Normal login and the later vault should instead share an account model from the outset, without making migration from app-specific production credentials a prerequisite.

## Decision

- Each Mikaki instance has common accounts used for normal login to tossa and tsudoi. This does not mean all instances must have one operator.
- Credentials belong to a common `AccountId`. Each instance fixes one RP ID and authentication/unlock origin.
- An application's `SubjectId` is distinct from `AccountId`. Linking them requires the person's authentication and permission to connect the application.
- Mikaki controls common-account enrollment and credential management. A general connected application cannot manage credentials.
- Each application controls its sessions, participation rules, organizations, and roles.
- Create a vault when it is needed. Keep normal login separate from PRF unlock, and application-login consent separate from vault read/write permission.

## Consequences

`AccountId` is the authentication subject from P0. Production common login is integrated after the G0/G1 gates; the connection protocol is not deferred until P1. OIDC was undecided at the time of this ADR and was later selected by [ADR 0002](0002-oidc-from-first-release.md). The production domain, application registration, subject mapping, Mikaki sessions, logout/disconnection, management entry point, and OIDC contract still require implementation and verification. This decision alone is not a deployment claim.

## Acceptance criteria

- The same common account can log into both applications while each evaluates its own participation rules.
- Normal login works without a vault, an unlocked vault, or PRF support.
- Application login alone grants no vault read/write access.
- A login result for application A is rejected by application B.
- A connected application cannot add or remove common credentials.
- Disconnecting an application does not delete the common account, another application's state, or the vault.
