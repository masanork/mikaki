# ADR 0002: Use OIDC from the first production RP integration

**Status:** Accepted, 2026-09-22

## Decision

Mikaki acts as the OpenID Provider and tossa and tsudoi act as relying parties. Their first production integration uses OIDC Authorization Code with PKCE. Do not first introduce a proprietary login-result transport.

The user-facing entry point remains passkey login. Integrate first connection approval into the authentication screen and reuse a valid Mikaki session for previously approved applications. Vault creation, unlock, or access permission is not a required step in normal login.

## Rationale and consequences

A standard protocol carries the result of the common-account login. Introducing OIDC does not justify extra IdP setup, authentication, or consent on every visit. Explicit reauthentication requests and new connections or permissions still require the appropriate checks.

P0 core authentication can be verified first, but production RP integration requires an implemented and tested OIDC path. Keep OIDC out of the WebAuthn verifier. The [login UX contract](../oidc-login.md) describes the detailed target. G1 determines issuer, client configuration, signatures and tokens, sessions, logout, dependencies, and implementation boundaries; it does not revisit OIDC adoption. Initially only operator-registered applications are supported. This ADR does not commit to every general-purpose IdP feature or formal certification.
