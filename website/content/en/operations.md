---
type: article
profile: sorane-okf/0.1
title: 'mikaki operations and service information'
description: 'Public site and IdP roles, invitations and client registration, experimental availability, licensing, outage behavior, support and vulnerability reporting.'
lang: en
translation_key: operations
updated: 2026-10-03
---

This page describes current service conditions for evaluating mikaki. **It is an experimental development project with no supported formal release.** This information does not establish an SLA or paid support contract.

## Public sites and connection targets

| Host | Role |
| --- | --- |
| [mikaki.org](https://mikaki.org) | Product explanations, guides, specifications and test evidence |
| [auth.mikaki.org](https://auth.mikaki.org/.well-known/openid-configuration) | Public IdP authentication, OIDC and Web operations |
| [app.mikaki.org](https://app.mikaki.org) | Native application information and callback-related navigation |

Local development and conformance environments have separate issuers, keys and databases. Their success does not establish general production availability or a qualified application distribution. Japanese and English pages describe the same scope; also check current Discovery and implementation evidence.

## Registration and use

User registration requires an invitation. Administrators register application clients. Public dynamic client registration and self-service production SaaS onboarding are not provided. User passkey enrollment and developer client registration are different procedures.

The [security policy](https://github.com/masanork/mikaki/blob/main/SECURITY.md) states that there are no supported releases and that the local implementation is not intended to protect real accounts or data. Evaluate with test accounts and synthetic data. Avoid entrusting irreplaceable information to this experimental setup, including the public service.

## Availability and failure behavior

There is no availability SLA, performance/capacity guarantee, support response deadline or security bounty. HTTP reachability and CI success do not guarantee every login, notification or Vault recovery.

Connected applications must not create new sessions during an OP outage or extend existing sessions past the current confirmed lease. Distinguish UserInfo 503 from an invalid token or withdrawn consent. Qualify outages, revocation, replay and Back-Channel receiver failures per application.

Session policies are configurable. Use response values from the [API reference](api.md), rather than treating initial default durations as a fixed production guarantee.

## Data and recovery

Passkey authentication, RP sessions and Vault decryption keys are separate. The server stores Vault ciphertext and operational metadata such as item types and update times. Released data and downloaded plaintext cannot be recalled.

Comprehensive service guarantees for loss of every unlock method, universal device compatibility, retention periods or deletion deadlines are not established. Before handling real data, an operator must define retention, deletion, backups, recovery procedures and responsibilities for the target configuration. Read [Vault limitations](vault.md) and [release/recovery procedures](https://github.com/masanork/mikaki/blob/main/docs/release-and-recovery.md).

## Versions and changes

Inspect implementation, history and development progress in the [repository](https://github.com/masanork/mikaki) and [CI](https://github.com/masanork/mikaki/actions). The main branch need not match the public IdP's active version/configuration. Check implementation, local testing, deployment and operational activation separately.

Dates, tool versions and targets in the [conformance index](conformance.md) do not certify every current deployment. Requalify the affected connection from your application after changes.

## License and self-hosting

The software is open source under your choice of [MIT](https://github.com/masanork/mikaki/blob/main/LICENSE-MIT) or [Apache-2.0](https://github.com/masanork/mikaki/blob/main/LICENSE-APACHE). Software licensing differs from hosted-service availability and support commitments.

The current Worker configuration uses Cloudflare Workers, D1 and R2 for Vault storage. Self-hosting requires a separate issuer, keys, databases, client registrations, monitoring and recovery arrangements. See [development setup](https://github.com/masanork/mikaki/blob/main/docs/getting-started.md) and [operational design](https://github.com/masanork/mikaki/blob/main/docs/oidc-operations.md). Starting a local example does not complete production preparation.

## Support and vulnerability reports

Use [GitHub Issues](https://github.com/masanork/mikaki/issues) for ordinary bugs or proposals, including the target commit, environment and synthetic reproduction. Do not post accounts, private keys, invitations, OAuth callback URLs, codes/tokens or Vault contents.

Use GitHub private vulnerability reporting when enabled. If unavailable, open an issue **only requesting a private reporting channel**, without vulnerability details or exploit steps. Follow [SECURITY.md](https://github.com/masanork/mikaki/blob/main/SECURITY.md).

## Read next

- [Specifications and standards](specifications.md): Check connection capabilities and client profiles.
- [Security and status](security.md): Evaluate adoption against data and test limitations.
