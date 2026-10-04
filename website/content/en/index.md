---
type: index
profile: sorane-okf/0.1
title: 'mikaki — Open source passkey authentication and OpenID Connect'
description: 'An experimental Rust open source service for passkeys and OpenID Connect. Explore invitation-based setup, encrypted Vault, application integration and implementation status.'
lang: en
translation_key: index
updated: 2026-10-03
---

## Sign in to applications with a passkey

mikaki is an experimental open source identity service built primarily in Rust. It combines passkey authentication with OpenID Connect sign-in for applications.

Use the [Web sign-in page](https://auth.mikaki.org/signin?lang=en) directly, or start application sign-in from the application you want to use. Check the destination on the login screen, then authenticate with your passkey. Account registration currently requires an invitation code.

mikaki is an experimental project. Review implementation status and operational limitations before adopting it.

## For new users

Start with an invitation and your usual device. Check passkey sign-in and unlocking Vault as separate operations.

- [Get started with an invitation](getting-started.md)
- [Ask about an invitation](contact.md)
- [Check passkeys and device support](passkeys.md)
- [Explore saving and sharing with Vault](vault.md)
- [Read frequently asked questions](faq.md)

## For developers and adopters

Add passkey sign-in to your Web application. Follow the OpenID Connect guide for registration, Authorization Code with PKCE and session checks.

- [Read the application integration guide](integration.md)
- [Discuss application registration](contact.md)
- [Try the public IdP login demo](integration-demo.md)
- [Check specifications and standards](specifications.md)
- [Look up API requests and responses](api.md)
- [Run the local integration example](integration-example.md)
- [Inspect the implementation on GitHub](https://github.com/masanork/mikaki)

## For security evaluation

Check what has been tested and what still needs verification before adoption. Review encryption and recovery limits, OpenID, FAPI and FIDO test evidence, and formal certification status.

- [Review security and implementation status](security.md)
- [Browse conformance results](conformance.md)
- [Check operations and service conditions](operations.md)
- [Read Vault sharing and recovery limits](vault.md)
