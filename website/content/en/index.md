---
type: index
profile: sorane-okf/0.1
title: 'mikaki — Open source passkey authentication and OpenID Connect'
description: 'An experimental Rust open source service for passkeys and OpenID Connect. Explore invitation-based setup, encrypted Vault, application integration and implementation status.'
lang: en
translation_key: index
updated: 2026-10-02
---

## Sign in to applications with a passkey

mikaki is an experimental open source identity service built primarily in Rust. It combines passkey authentication with OpenID Connect sign-in for applications.

Use the [Web sign-in page](https://auth.mikaki.org/signin?lang=en) directly, or start application sign-in from the application you want to use. Check the destination on the login screen, then authenticate with your passkey. Account registration currently requires an invitation code.

## For new users

- [Get started with an invitation](getting-started.md): registration, Web sign-in and connected applications
- [Using Vault](vault.md): saving and unlocking, sharing and passkey transfer
- [Frequently asked questions](faq.md): invitations, device compatibility, recovery and certification

## For developers and adopters

- [Connect your application](integration.md): OpenID Connect, Authorization Code and PKCE
- [Security and implementation status](security.md): passkeys, encryption, conformance tests and certification status
- [Source code on GitHub](https://github.com/masanork/mikaki)

Review implementation status and operational limitations before adopting mikaki.
