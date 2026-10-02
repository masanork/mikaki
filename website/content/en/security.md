---
type: article
profile: sorane-okf/0.1
title: 'mikaki security and implementation status'
description: 'Passkey authentication, encrypted Vault data, OpenID conformance evidence and certification status.'
lang: en
translation_key: security
updated: 2026-10-02
---

## Passkey authentication

mikaki authenticates with WebAuthn passkeys. Its login screen identifies the destination application. Use [Web sign-in](https://auth.mikaki.org/signin?lang=en) directly, or start application login from the application you want to use. Ordinary authentication and Vault unlocking are separate operations; decryption requires the corresponding supported passkey and PRF.

## Vault and sharing

The Owner Vault is being developed to store encrypted names and notes. Attribute release to applications and AI exports have separate consent steps. Device compatibility, recovery and operational qualification still have open work.

The server stores ciphertext and operational metadata such as item identifiers and update times. Consented sharing lets a selected recipient decrypt the disclosed data. Downloaded plaintext files and data already delivered to a recipient cannot be recalled.

Read [Using Vault](vault.md) for practical limitations. Recovery after losing every usable unlock method and compatibility with every real device are not guaranteed.

See the [Vault documentation](https://github.com/masanork/mikaki/blob/main/docs/personal-vault.md) and [session limitations](https://github.com/masanork/mikaki/blob/main/docs/session-lifecycle.md).

## Conformance and certification

In the September 29, 2026 local test run, OpenID Connect Config OP finished PASSED. Basic OP finished with 22 PASSED, 4 REVIEW, 8 SKIPPED, 1 WARNING and 0 FAILED. These results apply to an isolated conformance deployment.

**mikaki has not obtained formal OpenID, FAPI or FIDO certification.** Test results do not establish certification or production qualification.

See the [test scope and evidence](https://github.com/masanork/mikaki/blob/main/docs/oidf-conformance-2026-09-29.md) and [source code](https://github.com/masanork/mikaki).
