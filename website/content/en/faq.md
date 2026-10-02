---
type: article
profile: sorane-okf/0.1
title: 'mikaki FAQ: invitations, passkeys and Vault'
description: 'Answers about invitations, Web and native apps, passkey compatibility, Vault recovery and sharing, and OpenID, FAPI and FIDO certification.'
lang: en
translation_key: faq
updated: 2026-10-02
---

## Can anyone register?

New accounts currently require an invitation code. Invited users can follow [Getting started](getting-started.md). Unrestricted public registration is not available.

## Do I need to install an app?

You can start Web sign-in and enter Vault from a browser. General distribution of the native app is still being prepared. Read [Getting started](getting-started.md) for the distinction.

## Can I use a password instead?

mikaki uses passkeys for login. It does not provide password fallback or a mechanism that recovers encrypted data using only an email address.

## Why can I sign in but not unlock Vault?

Authentication and decryption are separate. Unlocking needs the passkey corresponding to the saved data and PRF support. Merely adding another passkey to the account does not make it able to decrypt the item. Check the device and passkey used to save it, and follow the screen's error instructions. Do not try to recover it by overwriting it with new data.

## Does every application or AI get all my saved data?

Sign-in and Vault unlocking do not release all saved content. Selecting data and a recipient requires separate consent, and operational limits apply to individual features. A recipient of a plaintext export can read its contents. See [Using Vault](vault.md).

## Can I recover data after losing my passkeys?

Recovery is not guaranteed if all usable passkeys and unlock methods are lost. Per-item transfer to a supported passkey exists, but real-device recovery qualification is incomplete. Do not remove the original passkey before confirming that the target passkey opens the saved item.

## Can I connect any application?

OpenID Connect integration requires advance client registration by an operator and implementation and verification by the application. Use the [integration guide](integration.md). Signing in to mikaki does not sign you in to arbitrary services.

## Is mikaki OpenID, FAPI or FIDO certified?

No. Conformance evidence is published, but test results and formal certification are different. Read [security and implementation status](security.md) for the test scope and limitations.

## Where can I find known issues?

The [source code and documentation](https://github.com/masanork/mikaki) are public, with known work recorded in [Issues](https://github.com/masanork/mikaki/issues). Do not include invitation codes, login codes, tokens or personal data in public reports.
