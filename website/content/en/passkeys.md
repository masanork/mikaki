---
type: article
profile: sorane-okf/0.1
title: 'Passkeys and unlocking Vault'
description: 'Understand mikaki passkey authentication, WebAuthn PRF, why sign-in can work while Vault stays locked, and what to check before changing devices.'
lang: en
translation_key: passkeys
updated: 2026-10-03
---

A passkey signs you in to mikaki. Opening saved Vault items also requires PRF support from the corresponding passkey. This page explains the difference and the checks to make when an operation fails.

## Authenticate with a passkey

A passkey authenticates through your device or passkey provider instead of a typed password. Depending on the device, you may see a fingerprint, face or PIN prompt. WebAuthn biometric verification happens locally; it does not send your fingerprint or face data to the authenticating website.

Use a registered passkey at [Web sign-in on auth.mikaki.org](https://auth.mikaki.org/signin?lang=en). New registration currently requires an invitation code. See [Getting started](getting-started.md).

## PRF adds a capability for encrypted data

WebAuthn PRF is an extension that lets the browser obtain an output associated with a passkey. mikaki Vault derives a key from this output to decrypt saved data in your browser. This is separate from verifying a signature for sign-in.

| Operation | Required capability |
| --- | --- |
| Sign in to an account | Authenticate with a passkey registered to that account |
| Open a saved name or note | Obtain the required PRF output from the passkey associated with that item |
| Transfer an item to another passkey | Use PRF with both source and target passkeys on the same account |

Successful passkey authentication does not establish PRF support. Adding another passkey to the same account also does not automatically let it open existing items.

## When Vault will not open

1. Distinguish a sign-in failure from an unlock failure after sign-in. If you are not signed in, check the registered passkey and authentication domain.
2. Check which passkey the item needs. Use the passkey associated with the saved item, or the selected target of a completed transfer. Signing in with another passkey is insufficient.
3. Check on the original device, browser and passkey provider where that passkey is usable. If you cancelled authentication, follow the screen's instructions to try again. An unsupported-PRF message means unlocking has not been established for that combination.
4. Do not overwrite an item that failed to unlock with new empty data. Network errors and save conflicts are separate from passkey compatibility; check the actual error shown.

Distinguish the device, OS, browser, passkey provider and authentication transport. There is no product-name compatibility list guaranteeing Vault support. Virtual passkeys and mocked PRF in automated tests do not qualify real-device sync, biometric prompts, USB or wireless transport.

## Before changing devices

Passkey synchronization, registering an additional mikaki passkey and transferring a Vault item are different operations. Signing in on a synchronized device does not establish that it can decrypt saved data. Reopen the item on the destination before giving up the original device or passkey.

Current Vault transfer works item by item. Transferring the name does not automatically transfer the note. Recovery after losing every unlock method is not guaranteed, and email alone cannot reissue the decryption key. Read [Using Vault](vault.md) for transfer and export limitations.

## Specifications and verification scope

W3C describes the general mechanism in the [WebAuthn PRF specification](https://www.w3.org/TR/webauthn-3/#prf-extension) and [biometric verification section](https://www.w3.org/TR/webauthn-3/#sctn-biometric-privacy). For mikaki's implementation and real-device evidence, see [implementation status](security.md), the [device compatibility record](https://github.com/masanork/mikaki/blob/main/docs/webauthn-device-compatibility.md) and [passkey transfer design](https://github.com/masanork/mikaki/blob/main/docs/vault-passkey-transfer.md).
