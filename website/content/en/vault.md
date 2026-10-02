---
type: article
profile: sorane-okf/0.1
title: 'Using Vault: unlocking, saving and sharing'
description: 'How mikaki Vault handles names and notes, passkey PRF unlocking, plaintext export, sharing consent and passkey transfer limitations.'
lang: en
translation_key: vault
updated: 2026-10-02
---

## Sign-in and unlocking are separate

Vault is the interface for storing an encrypted name and note. Signing in to mikaki with a passkey does not automatically decrypt saved items. Opening an item uses the corresponding passkey's WebAuthn PRF output to decrypt it in your browser.

PRF is not required for ordinary login, but it is required for Vault decryption. Available operations can differ with the device, browser and passkey provider, even when ordinary sign-in works.

## Save a name or note

After Web sign-in, open the name or note panel, edit it and save. Names and notes have separate save, unlock and transfer operations. A note's title and body are information you enter yourself, not an issuer-verified credential.

Distinguish unsaved edits from saved content. If a conflict or network error appears, follow the screen's retry or reload instructions. Closing, reloading or locking the page can discard unsaved edits.

## Locking and signing out

The current Vault display has a 15-minute idle limit and a one-hour absolute limit. Open saved items again after a lock. Leaving the page or failing a session check also locks the view.

Locking Vault and signing out of mikaki are separate actions. Sign out after using a shared device. Closing a browser does not guarantee that the server-side login has ended.

## Sharing and export

Providing a name to an application or data to an AI recipient requires its own consent and configuration. Signing in, connecting an application or unlocking Vault does not release every saved item. Check the recipient, selected data, disclosure method and expiry shown on the screen. Features disabled by operational policy are unavailable.

A note's JSON export creates a **plaintext file**, not an encrypted backup. It exports saved content and excludes unsaved edits. Importing a file populates the editor; saving is a separate action.

Revoking a share stops future access. It cannot recall data already received by a recipient or erase a downloaded file.

## Before transferring to another passkey

Adding a passkey to the same account does not automatically make it able to decrypt existing data. The current transfer operation needs both supported passkeys on the transferring browser and moves selected saved items.

Transferring the name does not transfer the note. Keep the original passkey until you have reopened the transferred item with the selected passkey. The old passkey may still authenticate the account while being unable to open the new item using its previous key.

Recovery is not guaranteed if every usable unlock method is lost. Real-device recovery and transfer qualification remains incomplete.

## Implementation details

Read the [FAQ](faq.md) and [security and implementation status](security.md). Technical contracts are available in the [Vault design](https://github.com/masanork/mikaki/blob/main/docs/personal-vault.md), [passkey transfer](https://github.com/masanork/mikaki/blob/main/docs/vault-passkey-transfer.md) and [session and lock contract](https://github.com/masanork/mikaki/blob/main/docs/session-lifecycle.md).
