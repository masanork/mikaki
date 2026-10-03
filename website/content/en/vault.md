---
type: article
profile: sorane-okf/0.1
title: 'Using Vault: unlocking, saving and sharing'
description: 'How mikaki Vault handles names and notes, passkey PRF unlocking, plaintext export, sharing consent and passkey transfer limitations.'
lang: en
translation_key: vault
updated: 2026-10-03
---

## Sign-in and unlocking are separate

Vault is the interface for storing an encrypted name and note. Signing in to mikaki with a passkey does not automatically decrypt saved items. Opening an item uses the corresponding passkey's WebAuthn PRF output to decrypt it in your browser.

PRF is not required for ordinary login, but it is required for Vault decryption. Available operations can differ with the device, browser and passkey provider, even when ordinary sign-in works.

See [Passkeys and unlocking Vault](passkeys.md) for the difference between sign-in and decryption, and checks before changing devices.

## Find the controls on the screen

The name described here is the screen's “Display name”, and the note is its “Owner note”. Use these sections in the Web interface.

| Screen section | Operations |
| --- | --- |
| Profile | Open, edit and save your display name |
| Owner note | Open, edit and save the note title and text |
| Sharing & connections | Review name sharing and application or AI disclosure settings |
| Passkey management | Add a passkey and transfer the saved name |

“Sharing & connections” and “Passkey management” are collapsible sections: select their headings to expand them. Note import/export and note passkey transfer have their own collapsible sections beside the owner note. Opening the profile does not open the note.

## Save a name or note

After Web sign-in, open the name or note panel, edit it and save. Names and notes have separate save, unlock and transfer operations. A note's title and body are information you enter yourself, not an issuer-verified credential.

Distinguish unsaved edits from saved content. If a conflict or network error appears, follow the screen's retry or reload instructions. Closing, reloading or locking the page can discard unsaved edits.

## Save and reopen your first note

Start with a short piece of information you can afford to lose to check your device and passkey. If a note already exists, open and inspect it first; do not overwrite it just to try the service.

1. Select “Open note” in “Owner note” and confirm your passkey. This action is needed to begin editing even when no note has been saved yet.
2. Fill in both “Note title” and “Note text”. If an empty or oversized value produces an error, correct the indicated field.
3. Select “Save note” and confirm your passkey. Look for “Note encrypted and saved.” Typing into the editor does not save the note.
4. Saving closes the note. Select “Open note” again and verify the saved title and text. This completes a save-and-unlock check.

If it will not open, follow the [passkey troubleshooting steps](passkeys.md). If the save outcome is unconfirmed, do not assume success; check the error and retry instructions on the screen.

## Locking and signing out

The current Vault display has a 15-minute idle limit and a one-hour absolute limit. Open saved items again after a lock. Leaving the page or failing a session check also locks the view.

Use “Lock Vault” at the top of the screen to close the view. To reopen it, select “Check session and reopen”, then confirm your passkey for each item. If you lock with unsaved edits, read the discard confirmation.

Locking Vault and signing out of mikaki are separate actions. Sign out after using a shared device. Closing a browser does not guarantee that the server-side login has ended.

## Sharing and export

Providing a name to an application or data to an AI recipient requires its own consent and configuration. Signing in, connecting an application or unlocking Vault does not release every saved item. Check the recipient, selected data, disclosure method and expiry shown on the screen. Features disabled by operational policy are unavailable.

A note's JSON export creates a **plaintext file**, not an encrypted backup. It exports saved content and excludes unsaved edits. Importing a file populates the editor; saving is a separate action.

To export a note, open the saved note, expand “Import or export a note” and select the consent to plaintext export. Use “Export saved note” and check where the downloaded file is stored. “Import note JSON” loads a supported note JSON document into the editor; it does not restore an encrypted backup or accept arbitrary JSON. Review the imported content, then select “Save note”.

Revoking a share stops future access. It cannot recall data already received by a recipient or erase a downloaded file.

## Before transferring to another passkey

Adding a passkey to the same account does not automatically make it able to decrypt existing data. The current transfer operation needs both supported passkeys on the transferring browser and moves selected saved items.

Transferring the name does not transfer the note. Keep the original passkey until you have reopened the transferred item with the selected passkey. The old passkey may still authenticate the account while being unable to open the new item using its previous key.

Recovery is not guaranteed if every usable unlock method is lost. Real-device recovery and transfer qualification remains incomplete.

## Implementation details

Read the [FAQ](faq.md) and [security and implementation status](security.md). Technical contracts are available in the [Vault design](https://github.com/masanork/mikaki/blob/main/docs/personal-vault.md), [passkey transfer](https://github.com/masanork/mikaki/blob/main/docs/vault-passkey-transfer.md) and [session and lock contract](https://github.com/masanork/mikaki/blob/main/docs/session-lifecycle.md).
