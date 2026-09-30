# Typed owner attributes

**Status, 2026-09-28:** the first VG-02 slice implements an encrypted `owner_note` and its owner editor. This is a local implementation; it has not been deployed. It leaves the existing raw UTF-8 `name` unchanged. See the [fit/gap backlog](vault-fit-gap.md) and [protocol boundaries](adr/0012-vault-protocol-boundaries.md).

## Two distinct versions

The existing owner HTTP API still stores the format-1 ciphertext and PRF envelope. Its revision and encryption context bind the origin, attribute ID, credential and revision. The note's **plaintext schema version** is a separate value inside that ciphertext. Updating a note advances the storage revision; it does not change the plaintext schema version.

The attribute ID is `owner_note`. Version 1 has exactly these fields, in this order:

```json
{"type":"mikaki.owner-note","version":1,"title":"My note","text":"Owner assertions","provenance":{"kind":"self-asserted"}}
```

The wire plaintext and exported file are UTF-8 JSON produced by `JSON.stringify` of the validated fields in the displayed order, with no whitespace, BOM, extra fields or duplicate keys. This is a narrow deterministic encoding profile, **not RFC 8785/JCS**. A consumer must not normalize Unicode or silently accept alternative encodings. [`vault-note.ts`](../crates/worker/ui/vault-note.ts) implements this profile and can be reused by a later proposal adapter. No general attribute ontology or schema registry is introduced.

Both title and text must contain non-whitespace content. The title is limited to 256 UTF-8 bytes; text to 4096 bytes. C0 controls and DEL are rejected except tab, CR and LF in the text. Lone UTF-16 surrogates and invalid UTF-8 are rejected. The entire encoded document is limited to 16 KiB; JSON escaping counts toward that limit. HTML `maxlength` is an additional editor bound, not the authoritative byte validator.

## Validation and provenance

Authorized clients validate after decrypting, before importing into the editor, and before encryption. Storage sees the attribute ID, revision, envelope, ciphertext, and existing owner/operation metadata; the title, text, type/version and provenance remain encrypted. The generic server cannot validate plaintext or guarantee that another authorized client wrote a conforming note.

`self-asserted` means an editable owner assertion with no issuer assurance. The owner can import a file made elsewhere; this field does not prove its author, truth or original source. Imported files do not gain verified issuer provenance. Version 1 rejects claims of verified issuers and additional provenance fields. A future agent-suggested/imported-source profile needs a separate explicit schema decision and visible provenance; it cannot acquire authority by changing this string.

Issuer-signed credentials must preserve their original proofs and disclosures in a separate object model if VG-07 proceeds. This note format is neither an OID4VP presentation nor a credential wrapper. A byte digest alone would not prove an issuer.

Unknown type/version, extra fields, malformed encoding and invalid data fail closed. A saved incompatible record cannot be opened, saved or deleted through this editor; its ciphertext remains intact. There is no raw-text fallback, automatic conversion, or automatic upgrade. Future support needs an explicit migration and recovery contract.

## Owner editor and disclosure

The owner opens the note independently with PRF. Saving creates a fresh data key and the next conditional revision. Conflicts require rereading and explicit editing; they never silently overwrite a concurrent change. Lost-response retries retain the same encrypted body and operation ID. The editor locks changes until that request is retried or the owner explicitly discards local edits/retry state and reloads. Reloading does not undo a write that already committed. Deleting retains the existing tombstone and revision rules.

A valid imported JSON file changes only the editor; saving is a separate action. An invalid file preserves current edits. Export requires an explicit plaintext-disclosure checkbox and fresh passkey interaction. It exports the **saved** note, excluding unsaved edits. The resulting file contains plaintext and has no recipient encryption or issuer proof. Temporary byte arrays are cleared where practical; JavaScript strings and browser/download copies cannot be guaranteed erased.

The note uses its own attribute envelope. The [Passkey transfer UI](vault-passkey-transfer.md#saved-note-ui-2026-09-29) can now move this saved note separately from the saved name, preserving its schema/provenance and excluding unsaved edits. Moving the name does not move the note. There is no collection-wide recovery claim. A credential login alone does not unlock an older envelope. General owner-key recovery and real intended-device PRF tests remain VG-01 gates.

Adding `owner_note` does not expand any existing agent grant. The remote MCP snapshot still targets `name`. Since 2026-09-29, a separate [local read-export flow](agent-integration.md#saved-note-local-read-flow-2026-09-29) can disclose the saved note after explicit selection, consent, fresh PRF and saved-revision/schema checks; unsaved edits are excluded. It preserves the canonical note/provenance in a digest-bound, read-only local grant and previews the exact saved content before download. There is no automatic remote sharing or live link back to Vault. A separate [VG-03 typed proposal authority](vault-attribute-proposals.md) reuses this validator and requires explicit target/revision capability and proposal-plaintext disclosure. Approval adopts a suggested self-asserted value; that proposal capability alone does not share the current note, and the separate [VG-04 save action](vault-approved-commit.md) verifies and commits its exact encrypted candidate.

## Qualified local evidence

On 2026-09-28 the three note tests and seven existing attribute/crypto/passkey-transfer/agent-browser regression cases passed. The release Worker build, strict Node and Worker UI checks, Japanese/English message validation, product-source checks, formatting, documentation links and diff whitespace checks also passed. These are local results, not a hosted CI or deployment result.

`npm run test:vault-notes` runs schema/encoding negative cases and a Chromium-to-real-workerd owner flow. The Node HTTP fixture uses the same declared codec to write an encrypted note; Chromium opens it, edits it, and Node decrypts and validates the result. This qualifies those two repository client paths, not independent wallet or standards interoperability.

Cases cover Unicode/byte limits, unsupported versions/provenance, ambiguous JSON, lost-response exact retries, a concurrent HTTP edit, saved-only plaintext export, invalid/valid import, explicit save, deletion/recreation after a tombstone, protected unknown-version ciphertext, and unchanged legacy `name`. Chromium PRF is mocked; encryption and HTTP/D1/R2 transitions are real. The suite is included in CI after the Worker build. Production activation, real-device recovery and agent write support remain separate gates.
