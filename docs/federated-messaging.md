# Federated end to end encrypted messaging

This is a planned development goal, not a completed protocol or implementation. Separate Mikaki instances deployed under different Cloudflare accounts should exchange end to end encrypted messages between DID identified users. The [implementation specification](implementation-spec.md) defines the proposed device and delivery contracts.

## Identity and trust

Each instance may have a separate operator, Cloudflare account, D1, R2, and secrets. Cross instance delivery uses authenticated HTTPS, not a shared DB or account level Service Binding. Distinguish infrastructure account, instance DID, user DID, device/key IDs, and app subject. Internal IDs follow the [identifier policy](identifier-policy.md); a DID is used where key control and resolution matter, not for every database row. A DID alone proves neither real world identity, permission to send, nor Vault access.

`did:web` is the leading instance identifier and endpoint publication candidate; it depends on domain and document control. `did:key` may identify a fixed key but does not inherently supply a mutable endpoint or revocation. Select one tested combination and key format for the first pilot. Establish first key trust and continuity through invitation/fingerprint or equivalent checks. Bound DID resolution by HTTPS validation, redirects, time, size, depth, and SSRF controls. Do not fetch arbitrary DID methods or JSON-LD contexts initially.

Passkeys authenticate users; their private keys are not assumed to sign or decrypt messaging. PRF derived keys unlock a local Vault. Device messaging keys remain on devices. Instance operating keys authenticate delivery but cannot decrypt bodies. Archive keys are separate from live message state. Respect DID verification method purposes instead of treating any published key as universal.

## Encryption and protocol choice

The sender device validates recipient keys and encrypts. Both Mikaki servers relay/store ciphertext; the recipient device validates sender/context and decrypts. Servers still see metadata such as recipient, time, and size. Server authenticated delivery does not authenticate the message author. Key distribution and substitutions are in the threat model. A server that also supplies browser code can attack unlocked plaintext through malicious code/XSS; stronger client distribution or transparency needs separate design.

MLS/OpenMLS is the first candidate, gated on real Rust/Wasm tests for even the first one to one exchange. Do not create an ad hoc ratchet or treat DIDComm or HTTPS alone as forward secrecy. Evaluate vodozemac or another maintained implementation if MLS does not meet size, persistence, or recovery needs. Fix sender authentication, conversation binding, replay protection, offline receive, rotation, crash recovery, and compromise recovery before product use. This is a standard device cryptography candidate with limited custom delivery, not Matrix or DIDComm interoperability.

## First pilot

Use two mutually invited instances on separate Cloudflare accounts, one user and one active messaging device per instance, and short one to one text. Multiple passkeys for account authentication do not imply multi device messaging. Set inbox permission/block rules, quotas, request rates, body limits, durable send queue, message IDs, duplicate suppression, expiry, and retries. Distinguish HTTP acceptance, durable inbox write, device decryption, and read status. Do not promise global exactly once delivery or an atomic transaction across D1/R2 and cryptographic state. Public federation, discovery, groups, attachments, and forwarding follow a later review.

A recipient may explicitly archive verified/decrypted conversation text into their own Vault under separate archive keys. Receiving or archiving is not AI disclosure. MCP may read only selected, authorized conversations; a remote sender's text or DID cannot change tool permissions. Future AI sending requires a separate delegation.

The pilot is complete when two isolated instances exchange offline one to one messages; neither server's database, objects, nor operating keys decrypt the body; key substitution, impersonation, modification, replay, and unauthorized delivery are rejected or surfaced as key changes; retry/reorder/crash do not duplicate display or dangerously reuse cryptographic state; and archived conversations restore with separately authorized MCP access. Record the first trust assumption and device loss behavior.

References: [DID Core](https://www.w3.org/TR/did-core/), [did:web](https://w3c-ccg.github.io/did-method-web/), [did:key](https://w3c-ccg.github.io/did-key-spec/), [DIDComm 2.1](https://identity.foundation/didcomm-messaging/spec/v2.1/), [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html). Fix exact specification versions at adoption.
