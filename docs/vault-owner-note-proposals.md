# OwnerNote proposal review

The unlocked Owner workspace can load AI proposals for the saved `personal/owner_note`, compare them with the freshly read saved note, approve or reject them, and separately save an approved proposal. Approving a proposal never writes the note. The payload remains untrusted text with self-asserted provenance and is rendered as text.

This panel reviews proposals already produced under a live selected v2 Agent grant and an immutable exact-target capability. It does not create either authority, activate a hosted Agent, provision a recipient key, or enable production sharing. The capability is bound to one exact note revision, deletion state and owner-root authority; an active read grant alone cannot authorize a proposed write. See the [approved-commit contract](vault-record-approved-commit.md).

## Owner decisions

Loading is explicit and reads the saved note again before showing the proposal list. Each proposal shows its provider/delegate, state, expiry, proposed title/text and provenance, alongside the saved note. Historical revoked grants can appear without making the entire status response unusable. Only an unexpired pending proposal with current target and live matching authority offers approve/reject. An approved proposal exposes a separate Save action. Recreating a deleted note requires explicit confirmation and its actual positive tombstone revision; a never-created note uses revision zero.

Unsaved edits anywhere in the workspace block decisions and saves. Busy and uncertain proposal operations block other workspace mutations, while the original operation remains available for retry. The browser rechecks authority and the saved target before producing a candidate, and the server rechecks live authority at preparation and atomic commit. Observed saved-note changes clear stale previews. Locking or leaving the workspace clears local plaintext and operations and prevents late asynchronous results from restoring them.

## Interrupted operations

Decision and save operations are opaque objects bound to the controller and the exact snapshot. An unknown response retains the same operation for retry. Once preparation is acknowledged, a final-save retry goes directly to the approved endpoint with identical encrypted bytes, operation ID, proposal identity and conditional revision.

If status already contains an approved prepared candidate, the existing unlocked owner session opens it and compares its canonical plaintext with the approved payload before retrying the original save. It neither creates a new candidate nor repeats preparation. A historical acknowledgment confirms the original write only; the panel then reads the current saved head, which may contain a later owner edit. Prepared recovery still requires a live approved proposal and current target; terminal or expired proposals expose no new write action.

## Qualification

The [helper tests](../local/conformance/vault-owner-note-proposals.test.ts) exercise strict status parsing, opaque snapshot/operation identity, stale authority and exact retries. The [paired Worker tests](../local/conformance/record-attribute-commit.test.ts) exercise the helper against real OP/Agent services, D1 and R2, including a lost save response followed by a newer note and recovery of an existing prepared candidate. Browser qualification uses a virtual passkey and proposal-service fixtures; it does not establish physical-device PRF or an actual hosted Agent integration. No schema migration or production data reset is required for this slice.
