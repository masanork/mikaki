# Vault usage model and unlock experience

**Status:** proposed product model, 2026-10-03. The accompanying interactive prototype uses fictional data and simulated actions. It does not implement authentication, encryption, new storage APIs or production permissions. Current contracts remain authoritative until their replacements are implemented and qualified.

## Product purpose

Vault is an owner-controlled place for personal information and selected records that remain useful across applications and AI agents. Its ordinary human tasks are to review, correct, find, approve and selectively reuse information. Writing a standalone note is optional, not its defining use case. An agent helps collect or prepare information; it does not become the owner or silently turn guesses into established facts.

The working first-use hypothesis is personal profile plus cross-application AI context/results. Document/credential custody is a separate candidate, not a prerequisite for this first experience. The existing `owner_note` proves bounded encrypted record and proposal transitions; it is retained as legacy/test content, rather than expanded into the general record schema or silently relabeled as an AI memory.

## Human and agent journeys

| Journey | Trigger and useful result | Owner interaction | Authority and freshness |
| --- | --- | --- | --- |
| Reuse personal information | An app needs a display name or, in a future selected profile, another field. The owner reviews one current value instead of entering it in every app. | Open Vault once; inspect/correct the value; approve the named app and exact fields. | An editable assertion is not issuer verification. Ordinary login does not imply profile release. Existing profile release is currently name-only and separately gated. |
| Carry context between AI tools | A completed conversation/task produced decisions worth retaining. Another agent needs selected context for the next task. | Review/import a bounded summary and source references; later select the relevant records to disclose. | Keep source app, source item, version and confirmation state. A summary can be incomplete or wrong; confirmation does not verify its source cryptographically. |
| Keep a useful result | An agent produced a comparison, plan or application draft. The result should outlive its chat session. | Review a proposed new record, then save it to the chosen collection. | Append a new record by default. Replacing an existing value requires its exact base revision and explicit approval. |
| Find and check retained information | The human asks what was decided, what is current or what an app can access. | Search/open records and inspect source/date/history; review permissions in one place. | Do not equate the observation time with a source update time. Unknown or failed freshness checks stay unconfirmed. |
| Amend personal information | An agent suggests a profile change based on a document or conversation. | Review old/new values and source, accept or reject, then commit once. | A read grant cannot write; accepting a proposal cannot independently authorize disclosure to another app. |
| Continue an unattended task | A remote agent needs a selected result while the owner is away. | Issue a limited recipient copy/grant in advance, with target, operations and expiry. | Owner-session keys do not travel with OAuth. A retained copy and its revocation limits must be visible. Unattended append is a future explicit capability, not the default. |

Choose one actual producer and one actual consumer before adding an archive importer or a remote record-sharing capability. Candidate loop: an agent proposes one useful task recap; the human reviews and saves it; a second explicitly selected agent receives that saved recap. File trees, broad email/browser-history collection and arbitrary unattended writes are outside this first slice.

## Data semantics versus storage

`attribute` and `blob` are different layers, not two user-facing folders.

| Concept | Meaning | Example / lifecycle | Current implementation |
| --- | --- | --- | --- |
| Attribute | A named semantic value within an owner/namespace; consumers need a known meaning and current revision. | Display name; a future selected contact preference. Update with expected revision; retain provenance and deletion semantics. | `name` is a raw UTF-8 value. `owner_note` is stored through this API but is a typed test/legacy document, not proof of a universal attribute ontology. |
| Record | An independently identified retained item; there can be many items of one type. | Task recap, comparison result, approved draft or an imported conversation copy. Append/import, find, annotate or supersede with explicit source/history. | A general record collection/list/search API does not exist. One `owner_note` slot must not be advertised as a collection. |
| Attachment | Content belonging to a record, with an explicit media type, size, digest and record authorization. | A PDF attached to an application draft. | Proposed; the present 24 KiB encrypted-attribute bound is not a large-file service. |
| Credential | An issuer-produced signed artifact and its holder-key/status semantics. | A membership or identity credential. Preserve exact issuer evidence separately from local annotations. | Isolated probes exist; no production credential wallet follows from this design. |
| Blob | Immutable stored bytes referenced by an authoritative head/record. | The encrypted body of an attribute or an eventual attachment. | R2 stores ciphertext; D1 stores head/revision/digest/envelope metadata. The user should not manage internal object keys. |

Profiles may contain references to records; records may have attachments; both ultimately refer to stored bytes. Changing a profile field does not rewrite a source document. An encrypted blob's type is not sufficient evidence of its semantic schema, provenance or permission.

The proposed record identity is independent of its title/path, and namespaces bind the owner, collection and declared producer. Encrypt titles, content and sensitive provenance in the owner payload where feasible; document the minimum routing/revision/size/access metadata exposed to the service. Source labels supplied by an app or agent remain unverified labels unless a distinct verification contract establishes stronger assurance.

A future record envelope should version its schema and specify record ID, kind, collection, content or attachment references, provenance, optional source tuple/version, creation/observation times and supersession links. Do not add these fields to the strict version-1 note encoding. Imported source events and owner annotations are separate; deleting an imported record must not let a later sync silently recreate it. Define import deduplication, deletion suppression and conflict semantics with the chosen producer.

## Owner experience

The initial screen is one locked Vault, with one **Open with Passkey** action. Successful opening makes supported owner content readable and editable for a bounded session. Navigating sections and ordinary saves do not prompt again. A successful save keeps the owner's working session open and shows the saved value; it does not send the user back to another unlock action.

The proposed sections are **My information**, **Records**, and **Connections**. Pending agent suggestions appear as a review task linked to their destination. Passkey/recovery settings are secondary account settings. Technical identifiers, envelope formats and operation IDs belong in diagnostics, not the main task flow.

Locked views contain no decrypted values or sensitive record titles. Empty sections give a concrete next action such as accepting an app/agent's proposed record, not a compulsory note editor. Existing unsupported/unknown records remain intact and are explicitly unavailable rather than erased, rendered as raw text or overwritten.

Human-owned reading/editing and external authority are separate. A viewable Vault does not authorize an app or agent. Sharing presents the actual consumer/provider, exact selection, read/propose operations, copy/live mode and duration. Initial destructive deletion, external disclosure, new/replacement Passkey custody and broader authority retain explicit confirmation; their reauthentication requirements must be defined by operation, rather than by every field access.

## Unlock and key architecture

Current code keeps a display lease and separately obtains PRF for each value, clears outputs immediately, and requests PRF again when saving. `VaultSession.reopen()` verifies SSO without decrypting anything. That is the source of the misleading two-stage unlock experience.

The target is an owner-key session that is distinct from server SSO. A successful explicit Vault ceremony unwraps a Vault-level owner key, which protects collection/record keys. Data revisions continue to receive fresh content keys and revision-bound encryption. An agent or service receives only separately selected recipient authority, never the Vault root. This hierarchy was already proposed in [personal Vault](personal-vault.md); it is not implemented by changing button text or caching a field's plaintext.

The [WebAuthn PRF specification](https://www.w3.org/TR/webauthn-3/#prf-extension) permits one or two evaluation inputs per selected credential. Pairing the current name/note inputs could reduce prompts for those two objects, but cannot establish one scalable unlock for arbitrary independently wrapped records. Adding more per-object prompts behind an “open Vault” button would retain the underlying problem. Do not replace legacy PRF inputs with a common value: that would make existing ciphertext unreadable.

Before enabling the owner-key session, specify and test the versioned key/envelope format, stable PRF input, KDF/AAD domain separation, owner/origin/Vault/key-generation binding, per-Passkey wrapping and loss/recovery behavior. Prefer non-extractable browser key handles for the in-memory lease; clear retained byte arrays and drop key/state references on lock. This is bounded lifetime management, not a guarantee that JavaScript/browser memory can be physically erased.

Retain the current idle/absolute/session-replacement/logout/pagehide protections. A hidden tab masks content and suspends operations; verified return within the lease should not add another prompt. An expired or invalid owner session destroys the unlock lease; late authenticator/network results cannot recreate it. Do not persist owner keys or PRF output in localStorage, sessionStorage, IndexedDB, URLs or service Worker caches. Adding offline custody requires its own explicit design.

Ordinary RP sign-in remains usable without PRF. Combining an owner-facing sign-in with Vault opening is a later measured improvement: it must preserve login on non-PRF credentials, bind the authenticated owner/credential and keep owner secrets across navigation through a defined same-origin lifecycle. An SSO cookie alone must never produce decrypted Vault content.

Existing data requires a deliberate upgrade/rewrap flow that proves readability before committing and handles conflicts/exact retries. Different legacy Passkeys may require their respective existing credentials during that one-time upgrade; do not promise a universal one-prompt migration or silently delete test data. Login recovery and owner-key recovery remain distinct.

## Delivery slices and acceptance

| Slice | Concrete result | Required evidence |
| --- | --- | --- |
| U1: owner-key contract | Versioned Vault wrapping and a bounded unlock lease, independent of item count. | Round-trip/vector tests; wrong origin/owner/generation/credential; absent PRF/cancel; expired/aborted late replies; fresh content keys; unchanged legacy readability. |
| U2: actual unified unlock | One entry action opens current supported personal information and legacy records. Ordinary navigation/save stays open. | Actual Worker/browser journey; ceremony counts; save/reopen/conflict/exact-retry behavior; lock/sleep/SSO replacement; disclosure/transfer boundaries; intended-device PRF. |
| U3: first useful record loop | One named producer proposes a recap/result, the owner reviews/saves it, and one named consumer receives an explicitly selected saved record. | Source/schema contract; append identity/deduplication; approval versus disclosure; scope/search/list denials; saved-only bytes and stale-source handling. |
| U4: broader object storage | Multiple records and attachments with quotas, paging and deletion/import semantics. | A concrete attachment use case, bounded streaming/media/download behavior, metadata exposure and owner/recipient isolation. Do not adopt a file standard from this prototype alone. |

The [interactive preview](vault-usage-preview/README.md) exercises the intended locked → open → ordinary save → proposal review → selected sharing → lock flow with fictional data. It is a reviewable target for U1/U2, not their completion. The existing [quality gates](product-quality.md), [protocol boundaries](adr/0012-vault-protocol-boundaries.md) and [fit/gap backlog](vault-fit-gap.md) remain in force.
