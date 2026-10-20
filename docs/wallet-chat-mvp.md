# Wallet and Chat MVP

The product has two primary destinations: **Wallet** and **Chat**. Vault is the
underlying custody mechanism, rather than a separate collection of editors and
administrative tools. This supersedes the broader initial-screen proposal in
[the previous Vault product model](vault-product-model.md).

## Product loop

Read an identity document → review and complete the issuer's identity check →
receive a credential → keep it in Wallet → present selected information through
Chat or to a nearby reader. Additional credentials can use earlier credentials
as evidence when their issuer accepts them. Each issuer determines its own
eligibility, evidence and issuance policy.

Wallet is a collection from the beginning. One successfully received and
presented credential is the minimum acceptance example, not the inventory limit.
Document-derived information and issuer-produced credentials retain their source
and verification status. Reading a document does not silently create a digital
replacement for the original document.

## First implementation

- The native application opens Wallet directly; account authentication stays in
  the in-app Web screen. The primary navigation has
  only Wallet and Chat; account settings remain in the header.
- Wallet shows verified native credential metadata and supports multiple cards.
  Opening a card shows its contents. Reading documents, receiving credentials and
  presenting them are explicit tasks, initially closed.
- The first issuer remains Mikaki's existing linked-document attribute issuer.
  It is not a municipality-issued resident/tax certificate or an employer's ID.
  Its current five-minute validity and configured trust requirements remain.
- The existing reader supports My Number Card and traditional IC driving
  licences. Passport reading and additional issuers are subsequent integrations.
  Raw read previews and PINs are temporary. This slice retains the existing
  owner-approved attribute linkage and encrypted credential custody; it does not
  add a persistent archive of original identity-document data.
- Android retains up to eight credentials under its existing holder/storage
  keys. Other platforms keep the current in-memory behavior. The inventory IPC
  exposes verified display fields, never credential strings or holder keys.
- Native Chat opens the existing in-app Web companion. The browser product uses
  the same Owner unlock and the MLS runtime exercised by the qualification suite.
  The first slice supports one current one-to-one conversation per local device,
  manual synchronization and the existing bounded durable history.
- A complete OpenID4VP invocation sent as a Chat message offers a **Walletで提示内容を確認**
  link. Chat text grants no authority. Native Wallet independently validates the
  configured verifier, signed request, freshness and selected claims, then asks
  for approval. Nearby mdoc presentation keeps its separate review.

Profiles, the independent owner note, generic record/archive editing, Agent
grants, local exports and Work links are absent from the normal product entry.
Existing encrypted data and API custody are not erased by removing those controls.

## Local acceptance and activation

Run `npm run test:wallet-chat-product` for the two-destination native UI,
multi-card display, navigation redaction and bounded Chat handoff parsing. Run
the [MLS browser suite](../design/probes/mls/chat.browser.test.ts) against the
canonical product runtime for actual encrypted send/retry/reload/lock behavior.
The existing native Rust and identity-contract suites cover credential receipt,
holder binding and explicit presentation.

Chat uses the limited beta's single runtime, host and activation boundary:
Cargo feature `messaging-beta`, `MESSAGING_BETA_ENABLED=true`, and the dedicated
`MESSAGING_ISSUER_KEY` Ed25519 secret. Apply `0001_messaging.sql` and
`0002_beta_profile.sql` from the separate `crates/worker/messaging-migrations/`
directory only for an enabled environment. The ordinary owner migrations do not
add messaging tables. See [the beta configuration](mls-beta.md).

The Chat tab lazy-loads this runtime after the existing Owner unlock. First-time
browser enrollment requires an explicit action. The public local profile is tied
to the Owner key context; missing or mismatched local state stops without
silently making another device or overwriting a registered identity. Returning
between Wallet and Chat reuses the unlock and saved conversation. Unsaved text
requires confirmation before leaving Chat or opening settings.

The browser engine is built from pinned MLS Rust source into a per-build output
directory and served through gated static asset routes. It does not enlarge the
server Wasm with an embedded copy. Default builds keep the usual CSP and expose
no messaging endpoints even if the runtime beta flag is accidentally set.
No remote migration, production activation or trust provisioning is performed.

Release acceptance additionally requires a physical supported card/device,
configured issuer and verifier, restart and key-custody checks, and the actual
Chat-to-native and nearby-reader handoffs. Test credentials and simulated native
IPC do not establish those results. Third-party issuance remains a named
integration, not a capability implied by accepting a generic file.

## Integration verification (2026-10-20)

The two earlier implementation paths have been reconciled on
`feat/wallet-chat-mvp-release-20261020`, based on current main
`d7bfb2fc`. Earlier snapshot branches are retained locally and are not the PR base. The beta's runtime, separate schema, server-side device slot and
fail-closed profile handling are canonical. There is no duplicate Chat backend
or ordinary-owner messaging migration.

`npm run test:wallet-chat` builds and verifies both default and beta Workers,
then checks native Wallet. The independent MLS browser suites also exercise the
same runtime for retry, fork recovery, revocation and changed-key review. The normal
product browser test covers two separately authenticated owners, explicit first
enrollment, independent fingerprint review, invitation approval, encrypted
bidirectional delivery, Chat-to-Wallet presentation links, draft cancellation,
reopening without an extra PRF, missing local state and locking. Native IPC in UI
tests and the Passkey PRF in browser tests are fixtures. The test captures are
[reviewable here](wallet-chat-mvp-preview/README.md).

The existing independent identity, native Rust, locale/CSP and retired-component
regressions remain separate checks. Final local results are recorded with the
integration commit; CI, activation and physical-device qualification remain
separate.

Earlier integration checks: 40 native Rust cases; 55 native UI and budget-unit cases;
4 default/beta product-host cases; 10 shared Chat and peer-review cases; 12
login/legacy-data/UI regressions; and 15 independent identity/presentation cases.
Node, Worker/Svelte and shared-runtime type checks, docs, locales, formatting and
both standard and beta size budgets passed. Screenshots use the actual product
entry and synthetic credentials. These results do not establish CI or device
qualification.

The main-based release preserves the WebView-only account flow, eight-credential
issuance, authenticated age and single-use policies, and native navigation
origin/IPC boundaries. Native Web Chat presentation links enter the same pinned
invocation parser and explicit consent flow as OS deep links. Wallet returns
through the existing fixed `/native/wallet` route inside the app.

Main-based checks: 54 native Rust cases, 64 native UI cases, 12 login and
existing-data browser cases, and 4 default/beta Chat host cases passed locally.
The scoped candidate is prepared for PR/CI; its Chat beta is not activated in
production. See [release readiness](wallet-chat-release-readiness.md).
