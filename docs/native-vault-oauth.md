# Native Vault OAuth: ciphertext read profile

**Status:** local authorization, token, and ciphertext API preview, 2026-09-30.
The strict one-attribute request model, D1 consent/grant/code-context
schema, and shared encrypted snapshot reader are implemented. The D1 consent
record has a one-way `pending → approved/denied` and `approved → consumed`
transition guarded by the live owner SSO; a grant requires consumed consent.
The owner review page accepts an SSO-bound pending transaction, shows the
client ID and exact attribute, and records one approval or denial. With
`MIKAKI_NATIVE_VAULT_OAUTH=preview`, `/authorize` creates that transaction
for an exact registered HTTPS native callback and consumes its approval in
the same D1 batch that issues the authorization code, Vault grant, and code
context. The `/token` preview requires the exact Vault `resource` and a valid
DPoP proof, and records a distinct audience/grant context with the opaque
Access Token. It returns the granted `authorization_details`; UserInfo rejects
this Token. The preview GET `/vault-api/attributes/{attribute}` verifies the
Token, exact grant, live owner session, and one-use DPoP proof before calling
the shared encrypted snapshot reader. The preview must remain off outside
local testing: an installed, OS-protected DPoP key and production client
identity display are not implemented. The mobile Tauri preview has a
short-lived Rust-held DPoP key and ciphertext read command. Ordinary
native OIDC Access Tokens remain for UserInfo. The ordinary authorization route
explicitly rejects unsupported `resource` and `authorization_details`
parameters while this profile is incomplete, so a requested Vault audience is
not silently treated as UserInfo access.

The current consent schema requires the exact registered callback, so this
first slice targets the mobile app's HTTPS link. Desktop's ephemeral loopback
callback needs the same registered-template versus actual-port binding used by
ordinary OIDC codes before Vault consent is extended to desktop.

## Purpose and boundaries

The first grant lets a registered native client read **one named encrypted
attribute** and its owner envelope. It never returns plaintext, PRF output,
WebAuthn credentials, or an owner Cookie. It does not grant writes or imply
that the native app can decrypt the returned envelope. The existing
`/vault/attributes/{attribute}` routes retain Cookie-based owner authority.
The new API is `/vault-api/attributes/{attribute}` with a separate token
audience, `https://mikaki.tossa.app/vault-api/`.

Use [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) `resource` at
authorization and token requests. Require exactly the Vault audience for a
Vault grant; reject multiple resource values and token-time escalation. Use
[RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html)
`authorization_details` to name the exact attribute. This is a Mikaki
application profile of those standard parameters:

```json
[
  {
    "type": "https://mikaki.tossa.app/authorization-details/vault-read-v1",
    "locations": ["https://mikaki.tossa.app/vault-api/"],
    "actions": ["read_ciphertext"],
    "attribute": "owner_note"
  }
]
```

The request must also have `scope=openid vault.read`. `openid` maintains the
OIDC login result; `vault.read` identifies the coarse operation. The RAR
object narrows it to one attribute. Initially accept only a single object,
single location, single action, one exact attribute ID, and one native client
registration. Reject unknown fields, duplicate JSON keys, duplicate OAuth
parameters, inconsistent scope/resource/details, and unsupported attributes.
The type URI identifies Mikaki's own semantics; RFC 9396 alone does not define
the `attribute` field.

## Authorization and consent

1. The app opens the external browser with Authorization Code, S256 PKCE,
   `state`, `nonce`, `resource`, `scope`, and `authorization_details`. A native
   client remains public. The app creates one P-256 DPoP key per installation
   in platform-protected storage and supplies a DPoP proof at token exchange.
2. The OP authenticates the owner through its existing Passkey ceremony.
   Authentication and the current generic `consent: true` flag are **not**
   Vault consent. Before issuing a Vault code, show a dedicated same-origin
   page with the registered client identity, attribute, operation, and
   expiration. Require an affirmative owner action. Existing SSO does not
   skip this page. Denial returns `access_denied` to the exact registered
   redirect with the original `state` and `iss`.

The current review page shows the registered client ID and callback URI but
has no operator-reviewed display name or signing identity. Add trustworthy
client display metadata and show the grant lifetime before enabling live Vault
authorization; a UUID alone is inadequate for a production consent decision.
3. Store a one-use, browser- and SSO-bound consent transaction. In one D1
   transaction, consume it and issue an authorization code whose immutable
   context contains resource, attribute, client revision, owner account,
   grant version, and expiration. The code is still subject to the normal
   PKCE and redirect checks. Never infer Vault consent from an `app_connection`
   row, which represents ordinary OIDC connection.
4. At token exchange, require a valid DPoP proof and pin its JWK thumbprint
   to the issued Access Token. Reject an absent proof, `Bearer` substitution,
   a changed resource, stale client/grant revision, and an expired consent.
   Use a short lifetime no longer than the current OP policy and grant expiry;
   issue no refresh token in this slice. The preview implements these checks
   locally and requires the exact Vault `resource` in the token request;
   token-time `authorization_details` is omitted and the approved details are
   returned in the response. The ID Token still has the native
   client as audience, while the opaque Access Token has the Vault API as its
   server-side audience. Return the granted details in the token response.
5. The resource endpoint accepts `Authorization: DPoP <token>` only. Validate
   the `htu`, `htm`, `ath`, JWK thumbprint, `iat`, `jti` replay receipt, and
   nonce policy using the existing DPoP verifier and durable replay ledger.
   Resolve the token hash to a live Vault grant and internal owner account;
   check exact audience, attribute, operation, client/grant version, token
   expiry, revocation, account/credential status, and DPoP binding on every
   read. Return the same ciphertext, envelope, format version, revision, and
   ETag as the owner API through a shared storage reader. The local preview
   implements this GET path; it does not provide a write operation or plaintext.

## Storage and revocation

Add an immutable authorization-code Vault context and an active grant table
keyed by opaque grant ID. A grant records `account_id`, `client_id`,
`client_revision`, `attribute_id`, `resource`, `action`, `version`, `expires_at`,
and `revoked`. The token issue records the grant ID/version and audience; a
plain UserInfo token has neither. The resource query must join these records
to the currently eligible client session and active account, rather than
trusting fields from the client or a token body. Revoking a grant or client,
incrementing its version, invalidating the owner session, or deleting the
attribute must immediately stop reads. Existing already disclosed ciphertext
cannot be recalled.

Keep the owner envelope unchanged. Its PRF-wrapped key may be unusable in the
native client; that is an expected result until the separate Level 3 PRF and
device transfer gate passes. Do not export PRF output to repair this gap.

## Verification gate

Use the Worker contract harness with a synthetic owner to cover approval and
denial, existing SSO, exact attribute, wrong audience/scope/details, stale or
replayed code, missing or substituted DPoP proof, proof replay, expired or
revoked grant, another owner's record, deleted/corrupt blob, and attempted
write. Then test a signed installed app against a registered OP. A successful
encrypted read is **not** evidence of local decryption.

The implementation order is: strict request model and D1 constraints
(implemented); dedicated consent page and
decision handler (implemented); preview authorization code and grant binding
(implemented); preview DPoP Token exchange with separate audience
(implemented); DPoP resource
handler with shared storage reader (implemented in local preview);
ephemeral app-session key and mobile client request (implemented as a local
preview); OS-protected installation key; then
contract and installed-app tests. Each intermediate build must reject Vault
access until all checks are connected.
