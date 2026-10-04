# Tauri client authentication decision review

**Status (2026-10-05):** the client supports ordinary OIDC login and Identity
wallet/presentation. Native Vault OAuth, consent, ciphertext commands, and the
Vault-specific DPoP key/plugin surface have been retired. This source change
neither deploys a new service nor performs a production reset. The signed-app
and real-device qualification gates below remain separate from source tests.

## Distinguish the roles

Mikaki is an OIDC provider (OP) for registered relying parties (RPs). It uses a
WebAuthn Passkey to authenticate a person during an authorization transaction.
The Owner Vault is a same-origin Web application authorized by the owner
`__Host-op-sso` Cookie; Vault unlock separately calls WebAuthn PRF in the owner
page. An ID Token or Access Token does not create an Owner Vault session or
provide PRF output. See [OIDC login](oidc-login.md), [Vault design](personal-vault.md),
and the [shared Vault owner check](../crates/worker/src/vault_http.rs).

Tauri uses an external browser for ordinary native OIDC Authorization Code
with S256 PKCE, transaction-bound state and nonce, exact issuer/callback checks,
and in-memory token handling. The local UI also hosts Identity wallet and
presentation flows. It does not request Vault scopes or invoke native Vault
ciphertext operations. Android's native-dpop plugin remains for Identity
holder-key and wallet storage commands; its Vault DPoP methods and key alias
have been removed.

## Connection to Owner Vault

| Question            | First-party Owner Vault                | Native OIDC client                                          |
| ------------------- | -------------------------------------- | ----------------------------------------------------------- |
| Interactive Passkey | WebAuthn on the Mikaki HTTPS origin    | External browser during OIDC authorization                  |
| Session held by     | Mikaki WebView Cookie                  | Native client's in-memory OIDC session                      |
| Owner record access | Owner session plus WebAuthn PRF unlock | No native Vault resource access                             |
| Token authority     | Not used for Owner Vault access        | OIDC authenticates the client user; it is not a Vault grant |

An external-browser OIDC completion generally leaves its browser Cookie outside
the Tauri WebView. Do not copy the Cookie or turn an ID Token into
`__Host-op-sso`. The first-party Owner Vault continues to use its web session
and separate unlock flow.

## Ordinary native OIDC

The native public-client path follows [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252.html):
open authorization in an external user agent, use Authorization Code with S256
PKCE, and receive the response through an app-claimed HTTPS link or desktop
loopback. Do not reuse a confidential RP registration or package a shared
`private_key_jwt` key in the app. The FAPI deployment remains a separate
confidential-client profile.

The Worker conformance test `local/conformance/native-oidc.test.ts` covers
registered callbacks, ephemeral-port loopback, `iss`, PKCE, code exchange and
replay handling with a synthetic owner session. It does not prove that an
installed app receives a link, that a system browser completes Passkey login,
or that a local desktop listener binds safely. Signed-app association and
real-device qualification remain required before making those claims.

Operator registration uses `node scripts/client-admin.ts --config <normal-OP-config> --remote no --action register-native --input <registration.json> --actor <name> --reason <reason> --apply yes` after the native-client migrations. Review target DB and callback ownership before changing `--remote` to `yes`. The registration does not distribute a client secret or key.

## Retired native Vault flow

The native Vault authorization, consent page, `vault.read` token issuance,
DPoP ciphertext request, Tauri commands, UI, and platform Vault DPoP key have
been removed. `/vault/oauth/consent` and `/vault-api/attributes/*` are no longer
served. No replacement native record API is part of this change.

Historical Vault OAuth tables and retention references remain for reset and
expiry planning. The Worker also retains explicit token-class isolation so a
historical Vault token cannot be used for ordinary UserInfo/Identity claims or
ordinary DPoP/bearer resource authorization. Removing old schema or data needs
the later reviewed baseline/reset and production cutover; this source change
does not perform that operation.

## WebAuthn PRF qualification

WebAuthn Level 3 PRF provides client-side output; it does not define OAuth
authority or a server-verifiable Vault grant. Do not send PRF output through an
OIDC redirect, token, URL, server API, log, or unrestricted Tauri command.

Qualify the first-party HTTPS Owner Vault on intended devices independently:
verify Passkey registration/assertion, PRF result, reopening a saved record,
second-device behavior, cancellation, session lock, and recovery. A local
Tauri asset origin cannot silently assume `auth.mikaki.org` as its WebAuthn RP
ID. Browser mocks and desktop compilation do not satisfy the real-device gate.
