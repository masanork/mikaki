# Native Vault OAuth retirement

Status (2026-10-05): the follow-up branch `feat/issue-121-native-vault-retirement`
removes native Vault OAuth and ciphertext access from the Worker and Tauri client.
This source change is not yet merged to main or deployed. The first-party Owner Vault remains a web
application using its owner session and WebAuthn PRF flow. The native app keeps
ordinary OIDC login and Identity wallet/presentation capabilities; it has no
native Vault replacement API.

The authorization server rejects `vault.read`, resource indicators, authorization
details and `vault_consent` on the ordinary authorization endpoint. The old
`/vault/oauth/consent` routes and `/vault-api/attributes/*` routes are absent.
Legacy token exchange contexts cannot produce ordinary OIDC tokens. Existing
`vault_oauth_token_context` rows remain excluded from UserInfo/Identity claims
and ordinary DPoP/bearer resource authorization, preventing historical Vault
tokens from crossing into another token class.

Historical migrations and consent/grant/context tables remain in the database
for retention and reset planning. Retention ordering and old-object GC guards
remain active while historical rows or encrypted objects may exist. This code
retirement does not delete production data, reset a database, consolidate the
migration baseline, revoke stored grants, or deploy a service change. Those are
separate #121 cutover steps.

There is no supported native ciphertext read flow and no successor native
record API in this change. Do not register or configure a native Vault resource,
ask users to approve Vault OAuth consent, or enable a Vault preview build flag.

Validation for this retirement is recorded with the #121 implementation PR.
It covers rejection of the legacy authorization inputs and consent endpoints,
ordinary native OIDC/PKCE and DPoP boundaries, and retained Identity issuance
and UserInfo claim isolation. It does not qualify installed-app login or
physical-device Identity/PRF behavior.

## Local revalidation before Wallet adoption

The earlier preview qualification notes at this anchor are superseded by this
retirement record. Keep Owner Vault browser/device qualification separate from
native OAuth: the native client no longer reads ciphertext, and ordinary OIDC
or Identity issuance does not qualify PRF access or installed-app behavior.
