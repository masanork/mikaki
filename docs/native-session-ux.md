# Android Wallet and Chat session

The Android app keeps the bundled Wallet shell and its bottom tabs alive. A
separate, persistent first-party WebView hosts sign-in, Chat and passkey settings.
The normal Android login path opens the platform Passkey chooser from that view;
it does not launch a system browser. Desktop and iOS retain their existing OIDC
paths. External-browser mobile OIDC remains an explicit native compatibility
command, with PKCE, state, nonce and issuer checks unchanged.

The ordinary build embeds the public mobile registration from
`apps/mikaki-client/mobile-client-registration.json`. An explicit
`MIKAKI_MOBILE_CLIENT_ID` override must be valid; an empty override fails the
build. Previously a signed APK could omit the ID entirely and fail before the
Passkey ceremony.

The remote WebView has no Tauri IPC, native signer or storage bridge. It permits
only HTTPS navigation to `auth.mikaki.org`, cancels TLS errors, disables file and
content access, mixed content, popups and third-party cookies. Its origin-bound,
top-frame message listener accepts only fixed lifecycle/draft/navigation hints.
Those hints do not authenticate the native Wallet.

Rust privately reads the fixed HttpOnly SSO cookie through the Android plugin
and validates it with `POST /native/session`. This first-party account projection
is not an OAuth grant, credential issuance, or Vault unlock. It returns only the
registered mobile client ID, its stable pairwise subject and SSO expiry. It
requires the current active account, credential, session epoch, session expiry,
and exact active native client/sector/callback registration. It does not mint a
token or expose a raw account ID. Existing OIDC-owned document inventory uses the
same subject and remains addressable. A same-origin check and fixed request
header protect the endpoint; it offers no CORS access.

Native account authority has a maximum 20-second lease, refreshed every 10 seconds
while the shell is visible. Connection failure, expiry, revocation or account
replacement closes the native inventory rather than retaining an unverified
owner. Cancellation/logout generations reject late responses. Signing out of
this app destroys its remote view and removes its SSO cookie without clearing
unrelated cookies or local encrypted documents. It is a local app sign-out, not
backchannel logout of other applications.

The login PRF handoff remains single-use, document-local and bounded by its
existing 60-second deadline. The app waits until the handoff is consumed or
disposed before returning to Wallet. Hiding Chat suspends its Vault lease and
closes child MLS handles; returning revalidates owner/key authority and remounts
Chat using the retained Vault key, without requesting another PRF solely for the
tab switch. Existing idle/absolute lock deadlines still apply. Unsaved input
requires an explicit discard decision before leaving Chat; background/lock
continues to clear sensitive child state.

## Release evidence

Host tests and browser mocks do not establish an Android Credential Manager or
PRF success. Qualify the signed APK against the production asset links, then on
the connected device verify Passkey sign-in, Wallet → Chat → Wallet, background
resume, cancellation, logout and account replacement. The device preflight also
requires the production `/native/session` endpoint to return a cookie-free 401
with no-store headers before the new APK is used.

Chat availability remains controlled by its separately built messaging package,
runtime flag, issuer key and schema qualification. Shared login must not imply
that a disabled production Chat service is enabled. Real passport issuance and
presentation remain separate device qualification steps.
