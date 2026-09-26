# Mikaki Help RP

This is a small relying party in its own Rust crate and Worker. Public help articles and ticket validation live in Rust and compile to Wasm. The Worker handles OIDC, RP sessions, HTML, and a separate D1 database. It is a local integration target, not a deployed support service.

## Local run

From the repository root:

```sh
npm ci
npm run build
npm run dev:helpdesk
```

Open `http://127.0.0.1:18878`. The local OP is `http://localhost:18877`. The runner prints a single-use invitation and destroys keys and databases on exit. A browser with a discoverable passkey or the Playwright virtual authenticator is required for the first login. `node --test local/test/helpdesk.test.ts` exercises the same flow.

Anyone may read `/help`. A signed-in user may create a ticket, see their own tickets, reply, and close one. A staff member may list and reply to all tickets. Staff membership is a D1 `staff(sub)` row for this RP's pairwise OIDC subject; it must be provisioned by an operator. There is no public staff self-registration. Tickets are plain text in D1, so do not submit secrets or personal data in this prototype. There is no email notification or attachment handling.

The RP uses Authorization Code + PKCE S256, ES256 `private_key_jwt`, ID Token verification against the pinned issuer's JWKS, browser-bound state/nonce, and the managed `/session/check` lease. Its app logout removes the RP cookie and session; it does not terminate the Mikaki SSO session. `POST /backchannel` accepts an ES256 `logout+jwt` token from the pinned issuer for this client, requires a `sid`, and commits a tombstone and session deletion before returning 200. Duplicate signed deliveries are safe. The tombstone prevents a delayed callback for that `sid` from restoring a session. Register this RP with `backchannel_logout_uri=https://<rp-origin>/backchannel` and `backchannel_logout_session_required=true` once the OP supports delivery. The production OP uses JSON for `/session/check`; the disposable local OP uses a form, selected only by the runner's `LOCAL_ONLY=true` variable. A renewed lease cannot extend past the OP parent expiry. Staff and ticket access are checked on every request.

## Production integration preparation

`wrangler.example.jsonc` is a template. A deployment needs its own D1 database, origin, and registered client ID. Generate a fresh P-256 key for this RP. Register its **public** JWK and exact `https://<rp-origin>/callback` with the [managed client procedure](../../docs/rp-client-operations.md); store the private JWK only in the RP Worker's `RP_PRIVATE_JWK` secret. Apply both migrations in order to this RP's D1 database before routing traffic. Never reuse the OP signing key or database. The production OP does not yet send back-channel notifications, so the session-check lease remains the active revocation bound.

Before production use, add audited staff provisioning, abuse controls for ticket creation, retention/deletion and backup policy for ticket text, operational alerts, and real-device/browser checks. A local pass does not establish a production RP connection.
