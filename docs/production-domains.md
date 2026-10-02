# mikaki.org production domains

| Origin | Purpose | Worker |
| --- | --- | --- |
| `https://mikaki.org` | Public landing page | `mikaki-site` |
| `https://auth.mikaki.org` | OIDC issuer, Passkey, Vault, administrator settings | `mikaki-auth` |
| `https://app.mikaki.org` | Native app association, exact HTTPS callback, app/recovery pages | `mikaki-app-links` |

The UserInfo service is `mikaki-auth-claims`. Both authentication Workers bind the new `mikaki-auth` D1 database (`f9299d62-2dbf-4bae-ae49-8b75674572d4`) and private `mikaki-auth-vault` R2 bucket. No account, credential, session or encrypted Vault data is copied from the tossa.app test deployment. The previous Workers and storage remain untouched. Register a new Passkey on auth.mikaki.org using a privately issued first-administrator invitation; the old Passkey cannot authenticate this RP ID.

The signing key and readiness token use the existing production secret provisioning, including GitHub Actions. Public signing material and runtime policy are initialized in the new DB. Native Vault OAuth and attribute sharing remain disabled. Recipient key activation is a separate operation before enabling sharing. The disabled native Vault grant protocol retains its existing resource/detail identifiers to match the shared validator and immutable migration constraints; network requests use auth.mikaki.org. Renaming those protocol identifiers requires a separate schema change before native Vault activation.

## Web sign-in

The public landing and app pages link to `https://auth.mikaki.org/signin`. The issuer home also offers Web sign-in and invitation registration. Existing Passkeys sign in directly to `/vault`; unauthenticated Vault visits start the same flow. No native app, RP authorization, or agent request is needed. Browser account settings and Vault remain available on the Web; native apps provide device integrations such as identity-document reading.

First-party sign-in uses a separate five-minute, browser-bound transaction, requires verified WebAuthn authentication, and fixes its continuation to the issuer's Vault. It creates an SSO session without adding an application connection or authorizing an agent. Only the optional `lang=ja|en` parameter is accepted. Deployments must reconcile migration `0030_web_signin.sql` before activating the new authentication bundle.

## App links

The exact mobile redirect is `https://app.mikaki.org/oidc/native/callback`, with sector `app.mikaki.org` and the checked-in mobile client registration. Android package/signing identity is preserved. Rebuild/reinstall the native app to use its new issuer, callback and verified-link host. Existing installed builds still refer to the old test environment. iOS association remains unconfigured pending the actual Apple team/signing identity; this deployment does not claim iPhone qualification.

If the callback reaches a browser, the app Worker responds with a fixed 303 to `/native-link-help`, dropping code/state and the entire query. OP endpoints return 404 on app.mikaki.org. The root domain and app pages never receive authentication cookies or bind D1/R2/signing secrets.

## Build and deploy

`npm run build:website` builds both public sites using the same origin-derived woven renderer as the login screen. `npm run check:website` and `npm run test:website` check types, PC/mobile layouts, reduced motion, static HTML and exact callback isolation. Screenshots are written to `artifacts/website-preview/`.

On main, authentication CI promotes its attested Worker bundles to the production configurations, and the website deployment job publishes the two independently configured public Workers after verification. Older source runs may deploy only when their descendants consist solely of metrics bot changes. Public smoke checks auth.mikaki.org and app.mikaki.org.

Web RPs must change their issuer configuration to `https://auth.mikaki.org` and register on this new issuer. No external RP repository is modified by this deployment. The bootstrap invitation is kept in a private mode-0600 local file, never checked in or embedded in a public page.

## Initial activation evidence, 2026-10-02 JST

Clean source `d7e968ac986100471f586502c95a63463a5a2b2f` supplied the initial manually built deployment:

| Worker | Version |
| --- | --- |
| mikaki-site | `1ae4a6c7-3eb8-4500-acbb-168acd4fd3b9` |
| mikaki-app-links | `ee4329ce-35bf-4f0b-965b-6f67aadac399` |
| mikaki-auth | `f68c01bc-8510-44e7-a258-04453df94cde` |
| mikaki-auth-claims | `34089a0c-3f69-49a4-b413-2b5c13160120` |

At 2026-10-01T22:24:48Z, public HTTPS checks passed exact clean source/version, configured bindings, readiness 204, Discovery/JWKS, both reviewed login asset digests, landing/app/recovery pages, Android association, query-free callback 303, OP isolation 404 and mobile S256-PKCE login entry. A published Cloudflare edge address was used to bypass the local resolver's cached NXDOMAIN for newly provisioned hosts. The same checks passed with normal public DNS/HTTPS at 2026-10-01T22:28:19Z. This is public-endpoint qualification, not a production Passkey ceremony or a signed-device completion test. Local tests passed all 15 Worker browser tests, Passkey preflight and the website/browser checks.

Login JavaScript SHA-256: `a24faa61f0d0f5acf143b33d98b5e740146a872e13265a78beed6729d8d5b0e8`; CSS SHA-256: `445fa2134f1192ed82ee17564d560d6859282176d9fd89df5749b70eaa5c7966`.
