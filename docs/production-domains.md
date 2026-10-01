# mikaki.org production domains

| Origin | Purpose | Worker |
| --- | --- | --- |
| `https://mikaki.org` | Public landing page | `mikaki-site` |
| `https://auth.mikaki.org` | OIDC issuer, Passkey, Vault, administrator settings | `mikaki-auth` |
| `https://app.mikaki.org` | Native app association, exact HTTPS callback, app/recovery pages | `mikaki-app-links` |

The UserInfo service is `mikaki-auth-claims`. Both authentication Workers bind the new `mikaki-auth` D1 database (`f9299d62-2dbf-4bae-ae49-8b75674572d4`) and private `mikaki-auth-vault` R2 bucket. No account, credential, session or encrypted Vault data is copied from the tossa.app test deployment. The previous Workers and storage remain untouched. Register a new Passkey on auth.mikaki.org using a privately issued first-administrator invitation; the old Passkey cannot authenticate this RP ID.

The signing key and readiness token use the existing production secret provisioning, including GitHub Actions. Public signing material and runtime policy are initialized in the new DB. Native Vault OAuth and attribute sharing remain disabled. Recipient key activation is a separate operation before enabling sharing. The disabled native Vault grant protocol retains its existing resource/detail identifiers to match the shared validator and immutable migration constraints; network requests use auth.mikaki.org. Renaming those protocol identifiers requires a separate schema change before native Vault activation.

## App links

The exact mobile redirect is `https://app.mikaki.org/oidc/native/callback`, with sector `app.mikaki.org` and the checked-in mobile client registration. Android package/signing identity is preserved. Rebuild/reinstall the native app to use its new issuer, callback and verified-link host. Existing installed builds still refer to the old test environment. iOS association remains unconfigured pending the actual Apple team/signing identity; this deployment does not claim iPhone qualification.

If the callback reaches a browser, the app Worker responds with a fixed 303 to `/native-link-help`, dropping code/state and the entire query. OP endpoints return 404 on app.mikaki.org. The root domain and app pages never receive authentication cookies or bind D1/R2/signing secrets.

## Build and deploy

`npm run build:website` builds both public sites using the same origin-derived woven renderer as the login screen. `npm run check:website` and `npm run test:website` check types, PC/mobile layouts, reduced motion, static HTML and exact callback isolation. Screenshots are written to `artifacts/website-preview/`.

On main, authentication CI promotes its attested Worker bundles to the production configurations, and the website deployment job publishes the two independently configured public Workers after verification. Older source runs may deploy only when their descendants consist solely of metrics bot changes. Public smoke checks auth.mikaki.org and app.mikaki.org.

Web RPs must change their issuer configuration to `https://auth.mikaki.org` and register on this new issuer. No external RP repository is modified by this deployment. The bootstrap invitation is kept in a private mode-0600 local file, never checked in or embedded in a public page.
