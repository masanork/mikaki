# Direct issuer entry preview

The `/` page uses a single continuous bamboo fence, with no meeting stiles, split leaves or Passkey crossbar. It reuses the login screen's cached material, pointer/ambient light, optional device tilt and reduced-motion lifecycle. The current page's normalized origin determines the weave/color; the host on the top material plaque uses the same profile. Query parameters and paths do not affect this decorative identity cue.

The plaque identifies the service once, quietly, as `mikaki`. The only central instruction is “Sign in from your app”; invitation registration and language selection remain at the bottom. Direct entry does not create an RP authorization request or offer an unbound Passkey sign-in. Registration retains the selected language. The actual page host is shown, rather than a configured or caller-supplied destination. Appearance is not proof of authenticity.

This is a design choice informed by the contrast between [Google's direct account entry](https://myaccount.google.com/), which names its service, and [Auth0's default login routes](https://auth0.com/docs/authenticate/login/auth0-universal-login/configure-default-login-routes), which return a missing/expired login transaction to an application login route when configured. Mikaki has no requested application on `/`, so a small service name gives context while the central instruction preserves app-initiated login.

The server emits the same compact layout with a CSS fence and working registration/language links before JavaScript loads. Svelte replaces it with the shared animated fence. Canvas allocation/context failure retains the CSS fence; reduced motion freezes the light. The static fallback uses the default palette, while the live renderer derives its profile from the origin. The response remains `no-store`, `no-referrer`, unframeable and uses self-hosted scripts/styles. Inline styles are permitted for the generated material profile, as on the login screen.

| View | Capture |
| --- | --- |
| Japanese desktop | [home](home-ui-preview/home.png) |
| English desktop | [home-en](home-ui-preview/home-en.png) |
| Different origin | [other-origin](home-ui-preview/other-origin.png) |
| Mobile | [home-mobile](home-ui-preview/home-mobile.png) |
| Canvas fallback | [home-fallback](home-ui-preview/home-fallback.png) |

Run `node docs/home-ui-preview/capture.mjs` after building the Worker. Captures use actual local Worker `/` and asset responses in Chromium under their CSP, with the production hostname intercepted locally to preview its material profile. They do not contact production. The Worker UI browser test covers both locales, origin/profile changes, ambient and reduced motion, canvas fallback, mobile overflow and JavaScript-disabled entry/navigation. Existing login/registration/Vault/RP journeys are checked by `npm run test:worker-browser`.
