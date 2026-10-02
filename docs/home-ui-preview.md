# Direct issuer entry preview

The `/` page uses a single continuous bamboo fence, with no meeting stiles or split leaves. It reuses the login screen's cached material, pointer/ambient light, optional device tilt and reduced-motion lifecycle. The current page's normalized origin determines the weave/color; the host on the top material plaque uses the same profile. Query parameters and paths do not affect this decorative identity cue.

The plaque identifies the service once, quietly, as `mikaki`. The central Passkey instruction and sign-in link start a first-party Web ceremony at `/signin`; invitation registration and language selection remain at the bottom. Sign-in goes directly to Vault without creating an RP connection or agent authorization. Registration retains the selected language and uses `/enroll`, including from the first-party login screen. The actual page host is shown, rather than a configured or caller-supplied destination. Appearance is not proof of authenticity.

The service name gives context for direct account entry, while the woven material keeps the same origin identity cue as the RP login screen. The Web version requires no native app; native integration is reserved for device-specific capabilities such as identity-document reading.

The server emits the same compact layout with a CSS fence and working sign-in/registration/language links before JavaScript loads. Svelte replaces it with the shared animated fence. Canvas allocation/context failure retains the CSS fence; reduced motion freezes the light. The static fallback uses the default palette, while the live renderer derives its profile from the origin. The response remains `no-store`, `no-referrer`, unframeable and uses self-hosted scripts/styles. Inline styles are permitted for the generated material profile, as on the login screen.

| View | Capture |
| --- | --- |
| Japanese desktop | [home](home-ui-preview/home.png) |
| English desktop | [home-en](home-ui-preview/home-en.png) |
| Different origin | [other-origin](home-ui-preview/other-origin.png) |
| Mobile | [home-mobile](home-ui-preview/home-mobile.png) |
| Canvas fallback | [home-fallback](home-ui-preview/home-fallback.png) |

Run `node docs/home-ui-preview/capture.mjs` after building the Worker. Captures use actual local Worker `/` and asset responses in Chromium under their CSP, with the production hostname intercepted locally to preview its material profile. They do not contact production. The Worker UI browser test covers both locales, origin/profile changes, ambient and reduced motion, canvas fallback, mobile overflow and JavaScript-disabled entry/navigation. Existing login/registration/Vault/RP journeys are checked by `npm run test:worker-browser`.
