# Login UI preview

These images use the actual Worker UI bundle and a synthetic `mikaki-helpdesk-local` connection. Authentication and transaction data are mocked.

| Sign in | Registration | Missing invitation |
| --- | --- | --- |
| ![Sign in](login-ui-preview/sign-in.png) | ![Registration](login-ui-preview/enrollment.png) | ![Missing invitation](login-ui-preview/input-error.png) |

[Mobile sign in](login-ui-preview/mobile-sign-in.png) · [English sign in](login-ui-preview/sign-in-en.png) · [Vault and account screens](product-ui-preview.md)

[CSS fallback](login-ui-preview/sign-in-fallback.png) · [Reduced motion](login-ui-preview/sign-in-reduced-motion.png)

The 2026-10-01 design uses two upright woven bamboo gate leaves, a narrow meeting line and a metal crossbar as the Passkey button. A brushed plate near the top displays the application, current page host and connected application's host. Branding, consent prose, the address-bar instruction and the rejection button have been removed from this screen. Registration folds into “Register with invitation”; direct enrollment opens a compact invitation form on the same gate background. Authentication, discoverable Passkey registration and the rejection protocol endpoint retain their existing behavior.

[`WovenGate.svelte`](../crates/worker/ui/WovenGate.svelte) owns the background and optional tilt control. [`woven-gate.ts`](../crates/worker/ui/woven-gate.ts) derives each leaf's color, spacing, strip width, diamond aspect and over-under pattern independently from its normalized origin. The plate's color and grain use the same profile. A connection retains its appearance across transactions; changing one origin changes only its corresponding leaf. Hash collisions are possible and this visual cue is decorative, not proof of authenticity. The browser address bar and Passkey dialog remain the meaningful domain checks.

Bamboo material is cached in a 2D canvas. A diagonal grazing light and soft halo move at up to 24 fps without pointer input; mouse position changes their direction. The material and center seam remain still. The longer backing dimension is capped at 1800 pixels and device pixel ratio at 1.25. Hidden tabs and Passkey operations stop animation. Reduced motion retains a still render. A static CSS gate preserves the domains and controls when canvas allocation is unavailable or its context is lost. Animation frames, resize observers and event listeners are disposed on unmount. The old rotating seal and short-lived `/login/cue` refresh are no longer used by the login UI.

Tilt is offered on touch devices with an orientation API in a secure context. It requires a separate explicit toggle, requests permission where the browser requires it, and never delays Passkey authentication. Physical-device tilt behavior and performance remain unqualified; the screenshots and browser tests are synthetic Chromium evidence.

[`auth.css`](../crates/worker/ui/auth.css) provides the login styles. To refresh the screenshots, build with `worker-build --release crates/worker`, then run `node docs/login-ui-preview/capture.mjs`. The capture uses the login CSP and checks browser exceptions and desktop/mobile horizontal overflow, including forced canvas unavailability and reduced motion. `node --test local/conformance/worker-ui.test.ts local/conformance/enrollment-browser.test.ts` checks stable connection identity, idle animation, Passkey pause, context-loss fallback, locales, validation, actual registration and sign-in through a virtual authenticator, and Vault PRF encryption. See [quality gates](product-quality.md) for the distinction between synthetic visual evidence and production/intended-device qualification.

The gate design was activated on 2026-10-01 from merged PR #35. See the [activation record](cloudflare-deployment.md#woven-bamboo-login-gate-activation-2026-10-01) for the exact source/version and qualification limits. The following record describes the preceding seal release.

The seal was activated in production on 2026-09-30. [Public smoke](https://github.com/masanork/mikaki/actions/runs/36688517696) matched both served login asset hashes and the clean source/version identity, with readiness 204. See the [activation record](cloudflare-deployment.md#procedural-login-seal-activation-2026-09-30) for the versions and verification limits.

The shared woven-fence logo introduced by PR #34 remains in the native icons, favicon and other page marks, using [one SVG source](../branding/mikaki-mark.svg). The login gate has no separate brand header.

Login-only rules are scoped to `.auth-shell`. Shared typography, box sizing and brand sizing live in `product.css`, so the Vault, completion and logout pages retain their layouts.

The direct `/` entry uses the same material and lighting as a single fence; see [direct issuer preview](home-ui-preview.md).
