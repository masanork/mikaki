# Login UI preview

These images use the actual Worker UI bundle and a synthetic `mikaki-helpdesk-local` connection. Authentication and transaction data are mocked.

| Sign in                                  | Registration                                     | Missing invitation                                      |
| ---------------------------------------- | ------------------------------------------------ | ------------------------------------------------------- |
| ![Sign in](login-ui-preview/sign-in.png) | ![Registration](login-ui-preview/enrollment.png) | ![Missing invitation](login-ui-preview/input-error.png) |

[Mobile sign in](login-ui-preview/mobile-sign-in.png) · [English sign in](login-ui-preview/sign-in-en.png) · [Vault and account screens](product-ui-preview.md)

[SVG fallback](login-ui-preview/sign-in-svg.png) · [Reduced motion](login-ui-preview/sign-in-reduced-motion.png)

The login brand panel now uses a procedural SVG seal around mikaki's woven fence mark. The two origins determine its weave; the existing short-lived cue seed changes its rotational phase. Optional WebGL interference light adds depth without image assets, additional dependencies, external requests, or changes to the same-origin CSP. The seed is decorative and is not an authenticity proof.

`LivingSeal.svelte` provides the complete vector fallback; `seal-light.ts` caps the light at 30 fps and 720 pixels with a device-pixel ratio limit of 1.5. The light stops in hidden tabs and during Passkey operations. Reduced-motion preferences disable both vector animation and GPU rendering. Mobile layouts retain the compact domain cue and hide the large seal without initializing WebGL. Allocation/compilation failures and context loss retain the SVG and do not block authentication. Listeners, animation frames, buffers, and programs are disposed on unmount.

[`auth.css`](../crates/worker/ui/auth.css) provides the login styles used by the Rust Worker and local OP. The brand panel and action panel guide the user through checking the connected app, confirming with a Passkey, or registering by invitation. Typography, button priority, labels and errors were informed by the Digital Agency design system's [typography](https://design.digital.go.jp/dads/foundations/typography/), [buttons](https://design.digital.go.jp/dads/components/button/) and [text inputs](https://design.digital.go.jp/dads/components/input-text/); the palette and mark are specific to mikaki.

The visual cue uses the current page URI, validated RP `redirect_uri`, and login-transaction values. Both URIs determine its colors; transaction values also affect tile placement and motion. `/login/cue` checks the transaction against an HttpOnly browser cookie and refreshes the short-lived cue roughly every 20 seconds. A failed refresh preserves the previous cue without blocking login. Reduced-motion preferences disable refresh and animation.

Both domains are displayed, with a prompt to compare the current domain against the address bar. Static copies on another domain change the cue, but page content and cues can be relayed or spoofed; they are not proof of authenticity. The address bar and browser Passkey dialog remain the meaningful domain checks.

To refresh the screenshots, build with `worker-build --release crates/worker`, then run `node docs/login-ui-preview/capture.mjs`. See [quality gates](product-quality.md) for the distinction between synthetic visual evidence and production/intended-device qualification.

The capture uses the login CSP and checks browser exceptions and desktop/mobile horizontal overflow, including forced WebGL unavailability and reduced motion. `node --test local/conformance/worker-ui.test.ts` also checks context-loss fallback and Passkey-operation animation pause. These synthetic Chromium checks do not qualify real-device GPU performance.

The seal was activated in production on 2026-09-30. [Public smoke](https://github.com/masanork/mikaki/actions/runs/36688517696) matched both served login asset hashes and the clean source/version identity, with readiness 204. See the [activation record](cloudflare-deployment.md#procedural-login-seal-activation-2026-09-30) for the versions and verification limits.

The woven-fence logo revision is locally prepared in PR #34; its native icons, favicon and page marks share [one SVG source](../branding/mikaki-mark.svg). The earlier production seal activation above used the four-tile mark. This revision has not been deployed.
