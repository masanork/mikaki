# Login UI preview

These images use the actual Worker UI bundle and a synthetic `mikaki-helpdesk-local` connection. Authentication and transaction data are mocked.

| Sign in | Registration | Missing invitation |
| --- | --- | --- |
| ![Sign in](login-ui-preview/sign-in.png) | ![Registration](login-ui-preview/enrollment.png) | ![Missing invitation](login-ui-preview/input-error.png) |

[Mobile sign in](login-ui-preview/mobile-sign-in.png) · [English sign in](login-ui-preview/sign-in-en.png) · [Vault and account screens](product-ui-preview.md)

[`auth.css`](../crates/worker/ui/auth.css) provides the login styles used by the Rust Worker and local OP. The brand panel and action panel guide the user through checking the connected app, confirming with a Passkey, or registering by invitation. Typography, button priority, labels and errors were informed by the Digital Agency design system's [typography](https://design.digital.go.jp/dads/foundations/typography/), [buttons](https://design.digital.go.jp/dads/components/button/) and [text inputs](https://design.digital.go.jp/dads/components/input-text/); the palette and mark are specific to mikaki.

The visual cue uses the current page URI, validated RP `redirect_uri`, and login-transaction values. Both URIs determine its colors; transaction values also affect tile placement and motion. `/login/cue` checks the transaction against an HttpOnly browser cookie and refreshes the short-lived cue roughly every 20 seconds. A failed refresh preserves the previous cue without blocking login. Reduced-motion preferences disable refresh and animation.

Both domains are displayed, with a prompt to compare the current domain against the address bar. Static copies on another domain change the cue, but page content and cues can be relayed or spoofed; they are not proof of authenticity. The address bar and browser Passkey dialog remain the meaningful domain checks.

To refresh the screenshots, build with `worker-build --release crates/worker`, then run `node docs/login-ui-preview/capture.mjs`. See [quality gates](product-quality.md) for the distinction between synthetic visual evidence and production/intended-device qualification.
