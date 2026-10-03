# Mobile experience and keyboard review

Measured on 2026-10-03 using disposable local accounts and the actual Rust OP/UI bundles. This review improves two bounded problems: serial Vault metadata reads and lost keyboard focus after asynchronous actions. It does not qualify physical devices or audible screen-reader output.

## Paired performance measurement

`npm run probe:ui-experience` runs Playwright/Chromium over a real loopback HTTPS bridge. Responses come from the local Rust Worker, with declared gzip level 6 compression and cache disabled. It does not use intercepted browser responses for network measurements. Chrome DevTools MCP was unavailable; Playwright's Chrome DevTools Protocol sessions provided network/CPU controls and accessibility-tree inspection instead.

The paired comparison used Chromium 153.0.8010.12 on the same macOS host, the same fixture origin (`https://mikaki.test:19443`), and three fresh browser contexts per screen/condition. Desktop uses 1440×900 with no throttling. Mobile uses 390×844, touch/DPR 2, CPU throttling 4×, 400 ms latency and 50,000 bytes/s upload/download. A third condition repeats mobile with reduced motion enabled. These are emulated conditions, not measurements from an actual phone or Cloudflare edge.

The [measurement JSON](ui-experience-measurements.json) preserves individual samples, timestamps, conditions, source state and hashes of served assets. Both paired builds used a dirty `5d8a9ee` base with the focus improvements; the comparison isolates parallel reads and offscreen animation suspension. The improved build additionally includes login focus recovery. After this comparison, the branch incorporated the subsequently merged note-validation/readiness/documentation changes from main; browser checks validate that integrated version separately.

Values below are medians of three samples. “Ready” is when the sign-in/profile unlock button is detected enabled, measured from navigation start; polling overhead is included. It does not include a real authenticator ceremony.

| Condition / screen | Ready before → after | FCP before → after | LCP before → after | CLS, both |
| --- | --- | --- | --- | --- |
| Desktop / sign-in | 507 → 482 ms | 508 → 484 ms | 508 → 484 ms | 0 |
| Desktop / Vault | 141 → 143 ms | 120 → 116 ms | 120 → 116 ms | 0 |
| Slow mobile / sign-in | 2,395 → 2,398 ms | 2,348 → 2,352 ms | 2,348 → 2,352 ms | 0 |
| Slow mobile / Vault | 4,432 → 3,943 ms | 2,592 → 2,624 ms | 2,592 → 2,624 ms | 0 |
| Reduced-motion mobile / sign-in | 2,371 → 2,402 ms | 2,348 → 2,384 ms | 2,348 → 2,384 ms | 0 |
| Reduced-motion mobile / Vault | 4,430 → 3,913 ms | 2,600 → 2,596 ms | 2,600 → 2,596 ms | 0 |

After verifying the owner session, profile sharing status, release status and encrypted name are fetched concurrently. All three settle before the loading state clears; optional-panel errors remain isolated and writes keep their existing serialization. Slow-mobile profile readiness improves by approximately 0.49 seconds (11%). A browser response barrier checks that all three requests start without waiting for another response; it fails with the previous serial implementation.

When the decorative header leaves the viewport, the woven renderer stops its animation loop and resumes on return. In a two-second offscreen window, normal-motion light updates fell from 40 to 0 on both desktop and mobile. Median offscreen script time fell from 4.75 to 0.12 ms on desktop and 9.19 to 0.08 ms on mobile. Reduced-motion cases already had zero light updates and retain that behavior. These small lab CPU observations do not establish device battery savings.

Visible motion, origin-derived weave/color, and pointer lighting remain. Sign-in rendering is essentially unchanged; initial material generation still produces long main-thread tasks. The two-second window immediately after Vault readiness includes outstanding panel work: its mobile script time increased from 7.91 to 33.34 ms as work moved earlier. This is not a claim that all idle CPU work decreased. Resource timing, paint, maximum-session-window CLS, long tasks and bounded interaction samples are recorded; interaction samples are **not field INP**. No noisy wall-clock threshold has been added to CI.

To repeat after building the Worker and generating policy/catalog fixtures:

```sh
npm run probe:ui-experience
# Optional: fixed origin and 1–5 repeats for controlled comparisons.
MIKAKI_UI_PROBE_PORT=19443 MIKAKI_UI_PROBE_REPEATS=3 MIKAKI_UI_PROBE_LABEL=current npm run probe:ui-experience
```

The probe writes `artifacts/ui-experience/report.json`, representative screenshots, and accessibility snapshots. It uses synthetic PRF output, cancels automatic sign-in and never contacts production. Do not run this fixture recorder against real user sessions.

## Keyboard and browser semantics

After an explicit action changes disabled/removed controls, a shared helper waits for the DOM update and restores focus to the useful next control. It skips hidden documents, detached/inert/disabled targets and preserves focus when the user moved elsewhere during the operation. Automatic sign-in does not acquire focus.

Browser regressions cover:

- Profile Passkey cancellation returns focus to unlock; keyboard retry opens the name field.
- Note unlock opens the title field. Moving to a navigation link while Passkey is pending preserves that link's focus.
- Uncertain profile/note saves focus the retry button; successful exact retries focus unlock. Existing write identity and conflict checks remain.
- Manual lock focuses the locked heading; keyboard reopening focuses main, then Tab continues to Profile navigation.
- Missing invitation focuses the invitation field. Existing note validation focuses the invalid field before requesting Passkey or sending a write.
- Japanese/English product screens have no horizontal overflow at 320, 390 and 1440 pixels. The measurement probe additionally checks mobile sign-in/Vault overflow.

The Chrome accessibility-tree audit checks accessible names on buttons, links, inputs, headings and disclosure controls; exactly one active main landmark; unique IDs; and valid `aria-labelledby`/`aria-describedby` references. Snapshots include live/atomic/focused/disabled/invalid properties. Coverage includes Japanese sign-in and invitation error, Japanese/English Vault, administration, completion and logout, plus locked Vault. Existing alerts/status regions remain the announcement mechanism; no extra user-facing text was added.

The deterministic keyboard, request-barrier, offscreen pause/resume and browser-semantic assertions run with the existing Worker browser suites. `test:vault-notes` additionally checks note focus and validation. CI uploads accessibility snapshots with its existing measurement artifacts.

Local validation after integrating main: `test:worker-browser` passed 17 tests, `test:vault-notes` passed 3 tests, and `test:frontend-coverage` passed 13 tests plus the existing five-module regression gate. `check:node`, `check:worker-ui` (zero errors/warnings), `check:worker-budgets`, `check:docs` and `format:check` passed. The release Worker build succeeded. These results are local; remote PR CI is separate.

### Reload recovery follow-up

Explicit profile/note reloads also restore focus after their controls are disabled: another failed read returns to the reload button; a successful read focuses unlock/open. Initial automatic note loading does not move focus. Regression checks reproduce focus loss with the previous implementation, then exercise repeated read failure and recovery using Enter, as well as initial automatic loading with focus still on the document body. Draft-discard confirmation, data/retry handling and the existing protection against stealing moved focus remain in place. This is browser keyboard evidence, not audible assistive-technology qualification.

Note read failures now use note-specific Japanese/English messages instead of incorrectly referring to the display name. The retry test waits for that failure status before checking focus and retrying.

## Remaining qualification

VoiceOver/TalkBack speech, OS Passkey dialogs, real iPhone/Safari and Android behavior, synced credentials, device tilt and physical-device performance remain unqualified. Browser semantics and synthetic PRF do not substitute for those checks. The assistive-technology and intended-device activation gates remain open in [product quality](product-quality.md). Production transport compression, edge caching, field Web Vitals and sustained battery/thermal behavior require separate measurement.
