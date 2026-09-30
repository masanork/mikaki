# WebAuthn browser and authenticator compatibility

**WG-06, 2026-09-23.** Virtual-authenticator automation and a person's operation of a real authenticator are different evidence. FIDO Server Conformance is not a browser/device compatibility test.

| Host | Browser | Authenticator | Recorded result |
| --- | --- | --- | --- |
| MacBook Air M3 (Mac15,13), macOS 27.0 (26A428) | Playwright Chromium 153.0.8010.12 headless | CDP virtual internal CTAP2.1 with simulated resident key, UV, and user presence | 49 integration tests passed; resident property and discoverable re-login checked. Not real hardware evidence. |
| Same host | Chrome 154.0.8037.58 headless | Same CDP virtual authenticator | 49 passed; no physical backup/counter behavior tested. |
| Same host | Chrome Canary 156.0.8068.0 headless | Same CDP virtual authenticator | 49 passed; no physical backup/counter behavior tested. |
| Same host | Safari 27.0 (22625.1.29.11.27) | macOS Touch ID/platform authenticator | Untested; requires visible GUI and biometric interaction. |

The virtual authenticator always simulated UV. Core counter behavior was tested separately with fixtures, not with physical backup/sync behavior. An SPUSB/SPBluetooth inventory did not identify a named external FIDO device, which is not proof none was attached.

`slice.test.ts` uses Playwright Chromium by default and `WebAuthn.addVirtualAuthenticator` for resident-key/UV capable CTAP2.1. Set `MIKAKI_BROWSER_CHANNEL=chrome` or `chrome-canary` before `npm run test:e2e` to select another Chrome channel. Each run uses disposable loopback issuer/RP/DB. Tests cover invitation enrollment, `credProps.rk`, discoverable passkey login and relogin, UV, code exchange, WebAuthn response checks, OIDC, and sessions. CDP makes them repeatable but does not reproduce biometric UI, OS permissions, passkey sync, USB/NFC/Bluetooth, or hardware firmware.

A headed Chrome Touch ID attempt on 2026-09-23 did not display a usable window/prompt and was not completed. It was excluded from automated results and is not evidence of real-device compatibility.

| Real platform / authenticator | Browser | Status |
| --- | --- | --- |
| macOS Touch ID / Google Password Manager | Chrome 154 | Registration, identified and discoverable authentication passed on 2026-09-29; sync/counter/backup behavior not established |
| macOS Touch ID / iCloud Keychain sync | Safari | Untested |
| iPhone/iPad built-in authenticator and sync | Safari | No device; untested |
| Android platform authenticator and sync | Chrome | No device; untested |
| Windows Hello | Edge, Chrome | No device; untested |
| External USB/NFC FIDO2 key | Chrome, Safari, Firefox | Device not confirmed; untested |

The original automation record covered only Chrome-family virtual authenticators. The physical follow-up below provides separate evidence; do not generalize either to untested devices or browsers.

## Operator hand-off, 2026-09-29

A visible Chrome tab at `http://localhost:8083/device` is prepared for physical operation. [device.html](../local/conformance/device.html) requests ES256, resident credentials and required UV with `none` attestation. It verifies registration, identified authentication and a separate discoverable authentication through the Wasm HTTP server. The operator creates the passkey and completes biometric/PIN prompts. Select the platform option for Touch ID/Windows Hello, or the unrestricted option for a key/phone.

The operator run on this Mac, Chrome 154, returned `server verified` for platform registration, algorithm -7, transports `hybrid` and `internal`, required UV and resident key (2026-09-29 07:13 JST). Identified authentication succeeded at 07:18 JST; discoverable authentication succeeded at 07:21:54 JST with `selected_registered_credential: true`. The user completed the Touch ID continuation. [Combined downloaded records](../local/conformance/device-results-2026-09-29.json) preserve the earlier pre-verification rejections as well as the successes.

The Chrome picker displayed two earlier `admin` credentials, a `demo-admin-...` credential and the current `device-1790633556933`. Explicit selection of the current credential resolved the discoverable attempt. Earlier attempts did not record which credential was selected, so their exact choice is not established. The page now scopes identified candidates to the test name and checks whether a discoverably selected credential belongs to it, displaying a useful error for an unrelated localhost passkey. These browser checks assist diagnosis; server verification remains required.

The observed platform UI was Google Password Manager with Touch ID continuation, not proof of iCloud Keychain storage or sync. A user-agent reporting `Mac OS X 10_15_7` does not establish the installed OS version. Hardware counter/backup/sync behavior, Safari, other operating systems and external keys remain separate tests.

The downloadable JSON records time, browser, attachment, algorithm, transports, status and duration without raw credential IDs, signatures or public-key payloads. Record the actual device/model and browser version alongside it. `platform`/`internal` does not independently establish a particular device model or Android Key hardware provenance.

The server is loopback-only. A separate phone/Windows computer needs an explicitly prepared secure reachable RP; this setup does not publish the test API. Other devices remain untested until actual results are recorded.
