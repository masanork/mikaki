# WebAuthn browser and authenticator compatibility

**WG-06, 2026-09-23.** Virtual-authenticator automation and a person's operation of a real authenticator are different evidence. FIDO Server Conformance is not a browser/device compatibility test.

| Host | Browser | Authenticator | Recorded result |
| --- | --- | --- | --- |
| MacBook Air M3 (Mac15,13), macOS 27.0 (26A428) | Playwright Chromium 153.0.8010.12 headless | CDP virtual internal CTAP2.1 with simulated resident key, UV, and user presence | 49 integration tests passed; resident property and discoverable re-login checked. Not real hardware evidence. |
| Same host | Chrome 154.0.8037.58 headless | Same CDP virtual authenticator | 49 passed; no physical backup/counter behavior tested. |
| Same host | Chrome Canary 156.0.8068.0 headless | Same CDP virtual authenticator | 49 passed; no physical backup/counter behavior tested. |
| Same host | Safari 27.0 (22625.1.29.11.27) | macOS Touch ID/platform authenticator | Untested; requires visible GUI and biometric interaction. |

The virtual authenticator always simulated UV. Core counter behavior was tested separately with fixtures, not with physical backup/sync behavior. An SPUSB/SPBluetooth inventory did not identify a named external FIDO device, which is not proof none was attached.

`slice.test.mjs` uses Playwright Chromium by default and `WebAuthn.addVirtualAuthenticator` for resident-key/UV capable CTAP2.1. Set `MIKAKI_BROWSER_CHANNEL=chrome` or `chrome-canary` before `npm run test:e2e` to select another Chrome channel. Each run uses disposable loopback issuer/RP/DB. Tests cover invitation enrollment, `credProps.rk`, discoverable passkey login and relogin, UV, code exchange, WebAuthn response checks, OIDC, and sessions. CDP makes them repeatable but does not reproduce biometric UI, OS permissions, passkey sync, USB/NFC/Bluetooth, or hardware firmware.

A headed Chrome Touch ID attempt on 2026-09-23 did not display a usable window/prompt and was not completed. It was excluded from automated results and is not evidence of real-device compatibility.

| Real platform / authenticator | Browser | Status |
| --- | --- | --- |
| macOS Touch ID / iCloud Keychain sync | Safari, Chrome | Untested |
| iPhone/iPad built-in authenticator and sync | Safari | No device; untested |
| Android platform authenticator and sync | Chrome | No device; untested |
| Windows Hello | Edge, Chrome | No device; untested |
| External USB/NFC FIDO2 key | Chrome, Safari, Firefox | Device not confirmed; untested |

Only Chrome-family virtual-authenticator automation is recorded. Do not generalize it to physical product compatibility or browser differences.
