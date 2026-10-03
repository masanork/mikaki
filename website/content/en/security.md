---
type: article
profile: sorane-okf/0.1
title: 'mikaki security and OpenID, FAPI and FIDO status'
description: 'Passkey authentication and encrypted Vault data, OpenID Connect, FAPI 2.0 and FIDO2 test evidence, certification status and checks before adopting mikaki.'
lang: en
translation_key: security
updated: 2026-10-03
---

mikaki is an open source project developing passkey authentication and an encrypted Vault. **It has not obtained formal OpenID, FAPI or FIDO certification.** This page explains the scope of published test evidence and the limitations to check before use.

## Passkey authentication

mikaki authenticates with WebAuthn passkeys. Its login screen identifies the destination application. Use [Web sign-in](https://auth.mikaki.org/signin?lang=en) directly, or start application login from the application you want to use.

Ordinary authentication and Vault unlocking are separate operations; decryption requires the corresponding supported passkey and PRF. Read the [passkey guide](passkeys.md) for device changes and unlock troubleshooting.

## Vault and sharing

The Owner Vault is being developed to store encrypted names and notes. Attribute release to applications and AI exports have separate consent steps. Device compatibility, recovery and operational qualification still have open work.

The server stores ciphertext and operational metadata such as item types and update times. Consented sharing lets a selected recipient decrypt the disclosed data. Downloaded plaintext files and data already delivered to a recipient cannot be recalled.

Read [Using Vault](vault.md) for saving, sharing and transfer limitations. Recovery after losing every usable unlock method and compatibility with every real device are not guaranteed. The design is in the [Vault documentation](https://github.com/masanork/mikaki/blob/main/docs/personal-vault.md).

## What OpenID, FAPI and FIDO cover

| Specification or certification target | Scope to check in mikaki |
| --- | --- |
| OpenID Connect | Authentication responses, code exchange and ID Tokens for application login |
| FAPI 2.0 Security Profile | Authorization, token issuance and use for APIs with high security requirements |
| FIDO2 Server | Server verification of passkey registration and authentication |

These targets differ. A successful passkey login or a test run without failures does not establish another profile's conformance, certification or Vault recovery. Distinguish the local FAPI configuration from the normal [Web application integration](integration.md) configuration.

## Conformance and certification

These are dated development and local test records for specific configurations. They do not qualify the current production deployment under the same certification profiles.

**OpenID Connect — September 29, 2026:** Config OP finished PASSED. Basic OP finished with 22 PASSED, 4 REVIEW, 8 SKIPPED, 1 WARNING and 0 FAILED in an isolated conformance deployment using HTTPS and Chromium virtual passkeys. See the [OIDC scope and evidence](https://github.com/masanork/mikaki/blob/main/docs/oidf-conformance-2026-09-29.md).

**FAPI 2.0 — September 30, 2026:** The selected isolated Final AS profile completed 52 modules with 45 PASSED, 4 REVIEW, 3 SKIPPED, 0 FAILED and none unfinished. It used private-key client authentication, PAR to push authorization requests in advance, and DPoP to bind token use to a sender key. Human review, production-edge TLS and independent client/resource-server qualification remain separate work. See the [FAPI run record](https://github.com/masanork/mikaki/blob/main/docs/fapi2-conformance-2026-09-30.md) and [readiness details](https://github.com/masanork/mikaki/blob/main/docs/fapi2-readiness.md).

**FIDO2 Server — September 29, 2026:** Development runs with Tools 1.9.2 recorded 167 passes and 0 failures each for isolated native and Wasm adapters. Their test configuration supports broader algorithms and attestation than the normal product configuration. These are not official submission results. The MDS profile was `mds3.0`; the tool's ES256K case remained pending and unexecuted. See the [certification preparation and scope](https://github.com/masanork/mikaki/blob/main/docs/webauthn-certification-readiness.md).

## Reading results and remaining gaps

`REVIEW` needs human assessment; `SKIPPED` was not executed for the selected configuration. Neither is counted as PASSED. `WARNING` also remains a separate result.

The remaining FAPI reviews cover direct authorization without PAR and reused, expired or wrong-client references. Skipped optional capabilities include additional claims selection and refresh tokens. An application that needs those features requires additional implementation and qualification.

Virtual passkeys and test adapters cannot establish compatibility with every real device. The [device evidence](https://github.com/masanork/mikaki/blob/main/docs/webauthn-device-compatibility.md) distinguishes observed operations from untested operating systems, browsers and authenticators. FIDO2 preparation also requires freezing the submitted version/configuration, checking MDS requirements and completing interoperability testing.

## Certification programs

The OpenID Foundation provides [conformance tests and certification](https://openid.net/certification/). Running tests and obtaining certification are separate steps. Its [open source fee waiver policy](https://openid.net/certification/open-source-project-certification-policy/) has conditions, including whether primary maintainers are compensated by an employer for their project work, and requests are assessed individually. Open source status alone does not establish certification or a fee waiver. Check the current [official fee schedule](https://openid.net/certification/fees/).

The FIDO Alliance's [FIDO2 Server certification](https://fidoalliance.org/certification/functional-certification/functional-certification-servers/) requires self-validation, interoperability testing and submission. It is a separate program with its own [fees and conditions](https://fidoalliance.org/fido-certification-fees/).

## Before adopting mikaki

1. Check login and saved Vault unlocking separately on the actual device, browser and passkey provider you intend to use.
2. Reopen items on the destination before giving up the original device. Keep copies of information you cannot afford to lose and check the recovery procedure.
3. From the actual connected application, test registered callbacks, session checks, revocation, logout and OP outages.
4. If certification is an adoption requirement, check the required product, version and profile. These development records alone do not meet that requirement.

The [source code](https://github.com/masanork/mikaki) and [session limitations](https://github.com/masanork/mikaki/blob/main/docs/session-lifecycle.md) describe implementation details and open work.

## Read next

- [Getting started](getting-started.md): After reviewing the limits, follow registration and Web-use instructions.
- [Application integration guide](integration.md): Review connection steps and validation for your intended setup.
