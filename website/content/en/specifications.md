---
type: article
profile: sorane-okf/0.1
title: 'mikaki specifications and supported standards'
description: 'Public IdP discovery, client profiles, signature algorithms, claims, logout, and the distinct deployment and test scopes of DPoP and FAPI.'
lang: en
translation_key: specifications
updated: 2026-10-03
---

This reference describes connecting to the public mikaki IdP. **Discovery advertisements, registered-client conditions and isolated test configurations have different scopes.** The service is experimental and has no formal certification.

## Public IdP specifications

The [public Discovery document](https://auth.mikaki.org/.well-known/openid-configuration) was checked on October 3, 2026. Fetch current metadata when integrating and verify its issuer against your configured issuer.

| Property | Advertised value |
| --- | --- |
| Issuer | `https://auth.mikaki.org` |
| Authentication flow | Authorization Code, `response_type=code` |
| Response mode | `query`, with authorization-response issuer identification |
| Grant | `authorization_code` |
| PKCE | `S256` |
| Subject type | `pairwise` |
| Scopes | `openid`, `profile` |
| ID Token signatures | `ES256`, `RS256` |
| Token endpoint client authentication | `private_key_jwt`, `none` |
| Client assertion signatures | `ES256` |
| DPoP proof signatures | `ES256` |

RS256 ID Token support does not imply RS256 client assertions. Normal server-side Web clients use ES256 `private_key_jwt`. The `none` method is subject to registered public-client conditions, such as those for a native client; it does not permit unrestricted registration or access.

## Client profiles

**Server-side Web application:** Ask an administrator to register the client ID, exact HTTPS redirect URI and public JWK. Keep the private key on the application server. Use Code with S256 PKCE, state, nonce, ID Token validation and session checks. The [integration guide](integration.md) covers this profile.

**Native application:** Use a registered public client, PKCE and an application-associated callback. Do not embed a server private key. [Android ordinary OIDC login evidence](https://github.com/masanork/mikaki/blob/main/docs/native-client-activation.md) exists; iPhone, distribution readiness and native Vault consent/unlocking remain separate qualification work.

## Standards and scope

| Standard or specification | Deployment or verification scope |
| --- | --- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) / [Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | Public Code flow, ID Tokens, UserInfo and Discovery; local OP test evidence |
| [PKCE — RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) | S256 code exchange |
| [JWT client authentication — RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) / OIDC `private_key_jwt` | ES256 assertions matching registered public keys |
| [Authorization Response Issuer — RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) | Advertised response `iss`; the RP must check its pinned issuer |
| [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | `/logout`, confirmation and registered return destinations |
| [Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Session-based notifications advertised; RP receipt and validation required |
| [WebAuthn](https://www.w3.org/TR/webauthn-3/) / FIDO2 | Passkey registration/authentication. Vault decryption separately requires PRF and device support |
| [DPoP — RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) | ES256 advertised. Check the actual client/resource conditions and qualification |
| [PAR — RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html) / [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html) | Isolated Final AS tests. Normal public Discovery has no PAR endpoint; this is not production FAPI certification |

This table does not claim every option of each standard. OID4VCI and OID4VP have bounded tests of separate components and are not counted as generally available public IdP features. See the [conformance results](conformance.md) for targets and verdicts.

## Claims and attribute release

Advertised claims are `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `sid` and `acr`. The advertised authentication context is `urn:mikaki:acr:passkey-uv`. Optional claims are not promised in every response.

Subjects are pairwise. Do not assume identifiers from different clients/sectors match, or automatically merge accounts by email. The `profile` scope alone does not promise a name or email. Releasing a Vault name additionally requires owner consent, client release configuration and operational policy.

## Unsupported requests and extensions

The checked metadata advertises no refresh-token grant and marks `request`, `request_uri` and `claims` parameters unsupported. Check whether your SDK requires them before assuming compatibility. Administrators manage client registration.

`/session/check` is a mikaki extension for RP session validity and expiry. It is not OIDC Session Management or OAuth token introspection, and does not accept Access Tokens as its authentication method. An RP cookie, OP SSO and Vault unlocking are separate states.

## Read next

- [Conformance results](conformance.md): Check versions, test environments, reviews and unexecuted cases.
- [Application integration](integration.md): Implement registration, login and managed session checks.
