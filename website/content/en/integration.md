---
type: article
profile: sorane-okf/0.1
title: 'Connect your application to mikaki'
description: 'Developer guidance for integrating mikaki passkey authentication using OpenID Connect.'
lang: en
translation_key: integration
updated: 2026-10-02
---

## Connect using OpenID Connect

mikaki acts as an OpenID Connect Provider (OP). Applications act as Relying Parties (RPs), using the Authorization Code flow with PKCE S256.

Discover endpoints and the signing key URL from:

```
https://auth.mikaki.org/.well-known/openid-configuration
```

The normal integration uses the `openid` scope and ES256 `private_key_jwt` client authentication. An administrator registers clients in advance.

## What to register

Use a separate client for each environment. Provide the operator with the application name, hostname, exact HTTPS callback URLs and an ES256 public JWK with its key ID. Keep the private key in your backend; do not send it to mikaki. Public dynamic client registration is unavailable.

This guide is for a Web application backend that holds a private signing key. Native public clients have separate registration, authentication and callback rules.

## Integration steps

1. Register your client and exact callback URL.
2. Start login from your application and check its destination on the mikaki screen.
3. Exchange the authorization code and validate the ID Token.

Generate `state`, `nonce` and PKCE values for each login and bind them to the browser transaction. Check state and issuer on callback before exchanging the code in your backend. Validate the ID Token's signature, issuer, audience, expiry and nonce, and map `sub` to an application-local user. The subject is not an email address.

## Sessions and logout

Managed RPs call `/session/check` from their backend when creating a session and when a protected request arrives after the validation lease expires. This is a mikaki-specific extension. It requires a fresh client assertion for that endpoint; a token-exchange assertion cannot be reused.

Register logout destinations separately. Implement Back-Channel Logout and session checks, including the case where a notification is lost or the OP is unavailable. Manage your own application's session cookie; do not share mikaki's cookie.

## Current integration scope

The normal production scope is `openid`. Name release has separate consent, operational settings and qualification requirements; ordinary login does not provide the Vault name or note. Do not assume support for the `email` scope, dynamic registration or general FAPI integration.

Registration alone does not establish interoperability. Test code exchange, invalid state/nonce/PKCE/signatures, replay, revocation, logout and OP outage from the actual application. [Implementation status](security.md) distinguishes local test evidence from certification.

See the [RP integration guide](https://github.com/masanork/mikaki/blob/main/docs/rp-integration.md) and [client registration instructions](https://github.com/masanork/mikaki/blob/main/docs/rp-client-operations.md) for details.

Read [security and implementation status](security.md) before adopting mikaki.
