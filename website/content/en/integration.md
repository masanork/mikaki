---
type: article
profile: sorane-okf/0.1
title: "Connect your application to mikaki"
description: "Developer guidance for integrating mikaki passkey authentication using OpenID Connect."
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

## Integration steps

1. Register your client and exact callback URL.
2. Start login from your application and check its destination on the mikaki screen.
3. Exchange the authorization code and validate the ID Token.

See the [RP integration guide](https://github.com/masanork/mikaki/blob/main/docs/rp-integration.md) and [client registration instructions](https://github.com/masanork/mikaki/blob/main/docs/rp-client-operations.md) for details.

Read [security and implementation status](security.md) before adopting mikaki.
