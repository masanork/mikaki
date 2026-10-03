---
type: article
profile: sorane-okf/0.1
title: 'mikaki invitation and application integration requests'
description: 'Find the GitHub request forms, information needed for invitations and application registration, private delivery steps and the path from a request to evaluation.'
lang: en
translation_key: contact
updated: 2026-10-03
---

Use the **dedicated GitHub issue forms** to ask about trying mikaki or connecting an application. A GitHub account is required and requests are public. The project is experimental; opening a request does not itself issue an invitation or register a client.

## If you do not have an invitation

Use the [invitation request form](https://github.com/masanork/mikaki/issues/new?template=invitation-request-en.yml). Describe what you want to try and, if known, your OS and browser. You do not need to publish your name, email or device identifiers.

If the request can be accommodated, arrange a separate private delivery channel with an administrator. Invitation codes are not posted to public issues. After receiving a code, follow [Getting started](getting-started.md) to enroll a passkey on your own device.

Already invited? Open the [registration page](https://auth.mikaki.org/enroll?lang=en). For an expired code or uncertain registration result, describe the situation without posting the code. If the registration response was lost, first check whether you can sign in with the newly created passkey.

## Developers connecting an application

Use the [application integration form](https://github.com/masanork/mikaki/issues/new?template=integration-request-en.yml) with information suitable for publication:

- Application name and purpose, such as login or attribute retrieval.
- Server-side Web application or native public client.
- Public HTTPS origin, proposed callback, and needed logout return/notification URLs.
- For a Web client, whether you can provide an RP-specific ES256 public JWK.

The callback is a configuration URL. Never paste an actual login callback carrying code/state queries. For private URLs or configuration, state only that details need a private channel. Keep private keys in the application; do not send them.

After discussing the target origin, exact destinations and public key, an administrator registers the client. This is separate from user invitations/passkey enrollment. Then follow the [integration guide](integration.md) and qualify code exchange, session checks, revocation and logout from your application.

## From request to evaluation

1. Submit the purpose and configuration you may publish.
2. Review scope and missing information, arranging a private delivery channel if needed.
3. After administrator invitation/client registration, evaluate from your device/application.

Unrestricted signup, response deadlines and activation dates are not guaranteed. Read [service information](operations.md) and [status](security.md), and evaluate with synthetic data.

## Bugs and vulnerabilities

Report ordinary bugs through [GitHub Issues](https://github.com/masanork/mikaki/issues), without invitation codes, private keys, tokens, personal information or Vault contents.

For vulnerabilities, follow the [private reporting procedure in SECURITY.md](https://github.com/masanork/mikaki/blob/main/SECURITY.md), rather than using invitation/integration forms. If private reporting is unavailable, a public issue should only request a private channel.

## Read next

- [Getting started with screenshots](getting-started.md): Follow registration and login after receiving an invitation.
- [Application integration](integration.md): Check implementation and qualification after client registration.
