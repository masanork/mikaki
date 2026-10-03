---
type: article
profile: sorane-okf/0.1
title: 'mikakiの仕様・対応標準 — OpenID Connectとパスキー'
description: '公開IdPのDiscovery、クライアント種別、署名方式、claims、ログアウト、DPoPとFAPIの提供・試験範囲を確認できます。'
lang: ja
translation_key: specifications
updated: 2026-10-03
---

mikakiの公開IdPに接続するための仕様一覧です。**公開Discoveryで広告する機能、登録済みクライアントの条件、分離環境の試験を区別します。** 実験的な提供であり、正式認定は取得していません。

## 公開IdPの諸元

2026年10月3日に[公開Discovery](https://auth.mikaki.org/.well-known/openid-configuration)を確認しました。接続時は最新のDiscoveryを取得し、設定したissuerと一致することを検証してください。

| 項目 | 公開Discoveryの値 |
| --- | --- |
| Issuer | `https://auth.mikaki.org` |
| 認証フロー | Authorization Code、`response_type=code` |
| 認証応答 | `query`、応答のissuer識別をサポート |
| Grant | `authorization_code` |
| PKCE | `S256` |
| Subject | `pairwise` |
| Scope | `openid`、`profile` |
| ID Tokenの署名 | `ES256`、`RS256` |
| Token endpointのクライアント認証 | `private_key_jwt`、`none` |
| Client assertionの署名 | `ES256` |
| DPoP proofの署名 | `ES256` |

ID TokenのRS256対応と、client assertionの署名方式は別です。通常のサーバー側WebアプリはES256の`private_key_jwt`を使います。公開クライアントの`none`は、登録したネイティブクライアントなどの条件に従う方式で、誰でも自由に接続・登録できることを意味しません。

## クライアントごとの接続条件

**サーバー側Webアプリ：** 管理者にclient ID、完全一致するHTTPSのredirect URI、公開JWKを登録してもらいます。秘密鍵はアプリのサーバーだけで保管します。Code＋S256 PKCE、state、nonce、ID Token検証とセッション確認が必要です。[アプリ連携ガイド](integration.md)がこの構成を説明します。

**ネイティブアプリ：** 秘密鍵を埋め込んだWebアプリと同じ構成にしません。登録済み公開クライアントとPKCE、アプリに対応付けたコールバックを使います。Androidでの通常OIDCログインの[検証記録](https://github.com/masanork/mikaki/blob/main/docs/native-client-activation.md)がありますが、iPhone、配布版、native Vaultの同意・解錠は別の検証項目です。

## 対応標準と確認範囲

| 標準・仕様 | 提供または検証の範囲 |
| --- | --- |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) / [Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | 公開IdPのCodeフロー、ID Token、UserInfo、Discovery。OPのローカル試験記録あり |
| [PKCE — RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html) | S256のコード交換 |
| [JWT client authentication — RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html) / OIDC `private_key_jwt` | 登録済み公開鍵に対応するES256 assertion |
| [Authorization Response Issuer — RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html) | 認証応答の`iss`を広告。RPでも固定issuerと照合 |
| [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) | `/logout`。登録済み戻り先と確認画面 |
| [Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | セッション単位の通知を広告。RP側の受信・検証が必要 |
| [WebAuthn](https://www.w3.org/TR/webauthn-3/) / FIDO2 | パスキー登録・本人認証。Vault解錠には別途PRFと対応端末が必要 |
| [DPoP — RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html) | ES256をDiscoveryで広告。対象クライアント・リソースの利用条件と検証が必要 |
| [PAR — RFC 9126](https://www.rfc-editor.org/rfc/rfc9126.html) / [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html) | 分離したFinal AS構成の試験あり。通常の公開DiscoveryにはPAR endpointがなく、本番FAPI認定を示すものではない |

表は各標準の全オプション対応を表すものではありません。OID4VCI・OID4VPは独立した試験用コンポーネントの限定検証で、公開IdPの一般提供機能には数えていません。[試験結果一覧](conformance.md)で対象と結果を確認できます。

## Claimsと属性提供

Discoveryの`claims_supported`は`iss`、`sub`、`aud`、`exp`、`iat`、`nonce`、`auth_time`、`sid`、`acr`です。広告する認証コンテキストは`urn:mikaki:acr:passkey-uv`です。任意claimがすべての応答に常に含まれることを意味しません。

`sub`はpairwiseです。別クライアント・sectorのユーザー識別子を同一と仮定したり、メールアドレスで自動的にアカウントを統合したりしないでください。`profile` scopeだけで名前やメールの取得を約束するものでもありません。Vaultの名前の開示には別途、本人の同意、クライアントの属性提供設定、運用ポリシーが必要です。

## 対応外の要求と独自機能

確認したDiscoveryにはrefresh token grantがありません。`request`、`request_uri`、`claims`パラメーターは非対応として広告されています。利用したいSDKがこれらを必須にする場合は、そのまま接続できると判断しないでください。クライアント登録は管理者の手順で行います。

`/session/check`はRPのセッション有効性と期限を確認するmikaki独自APIです。OIDC Session ManagementやOAuth token introspectionと同じAPIではなく、Access Tokenを送る場所でもありません。RP自身のCookieと、OPのSSO、Vaultの解錠状態もそれぞれ別です。

## 次に読む

- [試験結果一覧](conformance.md)：版、試験環境、REVIEWや未実行項目を確認します。
- [アプリ連携ガイド](integration.md)：登録からログイン・セッション確認までを実装します。
