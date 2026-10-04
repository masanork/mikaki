---
type: article
profile: sorane-okf/0.1
title: 'mikakiのOpenID Connectアプリ連携'
description: 'mikakiをWebアプリへ接続する開発者向けガイド。OIDCクライアント登録、PKCE、private_key_jwt、セッション確認と接続失敗時の確認手順を説明します。'
lang: ja
translation_key: integration
updated: 2026-10-03
---

公開IdPへの接続をブラウザーで試す方は、[公開接続デモ](integration-demo.md)へ進めます。
このガイドは、秘密鍵をバックエンドに保管するWebアプリをmikakiへ接続する開発者向けです。管理者への登録依頼、ログインの開始、コード交換、アプリのセッション作成までを説明します。利用者のログイン手順は[はじめ方](getting-started.md)を参照してください。

## OpenID Connectで接続する

mikakiはOpenID Connect Provider（OP）として動作します。連携先アプリはRelying Party（RP）として、Authorization CodeフローとPKCE S256を使ってログインを開始します。

Discovery URLは次のとおりです。

```
https://auth.mikaki.org/.well-known/openid-configuration
```

エンドポイントや公開署名鍵のURLはDiscoveryから取得します。通常の連携では、`openid`スコープとES256の`private_key_jwt`によるクライアント認証を使います。クライアント登録は管理者による事前登録です。

## 登録に必要な情報

環境ごとに別のクライアントを用意し、アプリ名、ホスト名、正確なHTTPSコールバックURL、ES256用の公開JWKとその鍵IDを管理者へ提供します。秘密鍵はアプリのバックエンドに保管し、mikakiへ送らないでください。公開の動的クライアント登録APIはありません。

ネイティブの公開クライアントには別の登録・認証・コールバックのルールがあります。

登録を依頼する前に、[アプリ連携の相談](contact.md)で必要な情報と確認の流れをまとめられます。

## 1. ログインを開始する

ログインごとにランダムな`state`、`nonce`、PKCEの`code_verifier`を生成し、開始時刻とブラウザのトランザクションに結び付けてバックエンドへ保存します。ログイン後の戻り先はアプリ内の検証済みパスに制限してください。

Discoveryの`authorization_endpoint`へ、次の値をURLエンコードして送ります。

| パラメーター | 値 |
| --- | --- |
| `client_id` | 登録されたクライアントID |
| `redirect_uri` | 登録と完全一致するコールバックURL |
| `response_type` / `scope` | `code` / `openid` |
| `state` / `nonce` | このログイン用に生成した値 |
| `code_challenge` | verifierのSHA-256を、末尾の`=`なしのbase64urlで表した値 |
| `code_challenge_method` | `S256` |

利用者のパスキー認証と接続承認はmikakiの画面で行います。アプリがパスキーやmikakiのSSO Cookieを受け取る手順はありません。

## 2. コールバックでコードを交換する

保存したトランザクションと`state`を照合し、応答の`iss`が`https://auth.mikaki.org`と完全一致することを確認します。エラー応答、期限切れ、処理済みのトランザクションではセッションを作成しません。コードをアクセスログへ記録しないでください。

バックエンドからDiscoveryの`token_endpoint`へ、`application/x-www-form-urlencoded`でPOSTします。`grant_type=authorization_code`、受け取った`code`、登録した`redirect_uri`、保存した`code_verifier`、`client_id`、`client_assertion`、`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`を送ります。

クライアントアサーションは、登録した秘密鍵で署名するES256のJWTです。ヘッダーの`kid`は登録した公開鍵に対応させます。`iss`と`sub`はクライアントID、`aud`はDiscoveryから取得したトークンエンドポイントの正確なURLです。要求ごとに新しい`jti`と、運用設定の有効期間に収まる`iat`・`exp`を使います。応答が失われてもコードやJWTを再送せず、新しいログインからやり直してください。

ID TokenはJWKSと許可した署名アルゴリズムで検証し、発行者、対象クライアント、有効期限、発行時刻、送信した`nonce`、必要な`auth_time`を確認します。アプリのユーザーには、発行者と`sub`の組を対応付けます。`sub`はメールアドレスやmikaki共通のアカウントIDではありません。

Access TokenはUserInfo取得用であり、アプリ自身のAPI認可やセッションの有効性確認には使いません。UserInfoを取得する場合は、その`sub`が検証済みID Tokenと一致することを確認します。

## 3. アプリのセッションを作成する

管理対象RPはCookieを発行する前に、バックエンドから`POST https://auth.mikaki.org/session/check`を呼びます。これはmikaki固有の拡張です。JSONで`client_id`、`client_assertion_type`、新しい`client_assertion`、ID Tokenの`sid`を送ります。

| JWTの用途 | `aud`に指定するURL |
| --- | --- |
| コード交換 | Discoveryの`token_endpoint` |
| セッション確認 | `https://auth.mikaki.org/session/check` |

セッション確認用には新しいJWTと`jti`が必要です。トークン交換用のアサーションを再利用できません。`active=true`なら`sub`と`auth_time`をID Tokenと照合し、確認開始時点から測った`lease_ttl`と親SSOの`expires_at`を越えない確認期限を設定します。固定の確認間隔を仮定せず、応答の値を使ってください。

アプリのセッション期限は、応答の`app_idle_timeout`から定まるアイドル期限と親SSOの有効期限のうち早い方に制限します。失効したセッションを、遅れて届いた有効応答で復活させないでください。

アプリ自身のホスト専用Cookieを`Secure`・`HttpOnly`・`SameSite=Lax`で発行します。mikakiとCookieの`Domain`を共有しません。確認期限を過ぎた保護リクエストでは状態を再確認し、OP停止時に期限を延長しないでください。最初の確認に失敗した場合は、新しいセッションを作成できません。

## ログアウトを接続する

ログアウト後の戻り先とBack-Channel Logoutの受信先は別々に登録します。受け取った署名付きログアウト通知を検証し、対応するアプリのセッションを失効させます。通知が届かない場合も、セッション確認の期限を越えて保護操作を続けないことを検証してください。

## 接続できないときの確認順序

1. 発行者・クライアントID・コールバックURLが同じ環境の登録と一致するか確認します。URLのパス、末尾のスラッシュ、クエリも区別されます。
2. コールバックが同じブラウザの未処理トランザクションに対応しているか確認します。`state`や`nonce`を固定値にして動作確認しないでください。
3. コード交換ではPKCEの保存値、鍵の`kid`、JWTの`aud`、時刻と有効期間を確認します。秘密鍵、コード、トークンを診断ログや公開Issueへ貼らないでください。
4. セッション確認では新しいJWTを使っているか、その`sid`が同じクライアントに発行されたものかを確認します。`active=false`を成功扱いにせず、ログインからやり直します。

## 現在の対応範囲

本番連携の基本スコープは`openid`です。名前の属性提供には別の同意・運用設定・検証が必要で、通常のログインだけでVaultの名前やノートを受け取れるわけではありません。`email`スコープ、動的登録、一般的なFAPI対応を提供していると仮定しないでください。

登録完了だけでは動作確認になりません。コード交換に加え、不正な`state`・`nonce`・PKCE・署名、再送、失効、ログアウト、OP停止時の挙動をそのアプリから検証してください。正式認定とローカルのテスト結果は[対応状況](security.md)に分けて掲載しています。

標準の手順は[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)と[PKCE仕様](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2)を参照してください。mikakiの設定と検証の詳細は[RP連携ガイド](https://github.com/masanork/mikaki/blob/main/docs/rp-integration.md)、[クライアント登録手順](https://github.com/masanork/mikaki/blob/main/docs/rp-client-operations.md)、[セッション確認の契約](https://github.com/masanork/mikaki/blob/main/docs/rp-session-check.md)を参照してください。

## 次に読む

- [API reference](api.md)：個々のendpointの要求・応答・エラーを参照します。
- [動かせるローカルRP例](integration-example.md)：登録からログインと失効までの実装を実行します。
