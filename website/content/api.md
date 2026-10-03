---
type: article
profile: sorane-okf/0.1
title: 'mikaki API reference — OIDCとセッション確認'
description: 'Discovery、JWKS、authorize、token、UserInfo、ログアウトとmikaki独自session/checkの要求・応答・認証方法・エラーを説明します。'
lang: ja
translation_key: api
updated: 2026-10-03
---

サーバー側Webアプリ向けのAPI参照です。**登録済みのES256 `private_key_jwt`クライアントと、通常のCode＋S256 PKCE構成**を対象にします。ネイティブ公開クライアント、FAPI、Vault APIは別の契約です。接続全体の順序は[アプリ連携ガイド](integration.md)、実行できる例は[ローカルRP例](integration-example.md)を参照してください。

## エンドポイント一覧

Issuerは`https://auth.mikaki.org`です。標準エンドポイントは[Discovery](https://auth.mikaki.org/.well-known/openid-configuration)から取得し、issuerの完全一致を確認します。以下は2026年10月3日の公開値です。

| メソッド・パス | 用途と認証 |
| --- | --- |
| GET `/.well-known/openid-configuration` | 公開メタデータ、認証不要 |
| GET `/jwks` | ID Tokenなどの公開署名鍵、認証不要 |
| GET `/authorize` | ブラウザーで認証開始、登録済みclientとPKCE |
| POST `/token` | バックエンドでコード交換、client assertion |
| GET / POST `/userinfo` | Access Tokenでsubjectを取得 |
| GET / POST `/logout` | 利用者の確認を伴うOPログアウト |
| POST `/session/check` | 独自のセッション確認、新しいclient assertion |

秘密鍵、code、token、assertionはURLや診断ログに残さず、アプリのサーバーで扱います。ブラウザーだけのSPAへサーバー側クライアントの秘密鍵を配布しません。

## GET /authorize

ブラウザーを認証エンドポイントへ遷移させます。すべての値はURLエンコードします。

| パラメーター | 値・生成元 |
| --- | --- |
| `client_id` | 管理者が登録したclient ID |
| `redirect_uri` | 登録と完全一致するHTTPS URL |
| `response_type` / `scope` | `code` / 最小構成は`openid` |
| `state` | ブラウザーの未処理トランザクションに結び付けた乱数 |
| `nonce` | ID Token検証用の、このログイン専用の乱数 |
| `code_challenge` | verifierのSHA-256をbase64url、末尾の`=`なしで符号化 |
| `code_challenge_method` | `S256` |

成功時は登録されたコールバックのqueryに`code`、`state`、`iss`が返ります。アプリはstateと固定issuerを検証してからコード交換します。エラー応答では`error`を扱い、セッションを作りません。未登録の戻り先へリダイレクトされることを期待せず、OP画面で拒否される場合も扱います。stateやnonce、verifierを固定値にしないでください。

## POST /token

`Content-Type: application/x-www-form-urlencoded`で、バックエンドから送ります。

| フィールド | 値 |
| --- | --- |
| `grant_type` | `authorization_code` |
| `code` | 今回のコールバックの未使用code |
| `redirect_uri` | 認証開始時と登録に一致するURL |
| `code_verifier` | 認証開始時に保存したverifier |
| `client_id` | 登録client ID |
| `client_assertion_type` | `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` |
| `client_assertion` | 下記のES256 JWT |

JWTヘッダーは登録公開鍵に対応する`kid`と`alg=ES256`を使います。`iss`と`sub`はclient ID、`aud`はDiscoveryの**正確なtoken endpoint URL**です。要求ごとに新しい`jti`と、運用設定内の短い`iat`・`exp`を使います。

成功時のJSONは`access_token`、`token_type`、`expires_in`、`id_token`を含みます。通常のBearer構成ではAccess Tokenはopaqueで、JWTとして解析しません。`expires_in`は秒です。この公開プロファイルにrefresh token grantはありません。

ID TokenはDiscoveryのJWKSと許可したアルゴリズムで署名検証し、issuer、audience、時刻、nonce、必要なauth_timeを検証します。ユーザー識別はissuerとpairwise `sub`の組です。JWTをdecodeするだけでは検証になりません。

主なエラー応答はJSONの`error`です。以下は現在の実装のマッピングで、全経路の網羅的エラー一覧ではありません。

| HTTP / error | 対応 |
| --- | --- |
| 400 `invalid_request` | 必須値・形式を見直す |
| 401 `invalid_client` | 登録鍵、kid、aud、署名、有効期間を確認 |
| 400 `invalid_grant` | code、PKCE、redirect URI、再送を確認し新規ログイン |
| 400 `unsupported_grant_type` | このプロファイルのgrantを使用 |
| 500 `server_error` | サーバー側障害。セッションを作らない |

タイムアウトや応答消失時もcodeやassertionを再送せず、新しいログインからやり直します。

## GET / POST /userinfo

通常構成では`Authorization: Bearer <access_token>`を使います。POSTでもtokenをURLやformへ移さず、このヘッダーに入れます。DPoPに結び付いたtokenを使う場合は、その構成に対応するproofと認証方式が別途必要です。

最小の成功応答は`{"sub":"<pairwise-subject>"}`です。取得したsubは検証済みID Tokenと一致させます。`profile`だけで名前やメールを保証しません。通常のログインでVaultのノートは返りません。

失効・期限切れなど無効tokenでは401とBearerまたはDPoPのchallengeを返します。内部障害は実装契約上503、`Retry-After: 5`、no-storeで、無効tokenのchallengeや古い属性を返しません。503を同意の撤回と扱わないでください。UserInfoはアプリのセッション確認や一般API認可の代わりにはなりません。

## POST /session/check

mikaki独自拡張です。`Content-Type: application/json`で次の形式を送ります。山括弧の値は説明用のプレースホルダーで、そのまま送信できません。

```json
{
  "client_id": "<registered-client-id>",
  "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion": "<new-signed-es256-jwt>",
  "sid": "<validated-id-token-sid>"
}
```

assertionの`aud`は**`https://auth.mikaki.org/session/check`**です。token endpoint用JWTの再利用はできません。新しいjtiを使い、ユーザーのSSO CookieやAccess Tokenは送りません。

有効なsidのJSONは`active=true`、`sub`、`auth_time`、`expires_at`、`lease_ttl`、`app_idle_timeout`、`policy_revision`、`session_policy_revision`を含みます。時刻はUnix秒、TTLとidle timeoutは秒です。subとauth_timeをID Tokenと照合します。親SSOのexpires_atを上限とし、**確認を開始した時点**からlease_ttlを測ります。固定の5分などを実装に埋め込まず応答の値を使います。

未知・別client・token未発行・失効済みsidは200の`{"active":false}`です。これを成功ログインとして扱いません。形式不正は400、クライアント認証不正は401で、これらの拒否応答はJSONのerror本文を約束しません。応答はno-storeです。

Cookie発行前の確認に失敗した場合は新しいセッションを作りません。OP停止時、既存セッションは現在の確認期限までに限り、期限を延長しません。遅れて届く応答やコールバックで失効を取り消さない実装が必要です。

## GET / POST /logoutとBack-Channel通知

Discoveryのend_session_endpointを使います。`id_token_hint`、事前登録した`post_logout_redirect_uri`、戻り時に照合する`state`を必要に応じて指定します。これらの値は常にすべて必須ではありません。不正なhintや戻り先を任意のURLへのリダイレクトに使えません。POSTはform形式で、確認画面を経由します。

RP自身のCookieを消すだけの操作と、OPのSSO終了は別です。RPがBack-Channel Logout受信先を登録した場合、OPはそのRPのendpointへformの`logout_token`を送ります。RPは署名、固定issuer、自分のclient audience、時刻、events、sidを検証し、nonceを受け入れず、対応セッションを失効させます。重複通知と、失効後に届くコールバックにも対応します。

通知到着やブラウザーの戻りの順序に依存せず、セッション確認の期限も守ってください。[ログアウト試験の範囲](conformance.md)は本番のすべてのRPへの通知保証ではありません。

## 契約の詳細と変更の確認

要求と応答の説明は[RP連携契約](https://github.com/masanork/mikaki/blob/main/docs/rp-integration.md)、[session/check](https://github.com/masanork/mikaki/blob/main/docs/rp-session-check.md)、[UserInfo](https://github.com/masanork/mikaki/blob/main/docs/oidc-access-token-and-userinfo.md)、[現在のtokenエラー実装](https://github.com/masanork/mikaki/blob/main/crates/worker/src/lib.rs)に基づきます。標準全体は[OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html)を確認してください。実験段階のため、接続時に公開Discovery、対象commitと運用設定を確認します。

## 次に読む

- [動かせるローカルRP例](integration-example.md)：コード交換とセッションの実装を実行します。
- [運用・サービス情報](operations.md)：利用条件、サポート状況、変更の確認先を確認します。
