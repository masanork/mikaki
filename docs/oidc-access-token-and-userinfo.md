# Access TokenとUserInfo

2026-09-22 / Draft 1（設計と初期実装記録。現行のRP手順は[RP向け接続手順](rp-integration.md)を参照）

[ログイン取引](oidc-login-flow.md)のtoken応答とUserInfoを具体化する。初期は通常ログインに必要な情報だけを扱い、アプリのログイン保持は[セッション契約](session-lifecycle.md)に従う。Rust ES256 ID Token signer、Rust JWS構成とCloudflare WebCrypto RSA署名によるRS256経路、Worker `POST /token`、不透明Access Token発行、D1のcode/token原子確定、activeなES256/RS256公開鍵を返す`GET /jwks`、発行済み・未失効tokenの`GET`/`POST /userinfo`を実装した。UserInfoはBearer headerからtokenを受け取り、subだけを返す。RS256のworkerd import/signと隔離D1での相互運用は後続の実装検証で確認した。以下の仕様全体への適合やRPとの本番相互運用を意味しない。

## 用途の分離

| 情報・API | 初期の役割 |
| --- | --- |
| ID Token | 認証結果をアプリが検証し、アプリセッションを作る |
| Access Token | mikakiのUserInfoを呼び出す権限 |
| UserInfo | 対象利用者のpairwise subを返す |
| /session/check | client認証とsidにより、既存のアプリセッションの有効性を確認 |
| アプリのcookie | 各アプリの日常利用。アプリ側でセッション・権限を判定 |

Access TokenをアプリAPI・Vault・管理操作の権限に使わない。/session/checkもAccess Tokenを受け入れず、client署名で認証する。Access Tokenの期限切れだけではアプリセッションを終了させず、取得し直すための定期リダイレクトも行わない。

## 形式・寿命・記録

初期はCSPRNGで生成した32 byteの乱数をbase64url（paddingなし）で表す不透明なBearer tokenとする。UUIDや利用者IDから生成しない。JWT署名を伴うID Tokenとは別形式であり、クライアントはAccess Tokenの中身を解析しない。署名JWTである必要のないtokenを不透明形式にすることは、OIDCの採用と矛盾しない。

mikakiはtokenのSHA-256ハッシュ、発行先client、sub、sid、grant版、scope、用途（UserInfo）、発行時刻、有効期限、失効状態、元codeの記録参照、policy_revisionを保存する。生のtokenは交換応答でのみ渡し、DB・ログ・監査イベントへ残さない。32 byteのランダム値なので、パスワード用の低速ハッシュは使わない。将来ハッシュ方式を変更する場合は記録形式を版管理する。

有効期間は既定5分を提案し、[設定例](../config/oidc-flow-policy.example.toml)のoidc.access_token.ttlへ分離する。実際のexpires_atは発行時刻＋設定TTLと元SSO期限の早い方に固定する。now >= expires_atで拒否し、JWT検証用の時計ずれ許容によって延長しない。既存tokenへの設定変更の適用は[設定契約](runtime-configuration.md)に従う。

token発行記録とcode消費は原子的に確定する。SSO失効、接続解除、対象clientの停止、元codeの再使用による派生token失効もUserInfoで確認する。失効を反映した読み取りを用い、UserInfoに5分の有効性キャッシュを追加しない。既に判定・実行中の応答の取り消しは保証しない。

このtokenはBearerであり、所持者が使用できる。発行先clientをDBへ記録しても、それだけで呼出し元の鍵に拘束されるわけではない。private_key_jwtはtoken発行時のclient認証であり、UserInfo呼出しの送信者証明ではない。初期はTLSとバックエンド内の保持で扱い、将来のDPoP等は別プロファイルとして評価する。

## Token応答

POST /tokenの成功応答はapplication/jsonで、以下を返す。

| フィールド | 内容 |
| --- | --- |
| access_token | 発行した不透明token |
| token_type | Bearer |
| expires_in | 発行したAccess Tokenの実際の有効期間（秒）。SSO残存期間で短縮する場合も反映 |
| scope | 初期はopenid |
| id_token | 既存設計に従う署名済みJWT |

Cache-Control: no-storeとPragma: no-cacheを付ける。初期はrefresh_tokenとoffline_accessを提供しない。Code Flowで任意のat_hashは初期発行では省略する。将来追加する場合は、採用署名方式に対応した標準の計算・検証をプロファイルに定める。

アプリはtokenをバックエンドだけで扱う。UserInfoを使わない場合はAccess Tokenを永続保存せず、応答の検証・処理後に破棄する。UserInfoを使う場合も当該ログイン取引内で取得し、その後は破棄する。ログアウト用ID Token hintの保持は既存の別契約に従う。

## UserInfoの契約

実装済みの`GET`/`POST /userinfo`はAuthorization: Bearerヘッダーだけを受け付ける。queryによるtoken送信を拒否する。Discoveryでendpointを公開している。標準OIDCクライアントとの本番相互運用は未確認。

有効なtokenに対して、Content-Type: application/jsonで次の形を返す。

```json
{"sub":"<当該tokenの発行先sectorに対応するsub>"}
```

通常ログインのscopeはopenidのみとし、氏名・メール・画像・アプリの役割・AccountId・VaultId・DIDは返さない。表示名と参加権限は各アプリで管理する。profile・email等の未対応scopeは認可要求時にinvalid_scopeで拒否する。Discoveryには実際に提供するscope・claim・機能だけを掲載する。要求されたからといって未提供claimを空文字や仮の値で補わない。

初期の静的client登録ではJSON応答を使い、署名・暗号化UserInfo応答の登録要求は未対応として拒否する。ブラウザからの直接利用は初期対象外とし、CORSを開放しない。サーバー間のUserInfo取得に利用者のSSO cookieや追加のPasskey操作は要求しない。

アプリがUserInfoを呼んだ場合は、返されたsubが検証済みID Tokenのsubと完全一致することを確認し、不一致ならそのログイン取引を失敗させる。UserInfo単独で利用者をログインさせず、/session/checkの代わりにも使わない。初期は追加claimがないため、通常経路ではUserInfo呼出しを省略できる。

## エラーと運用

- tokenなしは401とWWW-Authenticate: Bearerを返し、不要な詳細を付けない。
- 不正・失効済み・期限切れtokenは401、invalid_tokenとする。別用途のtokenも拒否する。
- 要求形式の不正や複数経路でのtoken指定は400、invalid_requestとする。権限不足には403、insufficient_scopeを使う。
- ストア障害等で有効性を確認できない場合は処理を停止し、5xxで一時障害を示す。失効と断定せず、同意・再認証を繰り返させない。
- UserInfoの成功・エラー応答ともno-storeとし、Authorizationや応答claimを通常のアクセスログに残さない。

UserInfoが任意呼出しであることと、失敗応答を無視することは区別する。利用する経路で不一致・invalid_tokenを検出したらログインを確定しない。一時障害では有効期限内の同じAccess Tokenで再試行できる。認可codeと異なり、Access Tokenは一回限りではない。

## 受入条件

GET/POSTとBearerヘッダー、subのみのJSON、ID Tokenとのsub不一致、別用途tokenの拒否、期限境界、SSO失効・接続解除・client停止・code再使用後の拒否、ストア障害、ログへの秘密漏出がないことを確認する。Access Tokenが失効しても、独立に有効なアプリセッションは継続できることも確認する。

初期はOAuth token introspection・公開revocation endpoint・汎用API scopeを追加しない。これらが必要になった時点で権限・失効・client認証を別途定める。

## 参照

- [OIDC Core §3.1.3.3](https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse)：ID TokenとAccess Tokenを含むtoken応答。
- [OIDC Core §5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)：UserInfoのHTTPメソッド・Bearer認証・sub照合。
- [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html)：Bearerヘッダーとエラー応答。
