# RP向け接続手順

この文書は、tossa・tsudoiなどのサーバー側Relying Party（RP）が本番のmikakiに接続するための実装手順です。対象issuerは`https://mikaki.tossa.app`です。現在の本番環境にRPはまだ登録されていません。登録はmikaki運用者が行います。

## 1. 接続情報を運用者へ渡す

RPごと、環境ごとに別のclientを用意します。RP側でES256/P-256の署名鍵を作成し、秘密鍵はRPのバックエンドのsecret storeに保存してください。mikaki運用者には次を渡してください。

- 環境、RP名、希望する`client_id`（未採番なら運用者がUUIDv4を採番）
- `sector_identifier`となるRPのホスト名
- HTTPSのcallback URLの完全な値（queryを含む場合はそれも含める）
- 署名用**公開**JWKの`kty=EC`、`crv=P-256`、`x`、`y`と`kid`

秘密JWKを送らないでください。登録形式、登録後の鍵・redirect URIの更新は[RP client operations](rp-client-operations.md)を参照してください。登録完了後に`client_id`、登録済みredirect URI、issuerをRP側設定へ固定します。動的client登録endpointはありません。

## 2. ログインを開始する

Discoveryは`https://mikaki.tossa.app/.well-known/openid-configuration`、公開署名鍵はそこに記載された`jwks_uri`から取得します。通常プロファイルはAuthorization Code Flow、`openid` scope、PKCE S256、`private_key_jwt`（ES256）です。隔離conformance環境のclient secret方式を本番接続に使わないでください。

RPのログイン開始操作にCSRF対策を設け、取引ごとに高エントロピーの`state`、`nonce`、PKCE `code_verifier`を生成します。`state`、`nonce`、verifier、開始時刻、ブラウザへの結び付け、ログイン後に戻す**RP内の検証済みパス**をサーバー側取引として保存します。`code_challenge`はverifierのSHA-256をbase64url（paddingなし）にした値です。次のパラメーターを付けてブラウザを`authorization_endpoint`へ移動させます。

| パラメーター | 値 |
| --- | --- |
| `client_id` | 登録されたclient ID |
| `redirect_uri` | 登録値と完全一致するcallback URL |
| `response_type` | `code` |
| `scope` | `openid` |
| `state` | 取引ごとの乱数。必須 |
| `nonce` | 取引ごとの乱数。RPでは必ず送ることを推奨 |
| `code_challenge` / `code_challenge_method` | PKCE challenge / `S256` |

`request`、`request_uri`、動的登録、`profile`・`email` scopeは現在の接続対象外です。mikakiのPasskey画面と初回接続確認はOPが処理します。RPはPasskeyやmikakiのSSO cookieを受け取りません。

## 3. callbackとcode交換

callbackでは、保存したブラウザ取引と`state`を照合し、一つのworkerだけが処理を獲得してください。OPが返した`iss`をissuerの完全な値と比較し、`error`があれば取引を失敗として扱います。codeがない、stateが違う、取引が期限切れ、既に処理済みの場合はtoken交換やアプリセッション作成を行わないでください。callbackのqueryに含まれるcodeをアクセスログへ残さないでください。

バックエンドから`token_endpoint`へ`application/x-www-form-urlencoded`で、`grant_type=authorization_code`、受け取った`code`、登録済みの`redirect_uri`、保存した`code_verifier`、`client_id`、`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`、`client_assertion`をPOSTします。assertionは登録した秘密鍵で署名したES256 JWTです。headerの`kid`は登録鍵、claimの`iss`と`sub`は`client_id`、`aud`はDiscoveryの**完全なtoken endpoint URL**、`jti`は要求ごとに一意、`iat`と`exp`を含めます。寿命は設定上限以内にし、同じassertionやcodeを再送しないでください。応答喪失時は新しいログイン取引から再開します。

成功応答の`id_token`はJWKSの鍵で署名と`alg`を検証し、`iss`、`aud`、`exp`、`iat`、送信した`nonce`、必要な`auth_time`を確認します。`sub`はRP内の外部ID対応に、`sid`はセッション失効の照会に使います。`sub`をメールや共通AccountIdとして扱わないでください。`access_token`は不透明なUserInfo専用Bearerであり、RPのAPI権限やログイン保持期間に転用しません。UserInfoを呼ぶ場合は返された`sub`が検証済みID Tokenと一致することを確認します。現時点のUserInfoは`sub`だけを返します。

## 4. アプリセッションを確定する

cookieを発行する前に、バックエンドから`POST https://mikaki.tossa.app/session/check`でID Tokenの`sid`を照会します。このAPIはOIDC標準endpointではなく、管理対象RPとの追加契約です。JSON bodyの`client_id`、`client_assertion_type`、新しい`client_assertion`、`sid`を送ります。assertionの`aud`は**`https://mikaki.tossa.app/session/check`**であり、token交換用assertionは使用できません。詳しい応答と失敗時の扱いは[RP session check](rp-session-check.md)を参照してください。

`active=true`の`sub`と`auth_time`を検証済みID Tokenに照合します。照会開始時刻から`lease_ttl`を数え、親SSOの`expires_at`を超えない確認期限を保存してください。RP自身のアプリセッションは、未操作期限`app_idle_timeout`と親SSO期限の早い方までです。失効記録、参加資格、ブラウザ取引の完了とアプリセッション作成をRPのストアで原子的に確定してから、RP host限定の`Secure`・`HttpOnly`・`SameSite=Lax` cookieを発行します。`Domain`属性やmikakiとの共通cookieは使いません。

保護対象の要求で確認期限を過ぎたら再照会します。初回照会に失敗したらセッションを作成しません。運用中にmikakiへ接続できない場合も、既存の確認期限を延長せず、期限後は保護対象の処理を停止します。遅れて届いた`active=true`応答で失効済みsidを復活させないでください。

## 現在の境界と受入確認

本番Workerに`/logout`、Back-Channel Logout通知、通知先登録・配送はまだありません。Discoveryにもlogout metadataを掲載していません。現時点でRPは通知を前提にせず、`/session/check`の確認期限で失効を反映してください。OPからのログアウト通知を含む統合試験が終わるまで、通常ログアウトが連携RPへ即時伝播するとは表示しないでください。

接続前に、登録済みredirectでのログイン、初回接続確認、SSO再利用、state・nonce・PKCE・署名・issuer/audienceの拒否、codeとassertionの再使用、別clientのsid、失効直後と期限境界、OP一時障害、複数タブと遅延callbackを確認してください。詳細な取引・競合契約は[OIDC login flow](oidc-login-flow.md)、[session lifecycle](session-lifecycle.md)、[Access Token and UserInfo](oidc-access-token-and-userinfo.md)にあります。
