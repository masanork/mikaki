# クライアント認証とログイン取引

2026-09-22 / Draft 1（レビュー用）

[ログインUX](oidc-login.md)と[セッション契約](session-lifecycle.md)を満たす初期案。Rust Workerは既存SSOと既存app connectionを使った`GET /authorize` code発行を実装したが、Passkey login UI・初回同意・connection作成は未実装。Discovery/token/UserInfo等の実装範囲は[実装基準](oidc-implementation-readiness.md)に記録する。以下のフロー全体への適合やconformance通過を意味しない。

## クライアント認証

サーバー側処理を持つtossa・tsudoiは、private_key_jwtを採用する案とする。アプリと環境ごとにclientと鍵を分け、秘密鍵は各アプリのバックエンド、公開鍵はmikakiの静的登録に置く。利用者への設定や操作は増やさない。初期は管理された登録更新で公開鍵を配布し、要求内のjku・x5uから鍵を取得しない。

client assertionはiss=sub=client_id、audはtoken endpointの完全なURL、jtiは取引ごとに一意とする。expに加えて本プロファイルではiatも必須とし、寿命と未来時刻を検証する。client_assertion_typeはurn:ietf:params:oauth:client-assertion-type:jwt-bearerを使用する。署名方式・kid・鍵種別は登録プロファイルと照合し、OPのID Token署名方式とは独立に管理する。初期候補はES256とし、互換方式は[暗号移行方針](crypto-agility.md)に従う。

検証成功したassertionの(client_id, jti)を原子的に一回だけ受理し、許容時計ずれを含む最終受理可能時刻まで再使用記録を保持する。後続のcode検証に失敗しても同じassertionは再使用しない。無効な署名によって他clientのjtiを消費させない。鍵更新は新公開鍵の登録、新秘密鍵への切替、旧assertionの受理可能期間経過、旧鍵の停止の順とする。漏えい鍵は即時停止する。

## ログインの順序

| 段階 | 処理と確定する状態 |
| --- | --- |
| 1. アプリで開始 | CSRF対策を持つログイン開始操作から、state・nonce・PKCE verifierを生成。ブラウザに結び付いたサーバー側取引として保存する。戻り先は検証したアプリ内パスに限定 |
| 2. mikakiへ移動 | GET /authorizeへcode flow・openid・S256を要求。登録client・redirect URI・要求パラメーターを検証し、変更不能な認可取引として保持 |
| 3. 本人認証・接続許可 | 有効なSSOと接続許可があれば追加操作なく進む。必要な場合だけPasskeyや初回接続確認を行い、認証結果・client設定版・grant版・sub・sidを固定 |
| 4. code発行 | 高エントロピーの不透明なcodeを発行し、サーバーには照合用ハッシュを保存。登録redirect URIへcodeとstateを返す。寿命は既定60秒、一回限り |
| 5. アプリcallback | ブラウザへの結び付け、state、取引期限を確認して取引を処理中にする。バックエンドがPOST /tokenへcode・redirect URI・verifier・client assertionを送る |
| 6. code交換 | client認証、codeのclient・redirect URI・PKCE、期限、未使用状態を検証。SSO・接続許可・client設定版も再確認して、一度だけ交換を確定 |
| 7. アプリで検証 | ID Tokenの署名・alg・iss・aud・必要なazp・時刻・nonce・必要なauth_timeを検証。下記のセッション確認でsid・sub・auth_timeの一致も確認 |
| 8. セッション確立 | アプリ参加資格と失効記録を確認し、外部IDの対応・アプリセッション・ログイン取引の完了をローカルに原子的に保存。その後cookieを発行し、元のアプリ内画面へ戻す |

アプリ間で共通のブラウザcookieを使わない。アプリセッションとmikaki SSOは、それぞれhost限定のSecure・HttpOnly・Path=/のcookieとし、通常のトップレベルGET callbackに合わせSameSite=Laxを初期案とする。Domain属性は付けず、__Host-接頭辞を用いる。ログイン取引もブラウザへ結び付け、stateだけを知る別ブラウザからのcallbackを拒否する。複数タブの取引は個別に保持する。

callbackではcode等のqueryをアクセスログに残さず、第三者リソースを読み込まない。Cache-Control: no-storeとReferrer-Policy: no-referrerを用い、処理後はqueryのないアプリ内URLへ移動する。tokenや秘密鍵をブラウザのlocalStorageへ保存しない。

## code交換と失効の競合

code消費、発行するtokenの記録、sidとの結び付けは同じ原子的操作で確定する。その確定時にSSO・grant・client設定・使用鍵が有効であることを条件にする。署名を先に生成する実装でも、確定前に応答を外部へ出さない。署名失敗・版競合ではtokenを返さない。鍵停止と進行中の署名の競合は署名鍵設計の契約に従う。

並行交換の成功は一件だけとする。消費済みcodeの再使用は拒否し、そのcodeから発行したtokenを失効させる方針とする。client認証とcodeへの結び付けを確認してから失効し、無関係な要求で他人のセッションを止めない。code単位の派生物を追跡し、SSO全体や他のログインまで一律に失効させない。

ログアウト通知を受けたアプリは、セッション作成前でもsidの失効を記録する。初回セッション保存と失効通知の処理を競合制御し、遅延callbackや有効性応答による復活を防ぐ。サーバー間確認の直後に失効し通知がまだ届かない場合は、既存の最大5分の確認期限で反映する。分散システム全体の即時・一回限りの完了は保証しない。

## セッション確認API

POST /session/checkをmikaki固有のバックエンドAPI案とする。OIDC標準endpointやOAuth token introspectionと同一視しない。client署名による認証を共用するが、audはこのendpointの完全なURLとし、token endpoint用assertionの転用を拒否する。jtiの一回性も検証する。

入力は当該clientのsid。認証済みclientに属しtoken発行確定済みの有効なsidに対して、active・sub・auth_time・元SSOのexpires_at・lease_ttl・新規アプリセッション用app_idle_timeout・policy_revisionを返す。存在しないsid、未交換codeに対応するsid、別clientのsid、失効済みsidはactive=falseとし、他clientの情報を返さない。失効を反映した読み取りを必要とし、応答をHTTPキャッシュに保存しない。

アプリは確認開始時からlease_ttlを数え、元SSO期限を超えない確認期限を保存する。応答到着時から数え直さず、時計の巻戻りでも延長しない。タイムアウト後や取引終了後の遅延応答は破棄する。初回の確認失敗ではアプリセッションを作らない。通常利用中の障害時は、既存の確認期限まで利用し、期限後は処理を停止して再試行を示す。

## 失敗時の利用者の流れ

- code交換の応答が失われた場合は同じcodeを自動再送せず、「ログインを再開」から新しい取引を作る。SSOが有効なら通常はPasskey操作を再要求しない。
- callbackの並行実行は一つの処理が担当し、他の要求は進行中または完了済みとして扱う。cookie送信前に応答が失われた場合も、codeの再交換で復旧しない。
- stateやブラウザへの結び付けが不正な要求では、既存セッションを変更せず、token endpointへ進まない。無効なredirect URIにはエラーも転送しない。
- キャンセル・期限切れ・アプリの参加拒否では、入力を保持して理由と次の操作を示す。無限の自動再ログインや、障害のたびのPasskey要求を行わない。
- アカウント切替時は古いアプリセッションを新しい識別子のセッションへ置換し、権限やVaultの解錠状態を引き継がない。

## 設定と受入条件

追加する値は[設定案](../config/oidc-flow-policy.example.toml)に切り出す。採用済みのcode・ID Token・SSOの期間は既存設定を参照し、二重定義しない。追加案の取引期限は10分、client assertionは60秒、JWT時計ずれ許容は30秒、バックエンド呼出しのタイムアウトは10秒とする。これらは標準の要求値ではなくレビュー対象。時計ずれ許容はsession・codeの期限を延長しない。

G1で、正常系と画面数、state/nonce/PKCEの不一致、assertion再使用と用途取り違え、並行code交換、応答喪失、通知とcallbackの順序逆転、鍵更新・停止、時計ずれ・遅延応答を統合試験する。

Access Tokenの用途・形式・寿命とUserInfoの提供範囲は、[Access TokenとUserInfo](oidc-access-token-and-userinfo.md)に具体案を定める。データモデル・原子操作・D1への対応方針は[OIDCストア契約](oidc-store-contract.md)にまとめる。残る具体化は、確定SQLと実環境検証、endpointのレート・サイズ制限、依存ライブラリである。本書はこれらの実装完了やOIDC全面適合を主張しない。

## 参照

- [OIDC Core §9](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)：private_key_jwtのclient認証とclaim。
- [RFC 9700 §2.5](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5)：非対称鍵を用いたclient認証の推奨。
- [RFC 6749 §4.1.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2)：codeの一回性、client/redirect URIへの結び付け、再使用時の扱い。
