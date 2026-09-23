# OIDCの識別子・署名鍵設計案

2026-09-22 / Draft 3（レビュー用）

共通アカウントとアプリ内アカウントの対応、署名鍵の更新を具体化する。以下はG1へ向けた提案であり、採用・実装・検証済みを意味しない。ログインUXとセッション期限は既存の[OIDC仕様](oidc-login.md)・[セッション仕様](session-lifecycle.md)を維持する。

## 1. 利用者に見える挙動

- 同じPasskeyでtossa・tsudoiにログインできる。アプリごとのユーザー名や役割は各アプリで管理する。
- 接続解除はログイン・データ利用の許可を取り消す。アプリのユーザーや保存済みデータは削除しない。
- 同じ共通アカウントで再接続した場合は、同じアプリ内ユーザーへ戻る。退会済み・利用停止中の場合の再参加は、アプリ側のルールに従う。
- 別の共通アカウントを使った場合、メールアドレスや表示名が同じでも同じアプリ内ユーザーに自動統合しない。
- 通常の署名鍵更新で、Passkeyの再登録・接続の再許可・一斉ログアウトを求めない。

## 2. 識別子を分ける

| 識別子 | 発行・保持 | 用途 |
| --- | --- | --- |
| AccountId | mikaki内部で発行 | credentialと共通アカウントの所有関係。OIDCで公開しない |
| issuer | インスタンスの固定HTTPS URL | 外部IDの名前空間。実ドメインは利用者が選択する |
| sector | OIDCのSector Identifier規則から確定 | アプリに公開するsubを分ける単位 |
| sub | mikakiがAccountIdとsectorの組に発行 | アプリへ渡す不透明で安定したID |
| SubjectId | 各アプリが発行 | アプリ内の業務データ・参加権限の参照先 |
| sid | mikakiがセッションの関連に発行 | ログアウト・有効性確認。本人の恒久IDに使わない |

初期案はpairwise subとする。tossa・tsudoiのsectorを分けるため、登録redirect URIのホストを各アプリで分ける。sectorはclient_idの別名ではない。同じホスト内のパス違いを別sectorと見なさない。初期は1 clientのredirect URIを単一ホストに限定し、任意のsector_identifier_uri取得を実装しない。実ドメインがこの条件を満たさない場合は、登録構成を再検討してから確定する。

subは初回の接続許可確定時に、sectorごとに独立したUUIDv4を生成して保存する案を推奨する。表記は小文字・ハイフン付き36文字とし、通常はURN接頭辞を付けない。UUIDv4/v7の比較と内部IDの割当ては[識別子方針](identifier-policy.md)に定める。同じAccountId・sectorには常に保存済みの値を返す。共通の識別子導出鍵を新設せず、OIDC署名鍵の更新から独立させる。衝突はDBの一意制約で拒否して再生成する。

アプリにはAccountId・VaultId・利用者DIDを通常ログインのclaimとして渡さない。subを分けることは、アプリ間のあらゆる照合を防ぐ保証ではない。利用者が別途共有した情報やmikaki内部の対応は残る。

### 2.1 OIDCの形式制約とDIDの利用

規格が定める形式・意味を優先する。OIDCのissuerはHTTPS URLであり、did形式に置き換えない。subはissuer内で一意かつ他の主体へ再割当てしない、大文字小文字を区別する255 ASCII文字以内の文字列である。UUIDや特定のURI形式は必須ではない。アプリは表記にかかわらず(issuer, sub)で本人を識別し、subの文字列を解析して独自に本人を決めない。

DID文字列をsubに入れること自体は、OIDCの長さ・一意性・安定性等を満たせば可能。ただし通常のOIDC検証をDID解決へ置き換えるものではない。全アプリに同じ利用者DIDを渡すと、それを共通の照合キーにできるため、pairwise分離とは両立しない。sectorごとに別DIDを発行する場合も、文書内の同じ鍵・controller等から関連が見えないか評価する。

`did:method:identifier`はDIDメソッドと、その生成・解決・更新等の意味を持つ。記法だけを借りる目的で未定義の`did:mikaki:...`を作らない。URI形式が必要な文脈では既存標準の`urn:uuid:<UUID>`を使えるが、ログイン用subには通常のUUID文字列を推奨する。UUIDは公開鍵や解決先を持つことを意味しない。

連合の利用者DIDは、既存の設計どおり公開鍵・端末・連絡先との結び付けに利用する候補とする。`did:key`は鍵から生成され更新できないため、鍵変更から独立したログイン用subの第一候補にはしない。DIDと共通アカウントの対応には本人の認証とDID制御の検証を必要とし、DIDの自己申告や文字列一致だけでアカウントを結び付けない。対応の証明形式・更新手順はG3で定める。

識別子という理由だけでDIDへ統一しない。AccountIdやVaultId等もUUIDを基本候補とする。G1で確定するのはログイン用subと内部IDの表現、G3で確定するのは連合用DIDメソッドと証明である。ログイン用sub自体にも鍵解決・可搬性を持たせたい場合は、DIDメソッド、鍵更新、sector分離の要件をG1へ前倒しして再設計する。

## 3. 対応表と接続許可

次は論理レコード案であり、migrationの確定版ではない。issuerは初期インスタンスで一つに固定し、別issuerのDBをそのまま混在させない。

| 配置 | レコード | 主要フィールド・制約 |
| --- | --- | --- |
| mikaki | OidcClient | client_id、sector、redirect URI、post-logout URI、backchannel URI、設定版、状態。管理者が静的登録 |
| mikaki | PairwiseSubject | account_id、sector、sub。UNIQUE(account_id, sector)、UNIQUE(sub) |
| mikaki | AppConnection | account_id、client_id、許可scope、同意表示版、grant_version、状態。UNIQUE(account_id, client_id) |
| アプリ | ExternalIdentity | issuer、sub、subject_id。UNIQUE(issuer, sub) |

PairwiseSubjectは識別の記録、AppConnectionは利用許可の記録として分離する。AppConnectionを失効させてもPairwiseSubjectを削除しない。再接続はgrant_versionを進め、同じsubと新しいsidを使う。古いセッションやVault grantを復活させない。

初回接続は、検証済みAccountIdと登録済みclientを使い、PairwiseSubjectの取得/作成とAppConnectionの許可確定を原子的に行う。並行する初回ログインで異なるsubを発行しない。認可codeにはclient・sub・sid・grant版を固定し、交換時に失効と版の整合性を確認する。

アプリはOIDC検証とセッション有効性確認に成功してから、(issuer, sub)に対応するSubjectIdを取得する。初回作成時はアプリの参加許可を確認し、SubjectIdとExternalIdentityを同じトランザクションで作る。並行callbackでユーザーを二重作成しない。既存SubjectIdをcallbackパラメーターから受け取って上書きしない。

初期はアカウント統合・既存ユーザーへの後付けリンクを提供しない。将来導入する場合は双方の所有確認と履歴を伴う別操作とする。共通アカウント削除後のID非再利用と記録の保持・消去は、アカウント削除機能の着手前に定める。

## 4. client・issuerの変更

client_secretや署名鍵を更新してもsubは変えない。redirect URIのパス変更は登録設定として検証し、sectorが変わらなければsubは維持する。ホスト変更によるsectorの変更とissuerの変更は、アプリの外部IDを変える移行である。メール一致による自動復旧や、運用者の設定変更だけでの既存アカウント統合を行わない。

初期は同一sectorへの無関係な別client追加を禁止する。client_idの再発行でも自動的に旧接続許可を引き継がせない。設定版が変わった場合、進行中の認可取引を新設定へ読み替えず、古い取引を拒否して再開させる。ドメイン移転・アプリの所有者変更は別の移行計画を必要とする。

## 5. 署名方式と検証

通常発行をRS256/RSA 3072 bitに固定する前案を撤回し、JOSE ES256（ECDSA P-256）を第一候補、Ed25519を比較候補とする。OIDCのRS256実装要件と通常の発行方式は区別する。[暗号方式の移行方針](crypto-agility.md)に従い、G1で実装と適合範囲を確定する。WebAuthnの鍵とは共有しない。暗号処理は保守される実装を利用し、Wasmでの対応・署名性能・依存をG1で評価する。鍵生成をリクエスト処理の途中で行わない。

公開JWKはkty・use=sig・alg・kidと方式固有の公開鍵パラメーターを持つ。RSAのn/eを共通構造の前提にしない。kidは鍵ごとに一意で再利用しない。発行プロファイルごとの署名中の鍵は一つとし、方式移行時はclient・用途ごとに新旧プロファイルを併存させる。

アプリは登録issuerのDiscovery/JWKSだけを使い、token内のjku・x5uや任意URLから鍵を取得しない。許可alg、鍵種別、署名、issuer、audience、時刻と用途ごとのclaimを検証する。ID Token・Logout Token・access tokenの検証入口を分け、別用途のtokenを受け入れない。未知kidでは再取得を集約・頻度制限し、なお鍵が見つからなければ拒否する。

## 6. 署名鍵の状態と保管

```text
prepared → published → active → verify_only → retired
                          └───────────────→ compromised
```

SigningKeyレコードはkid、用途、方式/パラメーター、鍵形式版、公開JWK、秘密鍵の参照先、状態、公開開始・署名開始・署名停止時刻、設定世代を持つ。秘密鍵本体はサーバーの秘密管理境界に置き、通常のDBレコード・リポジトリ・ログ・JWKSへ含めない。採用する秘密保管手段と配備方法はG1で評価する。VaultのPRF由来鍵、利用者DID鍵、配送用の鍵と共有しない。

更新状態は管理された運用操作で変更する。旧バージョンのアプリ配備へ戻しただけで、停止済み鍵を署名に再利用しない。署名開始時に有効な設定世代を確認し、世代競合時は発行を中断する。停止時刻は古い署名処理が完了または破棄されたことを確認してから記録する。この制御ができるストア・署名アダプターの契約をG1で定める。

## 7. 通常ローテーションの手順案

以下の運用間隔は[設定例](../config/oidc-key-policy.example.toml)へ分離する。[設定契約](runtime-configuration.md)に従い、実際に発行済みのセッション・tokenから求めた保持期限も満たす。値の外部化は本設計案の採用を意味しない。

1. 90日を目安に次の鍵を生成し、公開鍵だけを先にJWKSへ追加する。秘密鍵が利用可能であることも検証する。
2. JWKSのHTTPキャッシュは最大5分、新鍵の公開から署名切替までは初期24時間を置く。両アプリで取得・検証できることを試験してから切り替える。
3. 新鍵をactive、旧鍵をverify_onlyへ移す。旧鍵の新規署名が停止したことを確認し、旧秘密鍵を配備先から除去する。
4. 旧公開鍵は最終署名停止から最低32日保持する。通常のID Tokenは5分で失効するが、ログアウト用のid_token_hintとして期限切れID Tokenを使う経路があり、最大30日のSSO期間を考慮する。
5. 保持期間経過と未処理の検証用途がないことを確認して旧公開鍵を退役させる。kidと退役状態は再利用防止のため記録する。

この日数は製品案であり標準指定値ではない。ログアウトhintは署名が正しいだけで受け入れず、現在または直近の記録済みセッション・clientと照合する。Logout Tokenは送信時に現行鍵で作り、5分のTTLを提案する。再試行outboxは失効対象の意味情報を保持し、期限切れの署名済みtokenをそのまま送らない。新しいtokenで再送しても、対象の旧sidを変えない。

## 8. 漏えい・緊急停止

通常更新と漏えい対応を分ける。漏えい鍵は即座に署名を停止し、32日の検証猶予を与えない。JWKSから削除するだけではアプリのキャッシュや既存セッションが消えないため、管理対象アプリへkidの拒否を配布し、到達・適用を確認する。

影響期間・範囲を確定できない場合は全SSO・派生アプリセッションを失効させ、新鍵とアプリ側の拒否設定が有効になった後にPasskeyでログインし直す。緊急時の再認証は通常更新のUXとは区別する。バックアップから漏えい鍵を再有効化しない。

アプリセッション作成には従来通りサーバー間の有効性確認を必要とし、issuer/client/sidに対応するsubと認証時刻も照合する。署名の検証だけで自己申告sid・subのセッションを新設しない。漏えい検知や影響調査の完了時間までは保証しない。

## 9. API・ストア契約の候補

| 論理操作 | 必要な確定・検証 |
| --- | --- |
| ResolveSubjectAndAuthorizeClient | 検証済みAccountIdとclient設定版に対し、subと接続許可を原子的に確定 |
| RevokeClientConnection | grant版更新、対象セッション失効、通知outboxを原子的に確定。subを削除しない |
| CheckClientSession | 認証済みclient自身のsidだけ照会し、active・sub・auth_time・元セッション期限を返す。失効確認の最大5分契約に従う |
| ActivateSigningKey | 公開・検証済みの新鍵へ条件付きで切替。旧署名処理との競合を処理 |
| RetireVerificationKey | 検証保持期限と利用状況を確認し、公開鍵を退役。漏えいは別の即時停止操作 |

これらは認証core外のOIDC/セッション層の契約であり、WebAuthnパーサーにclient・JWT・鍵更新を持ち込まない。HTTPパス、SQL、依存ライブラリ、クライアント認証方式は未確定とする。

HTTPとクライアント認証の具体案は[ログイン取引](oidc-login-flow.md)、レコード・原子操作とD1への対応方針は[OIDCストア契約](oidc-store-contract.md)を参照する。確定SQLと実環境での検証はG1で行う。

## 10. 受入試験案

- 同じAccountId・sectorの並行初回接続でsubが一つに定まり、異なるsectorでは異なるsubになる。
- 接続解除・再接続・署名鍵更新後もsubが維持され、古い許可・sidは復活しない。
- アプリ側の並行callbackでSubjectIdが二重作成されず、同じメールの別アカウントは統合されない。
- sector/client設定の変更中に古いcodeを新設定で利用できない。
- 新旧JWKSキャッシュ、未知kid、JWKS障害、更新途中の再起動・旧配備への復帰を試験する。
- 通常の鍵更新後に旧ID Tokenを使ったログアウトが機能し、最大30日のセッションが鍵更新だけで切れない。
- 漏えい鍵の署名拒否、アプリのキャッシュ無効化、偽造tokenとサーバー記録の不一致を検証する。
- 私有鍵がDBの通常エクスポート・ログ・JWKSに出ず、期限切れLogout Tokenを再送しない。

## 参照

- [OIDC Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)：issuerとsubの形式・一意性・非再割当ての制約。
- [DID Core](https://www.w3.org/TR/did-core/)：DIDの構文とメソッドの責任。
- [did:key](https://w3c-ccg.github.io/did-key-spec/)：公開鍵からの生成と更新不可の性質。
- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html)：UUIDとURN表記。

- [OIDC Core §8.1](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)：sectorと安定したpairwise sub。保存した識別子を用いる方式も規定されている。
- [OIDC Core §15.1](https://openid.net/specs/openid-connect-core-1_0.html#ServerMTI)：OPのRS256対応要件。
- [OIDC Core §10.1.1](https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys)：JWKSによる署名鍵の更新。
- [OIDC RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)：期限切れID Tokenをhintとして扱う条件。
- [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)：issuer・jwks_uri・公開メタデータ。
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html)：アルゴリズム検証、JWT用途の区別、鍵URLの扱い。
