# 運用パラメーターの設定契約

2026-09-23 / Revision 2（D1での有効版管理を採用）

セッション関連の期間・回数を型付き設定に集約し、コードに数値を散在させない。設計書の採用済み数値は初期設定値とし、運用変更を可能にする。設定外部化は[ADR 0004](adr/0004-runtime-policy-configuration.md)、有効版のD1管理は[ADR 0011](adr/0011-d1-runtime-policy.md)に記録する。全runtime policyの製品loaderはまだないが、Python設計検証器とWorker用の部分projectionをD1から読むloader・有効版切替CLIを実装している。

## 設定形式と入力元

初期形式はTOMLとし、[runtime-policy.example.toml](../config/runtime-policy.example.toml)を初期投入・編集の統合見本にする。旧session/flow/keyの三つのファイルは経緯と個別項目の参照用に残し、実行時にmergeしない。運用設定の有効版は配備ごとのD1で管理し、検証済みの新しい版へactive参照を切り替えて反映する。無認証の設定APIは作らない。コードの再編集・再配備は通常の値変更に要求しない。

初期投入ではTOMLを検証してD1に完全な設定版として保存する。サーバーcoreはファイル・環境変数・D1を直接読まず、アダプターがD1から取得し検証した設定snapshotを受け取る。

同一配置につき有効な運用設定の入力元はD1のactive版一つに限定する。環境変数ごとの上書き、複数ファイルの暗黙merge、ブラウザ要求による上書きは設けない。署名秘密鍵と復旧世代は秘密管理から供給する。D1 binding、安定したissuer、配備profileの許可範囲は配備設定に残す。clientの認証方式、公開鍵またはsecret verifier、redirect URI、PKCE要件は配備ごとのD1で管理する。

Workerの配備profileは`MIKAKI_DEPLOYMENT_PROFILE`で固定し、省略時は`normal`とする。`conformance`は別の[`wrangler.conformance.jsonc`](../crates/worker/wrangler.conformance.jsonc)から明示し、別のissuer・D1・署名秘密鍵で配備する。`client_secret_basic`/`client_secret_post`はこのprofileだけで受け付ける。各clientの認証方式はD1の`client.auth_method`に固定し、secretは32 byte以上の乱数から生成した値のSHA-256/base64url verifierだけを`client_secret`に置く。`client.allow_missing_pkce`は既定で0とし、conformance配備のsecret clientに限り1を許す。通常配備では1でもPKCEを省略できない。更新時はrevisionを増やす。secret試行制限の期間とclientあたり回数はD1の有効なWorker projectionから読み、初期値は60秒・300回とする。閾値を超えた要求は拒否する。実配備のissuer、D1 ID、鍵、client secretは設定例に含めない。

現時点では全runtime policyのloaderは未実装。`mikaki-worker`のOIDC認可・token endpointsはauthorization code/assertion/Access Token/ID Token TTL、SSO絶対期限、clock skew、request target/parameter/state/nonce、JWT/form/response byte上限、tokenのclient別試行期間・回数を、schema version 5・全policy由来revision・projection自身のhashを含むstrict JSON projectionとしてD1のactive版から毎回読む。`MIKAKI_WORKER_POLICY`環境変数へのフォールバックはない。`npm run build:policy`は単一TOMLを検証し、投入用`local/generated/worker-policy.json`を生成する。issuerは`MIKAKI_ISSUER`、ES256またはRS256 private JWKは`OP_PRIVATE_JWK` secretとして別途設定し、D1の有効なsigning key行へ同じ方式の公開JWKを登録する。RSA JWKのimport/signはWorkers WebCryptoを使用する。secret/private keyをvarsやpolicyへ入れない。

初期migration `0001_oidc_initial.sql`は設定版・active参照・監査テーブルも作るが、有効版を自動投入しない。生成したprojectionは次のCLIで確認・投入する。`--expected none`は初回だけ使い、以後は現在のprojection revisionを指定する。CLIは投入前にschemaの項目・範囲・projection hashを検証し、D1 batchで版登録・比較更新・監査を一括確定する。現在の`wrangler.jsonc`はローカルD1を指す。遠隔D1では別の実DB binding設定と`--remote yes`を明示し、実環境の権限と配備条件を整えてから使う。

```sh
npm run build:policy
npx wrangler d1 migrations apply DB --local --config crates/worker/wrangler.jsonc
node scripts/activate-worker-policy.mjs --config crates/worker/wrangler.jsonc --policy local/generated/worker-policy.json --expected none --actor local-operator --reason initial-policy --remote no --apply no
node scripts/activate-worker-policy.mjs --config crates/worker/wrangler.jsonc --policy local/generated/worker-policy.json --expected none --actor local-operator --reason initial-policy --remote no --apply yes
```

`schema_version`を必須とし、未知の版・キー・重複・型不一致・必須値の欠落は拒否する。見本の有効項目はすべて明示する方式を採り、省略時にコード内の別の既定値へ戻さない。導入済みの段階で必要な設定だけを読み込む。P0はVault処理を実装するためにP1の設定を要求しない。

## 設定する項目

期間は正の整数と単一の接尾辞`s`・`m`・`h`・`d`を組み合わせた文字列とする。1日は86400秒、月・年・小数・無単位の数値・複合表記は受け付けない。回数は正の整数とする。期間は秒へ正規化して桁あふれと日時加算の安全性を検証する。`0`や負数を「無制限」「無効化」として解釈しない。

| キー | 初期値 | 適用先 |
| --- | --- | --- |
| authentication.ceremony_ttl | 5m | WebAuthn ceremonyの有効期間 |
| authentication.ceremony_max_failures | 5 | ceremonyごとの完了失敗上限 |
| session.sso_absolute_ttl | 30d | SSOの本人認証からの絶対期限 |
| session.app_idle_timeout | 7d | アプリの未操作期限 |
| session.validation.lease_ttl | 5m | サーバー間有効性確認の結果を利用できる最長期間 |
| session.management.operation_authorization_ttl | 5m | 対象操作に固定した一回限りの管理許可 |
| oidc.authorization_code_ttl | 60s | 認可codeの有効期間 |
| oidc.id_token_ttl | 5m | ID Tokenの有効期間 |
| vault.unlock_idle_timeout | 15m | Vaultの未操作施錠期限（P1） |
| vault.unlock_absolute_ttl | 1h | Vault解錠の絶対期限（P1） |

Logout Token TTL、署名鍵更新間隔、事前公開期間、JWKSキャッシュ、旧公開鍵の最小保持期間も設定対象とする。[oidc-key-policy.example.toml](../config/oidc-key-policy.example.toml)に前回の設計案の値を示す。これらの見本は、未確定の署名方式や鍵運用案を採用済みに変更するものではない。

Access Token TTL、時計ずれ、ログイン取引期限、timeout、再送間隔・上限・期限、JWKS再取得、入力サイズ・レート・容量・GCの初期値は統合見本へ収録した。意味と制御単位は[運用設計](oidc-operations.md)に従う。これらは実測調整する初期値であり、設定値を守る製品実装が完成したことを意味しない。

## 変更可能な値と変更できない性質

期間・回数・運用間隔は設定で変更できる。一方、UV必須、code/管理許可の一回性、client/対象への結び付け、失効後の拒否、期限切れの確認結果を障害時にも延長しないことは設定で無効化できない。

署名アルゴリズム、鍵長、乱数の必要量、ID形式、暗号スイートは単なる運用間隔ではない。任意文字列での切替を認めず、採用プロファイルと互換性試験を変更する対象とする。アプリ絶対期限は元SSOを超えないという派生条件にし、矛盾する独立設定を増やさない。

## 有効化前の検証

- `app_idle_timeout <= sso_absolute_ttl`、`lease_ttl <= app_idle_timeout`かつ`lease_ttl <= sso_absolute_ttl`を要求する。
- 管理許可と認可codeのTTLはSSOの設定上限を超えない。実際の操作では保存済みの親セッション・許可の有効性も確認し、親の失効後に利用できない。
- `vault.unlock_idle_timeout <= vault.unlock_absolute_ttl`を要求する。
- 鍵運用の採用時は、事前公開期間がJWKSキャッシュ期間と確定した時計ずれ/配備猶予を覆うことを検証する。旧公開鍵の実際の保持期限は、設定値だけで決めず後述の履歴も考慮する。
- 実装が処理可能な整数範囲、最大bodyサイズ、設定サイズ等を超えた値は拒否する。上限を内部で勝手に丸めない。

不正設定はキー名と理由を示して新しい版の有効化を止める。正常な旧版がある場合は維持し、デフォルトへのフォールバックで誤設定を隠さない。設定値の検証に通ることと、その値が運用目的に適することは別とする。設定が欠落・破損している、またはD1から確認できないリクエストは新規認証・発行を停止する。

## 設定版と既存状態への適用

正規化した有効設定から`policy_revision`を作り、有効化操作IDと共に記録する。全キーをASCIIのドット区切りパスへ展開し、期間を秒の整数へ変換、schema_versionを含む全有効項目をキーの辞書順・空白なしのJSON objectとしてASCII符号化し、SHA-256を小文字hexへ変換する。コメントや`60s`と`1m`では版を変えない。初期schemaの値は整数のみとなり、浮動小数点やUnicode正規化に依存しない。後続の型追加はschema更新とする。[設計検証器](../scripts/check_design.py)を参照実装としてRustとの一致を試験する。設定版はtokenの公開claimとして必須化せず、サーバーの状態・監査記録に保持する。

D1には不変の設定版、active版を指す単一行、変更監査を分けて保存する。管理者は完全な候補版を登録して検証結果と差分を確認し、期待している旧revisionを条件にactive参照を原子的に切り替える。同時変更は一方だけ成功させる。リクエストは開始時にactive版とpayloadを同じ読取りで取得し、schema・hashを検証してから同じsnapshotを使う。初期実装では毎リクエストD1から読み、キャッシュの古さを失効保証へ持ち込まない。D1 read replicationを使う場合はprimary読取りまたは同等の新鮮さ保証を必要とする。切替中の処理は旧版か新版の完全な一方で完了し、監査に使ったrevisionを残す。

初期の通常変更は次の契約とする。

| 対象 | 適用方法 |
| --- | --- |
| 新規SSO・ceremony・管理許可・code・token | 発行時の設定から期限・上限とpolicy_revisionを保存 |
| 既存のSSO・code・token | 発行済み期限を維持。設定を延ばしても延命せず、短縮しても暗黙に切らない |
| アプリセッション | 作成時の未操作timeoutと元SSOの絶対期限を保持。新設定は新規アプリセッションから適用 |
| 新しい失効確認結果 | 照会を処理する設定版のlease_ttlを反映。既存のSSOの古い設定へ固定しない |
| 発行済みの失効確認結果 | 元の確認期限まで。設定延長・短縮で取得済みの期限を変更しない |
| Vault解錠 | 解錠時の設定を保持し、次回解錠から新設定。既存の解錠を自動延長しない |
| 既存の鍵・失効記録 | 保持期限を短縮しない。必要な検証期間が伸びる場合は保持期限を延長 |

既存セッションも即時に止めたい場合は、設定短縮とは別に明示的な全ログアウト/対象失効を実行する。設定変更や配備のロールバックで、失効済みセッション・sid・鍵を復活させない。

## アプリ・ブラウザへの設定伝達

mikakiとtossa・tsudoiで同じ値を別々にハードコードしない。認証されたサーバー間のセッション確認応答に、policy_revision、元SSO期限、有効性確認の最長期間、および新規アプリセッション用の未操作timeoutを含める。既存アプリセッションの未操作timeoutは作成時の値を維持する。

アプリは照会開始時からの期間と、親/ローカルセッションの残存期限の最小値を利用する。応答到着時から数え直さない。アプリ側の独自制限で短くすることはできるが、mikakiの指定を超えて延長しない。キャッシュする確認結果とアプリセッションの寿命を同一視しない。

Vault解錠UIには必要な公開設定だけをmikaki originから渡す。policy_revisionを含め、解錠中は固定する。ネットワーク断を理由に長い値へ戻さない。ブラウザ内の施錠設定は正常クライアントの動作契約であり、侵害された端末を遠隔消去する保証ではない。

## 失効保証を変更する配備

失効反映の上限は固定の「5分」ではなく、既定値5分のlease_ttlに依存する。短縮時はすでに発行した長い確認結果が残る。例えば5分から1分へ変えても、旧値を発行する配備を停止し、その最後の発行から最大5分が経つまでは「最大1分」と表示しない。

新旧設定版が切り替わる間は、双方が発行し得る確認期間の最大値を運用上限とする。延長時は新版が応答を始めた時点から、より長い上限になる。各応答と監査のpolicy_revisionで稼働版を確認し、ロールバックでも同じ移行判定を行う。新値の保証へ切り替えた時刻と値を監査に残す。

## 履歴を考慮する保持期限

旧公開鍵の削除可否は、設定の最小保持期間、実際に発行したtokenの期限、同鍵のID Tokenをhintとして使うセッションの期限、ログアウトhintの許容期間、確定した時計ずれを基に計算する。`retain_until`は単調に延長できるが、設定短縮で減らさない。30日から60日へSSO期間を延長する場合、32日という旧設定だけを根拠に公開鍵を削除しない。

失効sidや再送の記録も同様に、発行済み状態と通知期限から保持の下限を求める。GC猶予の設定だけで生存中の状態を消せないようにする。漏えい鍵の即時拒否は通常GCと別操作とする。

## 検証と運用手順

統合見本の検証項目は設計検証器に列挙した。未知の空テーブルも拒否する。配備先が対応するrate window、JWTとheader/bodyのサイズ関係、HTTP timeoutより長い配送lease、鍵事前公開とcache/時計ずれ/配備猶予の関係を検査する。サイズ等の初期実装上限を超える設定はレビューしてschema/試験を更新し、無言で丸めない。

運用手順は「設定編集 → 構文/型/関係の検証 → D1へ不変版を登録 → 有効設定との差分を確認 → 期待revision付きでactive版を切替 → 稼働版と保証移行を確認」とする。変更者・理由・時刻・旧新revisionを監査する。ロールバックも旧版へactive参照を再設定する管理操作として検証・記録し、失効済み状態を復活させない。署名鍵やtoken等の秘密は有効設定の表示に含めない。

実装時に、既定値だけでなく短い試験用設定でも同じ状態遷移・期限境界試験を行う。さらに未知キー、無単位・負数・ゼロ・桁あふれ、関係違反、設定延長/短縮、旧新配備混在、ロールバック、長期セッション発行後の鍵GCを確認する。今回の設定見本の構文検証は、将来の実行時検証器が完成したことを意味しない。
