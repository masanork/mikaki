# mikaki 実装仕様

> Historical implementation plan. It preserves the original acceptance gates and future design. For implemented and deployed behavior as of 2026-09-23, use [project status](status.md) and the relevant operational guide before treating any “not implemented” statement below as current.

2026-09-22 / Draft 5

開発優先順位は[ADR 0006](adr/0006-compact-portable-webauthn.md)に従う。まず小さなnative/Wasm共通WebAuthnコアを磨き、後続機能のために検証器の責務を広げない。

本書は認証・個人Vault・連合E2EEメッセージングを段階的に実装するための仕様である。実装済み・監査済みを意味しない。「必須」「禁止」は実装の受入条件、「初期案」は検証で確定する選択を表す。未決事項は末尾のゲートで管理し、実装者が暗黙に決めない。

既存のREADMEと分野別方針を具体化する。採用済みADRの契約を維持し、分野別仕様との担当範囲は[文書案内](README.md)に従う。本書が全分野を無条件に上書きするものではない。API名は論理操作名であり、HTTPパスやRustの公開シグネチャの確定版ではない。

## 1. 目的・非目標

- tossa・tsudoiのPasskey認証を共通の検証器に集約する。
- PRFを用いて本人の端末で鍵を解錠し、暗号化データを保存・復元する。
- 別々のCloudflareアカウント上のmikaki間で、端末を終端とするE2EE通信を行う。
- 利用者が選んだ会話を個人Vaultへ保管し、後にローカルMCPから限定参照できるようにする。
- 初期のOIDC連携と将来のコンテナ実行で、認証coreの処理と契約試験を共有する。

初期には既存互換、パスワード、SAML、SCIM、汎用マルチテナント、任意DIDメソッド、公開連合、グループUI、音声・映像、サーバー全文検索を実装しない。`webauthn-rs`を採用しない。独自ratchet・暗号プリミティブ・「soft MLS」を実装しない。

## 2. 開発単位と完成条件

| 段階 | 実装対象 | 次へ進む条件 |
| --- | --- | --- |
| P0 | 認証3 crate、ブラウザPRF検証ページ、本番接続用のOIDC | 認証・PRFの検証に加え、本番アプリ接続前にOIDCとログインUXの受入条件を満たす |
| S1 | MLS技術検証。P0後に独立して実施可能 | 実Wasmの2クライアントで参加・送受信・保存復元・鍵更新・除名を検証 |
| P1 | 個人Vault、鍵包み、同期 | アプリ間分離、端末Bでの復元、競合・失敗時のデータ保全 |
| P2 | 会話アーカイブ | tossa・tsudoiの許可された会話だけを取り込み、重複・編集・削除を検証 |
| P3 | MLS端末処理、限定連合 | S1合格後、別Cloudflareアカウント間の1対1往復と障害試験に合格 |
| P4 | ローカルMCP読み取り | 明示的な対象・期限・提供先に基づく開示と失効を検証 |
| 将来 | コンテナ、複数同時端末、グループ | 各々の利用要件と独立した仕様レビューを行う。OIDCは初期の本番接続から採用 |

共通アカウントはP0から認証の主体とする。アプリとの本番ログイン統合はG0/G1を満たしてから行い、P1のVault作成・解錠を前提にしない。P0の検証用画面と、本番の共通ログイン画面・連携方式は区別する。

後続段階の空crate・空trait・APIだけの先行実装は禁止する。S1の失敗は認証やVaultの開発を止めない。プロトコル変更はADRで記録する。

## 3. 脅威モデルと信頼境界

守る対象はcredentialの所有関係、ログイン結果、利用者の秘密鍵・本文、操作の一回性、暗号状態の継続性である。

想定する攻撃・障害は、不正クライアント、悪意ある連合相手、保存データの改変、鍵の差し替え、再送・並行処理、応答喪失、端末再起動、古い状態の復元である。

- 認証サーバーはログイン判定の信頼主体だが、Vault・会話の復号主体にはしない。
- 配送サーバーの鍵は配送認証だけに使う。端末の署名鍵・復号鍵と分離する。
- API認可だけでは暗号文の取得者による復号を防げない。復号鍵の配布範囲も制限する。
- DID Documentだけでは悪意ある管理者の鍵差し替えを防げない。初回確認と鍵の継続性確認が必要。
- 保存先からサイズ・時刻・宛先・アクセス頻度を隠すこと、可用性、全新規端末での完全な巻き戻し検知は初期保証外。
- 解錠中の端末侵害・XSS・悪意あるクライアント配信コードからの保護は保証しない。Rust/Wasmはこの信頼境界を消さない。
- 鍵や平文の配布後の回収は保証しない。失効は以後のアクセスと鍵世代について定義する。

### サーバー可読データとLockerの暗号境界

データを暗号化方式で一括分類せず、「サーバーが業務上復号する必要がある領域」と「Lockerの秘密領域」を分ける。OIDC subject対応、credential/セッション/失効状態、UserInfo生成に必要なclaim等は前者であり、認証・token・UserInfo処理中にサーバーが利用できる。現行のUserInfo初期profileは`sub`のみであり、claimを増やす場合は対象項目・保存期間・クライアント開示を別途定める。

Locker本文、タイトル等の意味情報、会話内容、添付用の秘密鍵は後者とする。クライアントが暗号化してから送信し、サーバーはciphertextと同期に必要な最小metadataを保存する。標準状態ではサーバー用KEK/KMSによるLocker鍵wrap、復旧用server escrow、サーバー復号fallbackを作らない。

利用者が明示的にシステム処理を必要とする個別データでは、対象・目的を限定したsystem principalを追加recipientにできる。例として任意blobへの必須ウイルス検査がある。暗号化データ鍵は利用者端末と、そのsystem principal向けに別々にwrapする。recipient wrapはOR条件であり、system wrapを持つ処理主体は単独で本文を復号できるため、そのデータは当該目的に限りserver-readableとして扱う。全Lockerや共通の万能system keyを受信者にしない。Login認証やAuthZENのallow判断だけでは鍵包みを作らず、暗号鍵の配布・復号を別の認可・監査対象とする。

UserInfo、アカウント管理、集計などサーバーが常時処理する情報は、利用者が開示を選ぶ属性か、システム運用上必要な情報かを区別する。利用者が任意に提供するUserInfo属性は、[Vault属性の限定共有案](vault-claim-sharing.md)として、対象属性だけを専用system principalと共有する方向を検討する。これはその属性をsystem-readableにする明示的な選択であり、通常ログインの必須項目にはしない。Locker内情報を統計へ使うなら、対象フィールド/collectionと目的を限定したsystem recipientを明示する。必須ウイルス検査は、Lockerへの確定前に隔離されたscan serviceで実施するか、継続再検査のためscannerをrecipientに含める。後者ではscannerが保存済み本文を復号できる能力を持つことを利用者に示す。

| データ区分 | 復号主体 | 鍵の方針 | サーバー侵害時の主な影響 |
| --- | --- | --- | --- |
| Server-operational data | mikakiの認証/OIDC処理 | 保存時暗号化に加え、機微項目を暗号化する場合は用途別KEKをKMS/HSM境界で管理する案。実行中の処理は復号権限を持つ | 当該処理・鍵権限の範囲でclaimや識別対応を読まれる可能性 |
| Locker content | 利用者が認めたclient/device。個別に許可したデータは指定system principalも含む | client-only root keyを標準とする。個別recipient wrapは目的・対象・鍵IDに結び付ける | DB/object store/通常APIの侵害だけでは本文を復号できない。system recipientに許可した範囲はそのサービス侵害で読まれ得る。可用性・改変・削除・metadata漏えいも残る |

暗号方式・鍵ラベル・AADで用途を分離し、server-operational keyをLocker key derivation/wrapに流用しない。system recipientは専用の鍵pairとサービスIDを持ち、鍵管理サービスの権限をその処理にだけ付与する。鍵包みの取得・unwrapはAuthZEN等の認可、目的制約、監査記録を要求する。鍵包みを除去して以後の取得を止めても、既に復号したrecipientから平文を回収できない。失効後の秘匿が必要なら、新しいデータ鍵で再暗号化し、過去の平文コピーまでは回収不能と明記する。

Lockerのobject metadataも秘密なら、名前・type・参加者等を暗号文内に置く。DB/object key、サイズ、更新時刻、アクセス頻度等、同期に必要な情報の開示は別途明記する。

この境界は、悪意あるWorker/app codeやWeb client配信の改変までLockerを保護するとは限らない。Web clientは復号時に平文・鍵へ触れるため、同じoriginから配信される悪意あるコードは解錠中に情報を外へ送れる。Locker保証は保存データ・APIの通常侵害に対する暗号境界として記述し、侵害済み配信基盤に対する保護は別のclient integrity対策なしに約束しない。

サーバー可読データの鍵運用は、平文のないバックアップ、暗号鍵とDB/object backupの整合、KMS停止時の障害動作、ローテーション中の新旧鍵読取、失効・削除手順を定義する。Lockerは全端末・credentialの鍵wrap喪失で復旧不能となり得る。認証アカウント復旧をLocker鍵復旧と同一視しない。

PRF出力・解錠鍵・平文秘密鍵を、API本文、URL、ログ、トークン、分析基盤へ送ることを禁止する。サーバーがJWEを復号してVault鍵を返す方式も禁止する。「保存しない」だけではこの条件を満たさない。

数年以内のPQC移行を設計条件とし、[暗号方式の移行方針](crypto-agility.md)に従う。初期の方式限定は維持しつつ、鍵・データ形式・クライアント登録を特定方式へ固定しない。

## 4. crate構成

### 4.1 段階的なworkspace

| crate / package | 導入 | 責任 | 持ち込まないもの |
| --- | --- | --- | --- |
| `mikaki-webauthn` | P0 | 入力解析、WebAuthn暗号検証、検証済み事実の型 | DB、HTTP、Workers、業務認可 |
| `mikaki-auth` | P0 | ceremony、credential管理、AccountId、ストアの原子的契約 | Vault、MLS、DID、Workers型 |
| `mikaki-oidc` | G1/P0本番接続 | OIDC、client認証、セッション、JOSE用途別検証、outboxとストア契約 | D1/Workers型、Vault、MLS |
| `mikaki-worker` | P0 | composition root、Service Binding/HTTP、D1、後にR2/DO、設定・時刻・乱数 | 端末秘密鍵、PRF処理、OpenMLS |
| `mikaki-browser-wasm` | P0検証・ローカル | ブラウザとローカルharness向けJSON/Wasm境界 | Cloudflare binding、認可の確定 |
| `mikaki-vault` | P1 | grant、暗号文オブジェクトの版管理、同期の状態遷移とストア契約 | 復号、OpenMLS、Cloudflare型 |
| `mikaki-client` | S1/P1 | 端末側の鍵保護と状態遷移。S1でMLSモジュール、P1でVaultモジュール | サーバー認証core、D1、R2、HTTPサーバー |
| `mikaki-federation` | P3 | 限定DID検証、配送許可、envelope検証、重複排除・再送契約 | 本文復号、MLS秘密状態、Cloudflare型 |
| `packages/browser`（TS） | P0 | WebAuthn API、UI、IndexedDB、ブラウザ通信、Wasm呼び出し | 独自暗号プロトコル、サーバー認可の代行 |

認証開始時は3 crate、連合段階でも原則6 crateとする。数は上限目標であり、責任を混ぜるための制約ではない。`mikaki-client`のVault/MLSを独立公開・再利用する必要が生じた場合だけ分割を再検討する。

```text
mikaki-worker ──→ mikaki-oidc ──→ mikaki-auth ──→ mikaki-webauthn
       ├────────→ mikaki-vault
       └────────→ mikaki-federation

mikaki-browser-wasm ──→ mikaki-auth / mikaki-webauthn

packages/browser ──→ mikaki-client (Wasm)
                          ├─ vault / keywrap モジュール
                          └─ mls モジュール ──→ OpenMLS
```

矢印はCargo依存または明記したWasm呼び出しを示す。`vault`と`federation`は`auth`に依存せず、入口で確定したactorと、自分のストア内のgrant/受信許可を使って判断する。HTTPからactorの自己申告を受け入れない。これらの内部APIの呼び出し元は信頼されたcomposition rootである。

### 4.2 境界規則

- coreの公開APIに`worker::Env`、D1、R2、DO、Axum、JS値を露出させない。
- パーサー・検証器は同期の純粋処理を基本とし、時刻・乱数・I/Oは外側から供給する。
- ストアtraitは消費、条件付き公開、重複排除などの業務操作とする。汎用Repository/ORM抽象化を作らない。
- 検証済み事実の型は非公開フィールドを持ち、無検証コンストラクタとDeserializeを提供しない。
- `mikaki-client`はNative試験用の`rlib`とWasm用の`cdylib`を提供する。wasm-bindgenの公開口は薄い境界モジュールに閉じ込める。
- ブラウザのWebAuthn/IndexedDB/画面処理はTSでよい。P0の小さなPRF試験をRust化するためだけにcrateを追加しない。
- サーバーの依存グラフにOpenMLS・端末の鍵包み処理が入らないことをCIで確認する。featureの組合せを増やさず、使う構成だけ試験する。
- 自作Rustは原則`unsafe`禁止。依存のunsafe・Wasm乱数源・ライセンス・利用条件を別に評価する。

将来の`server`（Nativeアダプター）とMCPは必要時に追加する。SQLx/TursoはNativeストア実装の選択であり、現時点のcore依存にはしない。認証3 crateから検証を始め、G1の実装着手時にOIDCを独立crateとして追加する。worker → oidc → auth → webauthnの依存とし、詳細は[初期OIDC実装基準](oidc-implementation-readiness.md)に従う。署名/ストアポートをcoreに置き、WorkersやD1の型はworkerアダプターに閉じ込める。

言語・runtimeの適用範囲とローカルJS実装からの移行条件は[ADR 0009](adr/0009-rust-oidc-and-worker-stack.md)に従う。workers-rsではD1原子操作・`FirstPrimary` read・非同期cryptoの一部をlocal workerdで実証済みだが、全面採用の判断には[残るゲート項目](adr/0009-rust-oidc-and-worker-stack.md#workers-rsの実証ゲート)を確認する。

## 5. 認証仕様（P0）

### 5.1 固定プロファイル

WebAuthn Level 3の登録・認証検証を基準に、ES256/P-256、UP/UV必須、residentKey=`required`、attestation要求の既定を`none`とする。登録時は`credProps`を要求し、`rk=true`をクライアント互換性条件として確認する。ただしこれは署名された本人確認情報ではない。

RP IDと許可originは設定で固定し、ワイルドカード、要求のHostからの推測、クライアント指定の上書きを禁止する。初期はcross-origin iframe ceremonyと関連origin拡張を扱わない。`crossOrigin=true`は拒否する。

検証対象は、type、challenge、origin、rpIdHash、UP/UV、credential ID、userHandle、COSEのkty/alg/crvと座標、署名、AT/EDを含む構造・長さである。登録は`fmt=none`と空attStmt、またはES256 packed self-attestationを受け付ける（[ADR 0007](adr/0007-packed-self-attestation.md)）。製品の既定設定では証明書付きattestationのtrust storeを渡さない。[ADR 0008](adr/0008-webauthn-conformance.md)に基づき共通検証器はpacked full/U2F/TPMとMDS検証にも対応し、明示的に認証済みmetadataを渡した場合に限り使用できる。x5cが存在するpackedをselfへフォールバックしない。共通コアの`attestation_policy=required_trusted`はnone/selfを拒否し、成功時は検証済みの方式・信頼anchor等の証跡を返す。製品はoptional既定を維持する（[契約](webauthn-attestation.md)）。必須項目の重複、末尾の余剰データ、不正なbase64url、サイズ・深さ上限超過を拒否する。未知の非必須フィールドは規格とパーサー方針に従い扱い、独自の意味を付けない。

署名カウンタは保存するが、常に増えることをPasskey全体の前提にしない。BE/BS整合性とBE継続性を検証する。非バックアップcredentialで両カウンタがゼロではなく増加しない場合は初期方針として認証を拒否し、バックアップ可能credentialはカウンタだけで一律拒否しない。この判定は互換性試験と監査対象とする。

### 5.2 論理APIと状態

| 操作 | 前提 | 結果 |
| --- | --- | --- |
| `BeginRegistration` | mikakiの新規登録許可、または既存所有者の直近UV | AccountId・caller・目的に固定したchallenge/options |
| `FinishRegistration` | 同じブラウザ操作への結び付け、未消費challenge | credential登録とchallenge消費が共に確定 |
| `BeginAuthentication` | callerとブラウザ操作の固定 | discoverable認証のchallenge/options |
| `FinishAuthentication` | 有効なassertion、credentialが有効 | credentialから確定したAccountIdと認証時刻（内部結果） |
| `ListCredentials` | mikakiの管理入口で所有者を認証・認可 | 秘密を含まない一覧 |
| `DeleteCredential` | 所有者の直近UV、残存credentialの確認 | 無効化。物理認証器内の鍵消去とは区別 |

登録の初期許可はmikakiが管理する招待/承認とし、公開自己登録は追加しない。アプリへの参加承認と共通アカウントの登録許可は別とする。AccountIdはmikakiが割り当てる不透明ID。認証完了要求のAccountIdやsubjectを結果の根拠にしない。最後の有効credential削除は拒否する。アカウント削除は別機能。

招待の発行者・一回性、初回管理者bootstrap、全Passkey紛失時に既存account復旧を提供しない初期契約は[ADR 0005](adr/0005-invitation-bootstrap-and-recovery.md)に従う。通常招待から既存accountのcredentialを再設定しない。

challengeはCSPRNGで32 byte生成し、期限は初期値300秒、`now >= expires_at`で失効する。ブラウザには推測困難なceremony IDを渡す。ストアにはcaller、目的、対象、origin/RP条件、ブラウザ結び付け、期限を保存する。クライアントが同じ値を送るだけではブラウザ結び付けにならず、アプリ側セッションとCSRF検証を必要とする。

完了処理は「読み取り→暗号検証→有効期限/未消費/credential版を条件とする原子的確定」とする。challenge消費だけ成功してcredential登録を成功扱いする実装は禁止。並行要求の成功は高々一つ。無効なassertionは成功状態へ進めず、試行数を制限する。

応答喪失後に完了を再実行しても二度目の認証成功を発行しない。初期版では新しいceremonyから再開し、登録済みcredentialは所有者の認証後に確認する。削除と認証の競合では確定時のcredential有効性を再確認する。削除前に発行済みのアプリセッションの失効は、認証core外でセッション・ログアウト仕様に従って行う。

Service Bindingは私的入口とし、callerはデプロイ境界で認証する。caller文字列の自己申告を信頼しない。mikakiの認証・管理入口と一般の連携アプリを区別し、連携アプリに共通credentialの追加・削除権限を与えない。binding/入口の分離かアプリ別資格情報による識別をG1で固定する。各アプリは自分のセッション・業務認可・CSRFを担当し、mikakiは認証画面のセッション・CSRF・ceremonyとの結び付けを担当する。

## 6. 共通アカウント・ブラウザ境界（P0から本番アプリ統合）

インスタンスごとにmikakiの共通アカウントを持ち、tossa・tsudoiの通常ログインもこのアカウントを利用する。認証・解錠originとRP IDはインスタンスごとに一つに固定する。これは採用方針であり、実ドメインはG0/G1で確定する。P0の隔離した検証配置からアプリ別アカウントを本番へ持ち込まない。任意の別originにPRF秘密を渡して共有ログインを成立させない。[ADR 0001](adr/0001-common-account.md)に決定を記録する。

`AccountId`、アプリ別`SubjectId`、`VaultId`、利用者DID、端末IDは別の識別子とする。アプリとの対応表は本人の認証・許可から作り、メール一致で統合しない。通常のエンティティIDはUUIDへ寄せる方向とし、v4/v7の用途別比較・形式案を[識別子方針](identifier-policy.md)に整理する。DIDは連合で必要な役割に限定し、秘密値や規格固有の識別子をUUIDへ置き換えない。

credentialはAccountIdに所属する。認証coreはAccountIdを内部結果として返し、アプリ連携の入口が登録済みアプリと本人の許可を確認してアプリ向けsubjectへ対応付ける。SubjectIdの発行・対応表の管理方式とアプリへの公開識別子はG1で固定する。[識別子・署名鍵設計案](oidc-identity-and-keys.md)にpairwise sub、接続解除後のID維持、署名鍵更新と論理ストア契約の候補を示す。同案はレビュー用であり採用未確定。組織・役割・参加権限は各アプリが管理する。

通常ログインにVaultの作成・解錠やPRF成功を要求しない。Vaultは共通アカウントに必要時に作成する。アプリへのログイン許可はVaultの読み書き権限を含まず、会話保存と既存会話の読み取りも別のgrantとする。アプリ接続の解除を共通アカウントや他アプリの削除として扱わない。保持期間と失効・接続解除は[セッション・ログアウト仕様](session-lifecycle.md)に従う。SSOの既定値30日、失効確認期間の既定値5分と確認不能時の処理停止を初期契約として採用する。期間・回数の変更と旧新設定の適用は[運用設定契約](runtime-configuration.md)に従う。

共通ログインは最初の本番アプリ接続からOIDC Authorization Code Flow＋PKCE S256を採用する。登録済みredirect URI、state、nonce、一回限り・短寿命・client固定のcode、バックチャネル交換を必要条件とする。独自のログイン結果伝達方式を先行実装しない。[ADR 0002](adr/0002-oidc-from-first-release.md)と[初期OIDCとログインUX](oidc-login.md)に採用判断と受入条件を定める。初回の接続確認は認証画面に統合し、許可済みアプリへの通常ログインでは有効なmikakiセッションを利用して不要な確認・Passkey操作を省く。

解錠UIは独立originのトップレベル画面を基本とする。アプリには鍵ではなく許可された読み書き操作を提供する。popup等を使う場合はexact origin、送信元window、要求ID、期限、ユーザー同意を検証し、`postMessage('*')`を使わない。読み出した平文を受け取るアプリは、そのデータの信頼された受信者となる。

## 7. PRF・鍵保護

認証成功とVault解錠成功を別結果とする。PRF非対応でも認証は可能だが、鍵保護操作は明示的に失敗させる。

初期暗号プロファイル案はHKDF-SHA-256とAES-256-GCMとする。以下の入力エンコード、label、暗号形式をG2でバイト単位に固定し、既知解テストを作ってから永続データを書き始める。

1. credential/Vaultごとの公開PRF入力（32 byteランダム）を初回に生成・保存する。同じ鍵包みの解錠では同じ入力を使用する。
2. ブラウザのWebAuthn PRF評価結果をHKDFのIKMとし、保存したランダムsalt、用途label、版、RP、Vault、credentialを区別したcontextから32 byteのKEKを得る。
3. ランダムな32 byteのVault root key (VRK)を生成する。KEKでVRKを認証付き暗号化する。各Passkey credentialは独立したwrapを持つ。
4. collection key (CK)をcollectionごとに生成してVRKで包む。blob/objectごとにランダムなdata-encryption key (DEK)を生成し、本文をDEKで暗号化、DEKをCKで包む。アプリへVRKを渡さない。初期のアプリ連携は解錠UIによる操作仲介とし、鍵の直接委任は後続機能とする。
5. 各AEAD呼び出しは新しい96-bit nonceを生成する。鍵ごとの使用量上限と更新を定義し、エラー時のnonce固定・再利用を禁止する。

暗号文は一度だけ作り、復号権限を付与する受信者ごとに対象鍵のwrapを追加する。初期P1の受信者は所有者の登録済みPasskey credentialのみ。将来、共有collectionには共有相手の暗号化公開鍵でCKをwrapし、特定blobのシステム処理には専用system principalの公開鍵でDEKをwrapできる形式にする。複数wrapはOR条件であり、いずれか一つを復号できる受信者は同じ本文を読める。複数者の共同承認を求めるものではない。

共有相手用の公開鍵はWebAuthn認証鍵と別の暗号化鍵として登録する。公開鍵とAccountId/device/service principalの結び付きを検証し、鍵更新・失効を既存の信頼済み端末から承認する。鍵directory侵害による差し替えを防ぐ公開鍵継続性/透明性の方式が決まるまで、共有相手への本番鍵配布を有効化しない。受信者秘密鍵は本人または専用system key serviceが保持し、mikakiの一般APIやStorage Workerへ渡さない。

AADには形式版、用途、Vault、コレクション/オブジェクト、鍵世代、対象credential（wrapの場合）を含め、曖昧な文字列連結を使わない。秘密鍵と平文にはDebug/Serializeの不用意な公開を避け、可能な範囲でメモリを消去する。JS/Wasm環境で完全消去を保証しない。

追加Passkeyには、既存の解錠済み端末で本人が許可し、新しいPRF評価から同じroot keyのwrapを作る。サーバーには新しいwrapだけを送る。別端末への引き渡しが必要な場合は双方の確認を含む別手順をG2で固定する。

全復号経路喪失時のサーバー復旧は初期版では提供しない。アカウント再登録で旧Vaultを自動上書きしない。失効したcredentialが旧root keyを知る可能性は残る。以後の秘匿が必要な場合はroot/下位鍵の世代更新を行い、API無効化だけで暗号学的失効と呼ばない。

## 8. 個人Vaultと同期（P1）

### 8.1 データと操作

| レコード | 必須の意味 |
| --- | --- |
| `Vault` | owner、形式版、現在の鍵世代 |
| `KeyWrap` | owner credential、PRF入力、KDF salt/context版、鍵種別・世代、nonce、暗号文。PRFはVRK unwrapにだけ使う |
| `KeyEnvelope` | 対象鍵（CK/DEK）、scope、recipient種別/ID/key ID、purpose、suite/version、鍵世代、HPKE encapsulated key/ciphertextまたはowner AEAD wrap |
| `Grant` | owner、アプリ/委任先、コレクション、操作、期限、失効版 |
| `ObjectHead` | オブジェクトID、現在版、暗号文ハッシュ、R2参照、削除状態 |
| `Mutation` | owner、operation ID、要求ハッシュ、結果版、確定状態 |

タイトル・本文・会話参加者など、検索に不要なアプリ意味情報は暗号文の内側に置く。サーバーに必要なID、サイズ、時刻、grant情報は平文メタデータとして開示を明記する。KeyEnvelopeは認可記録そのものではなく、AuthZEN/Grantが許可した相手へ包みを配布するための暗号材料である。APIは暗号文取得とKeyEnvelope取得を別操作・別権限として扱う。

論理操作は`CreateVault`、`AddKeyWrap`、`GetSnapshot`、`PutSnapshot(expected_revision, operation_id)`、`DeleteSnapshot(expected_revision, operation_id)`、`ListChanges(cursor)`、`Grant/Revoke`。将来は`AddRecipientEnvelope`と`RevokeRecipient`を追加する。Grant作成と対応するenvelope公開は一つの確定操作として扱い、許可のない宛先へ暗号鍵を公開しない。各操作でowner/grantと期限・失効を確認する。

recipient失効には二段階ある。API/AuthZENで対象の読み出しとenvelope取得を直ちに止めるのがアクセス失効である。相手が既に鍵と暗号文を保存していれば、その過去データは復号できるため、過去に渡した能力の回収とは表現しない。

失効後に作られる新しい内容を読ませない場合は、新しい鍵世代へ進める。共有collectionでは新CK epochを作り、残るrecipientだけにwrapする。更新されるblob/objectは新DEKで本文を再暗号化し、残るrecipient向けに鍵包みを作る。同じDEKを再利用したままwrapだけ更新しても、旧recipientがDEKを保持していれば新しい本文も復号できる。未更新の既存objectはサーバーからの配布を止めるが、相手が既に取得したciphertextの復号は止められない。ownerが不在でrotationが完了していない間は、アクセス拒否を先に適用し、当該scopeへの新規書込みを保留する。ownerが共有解除操作中に解錠済みなら、その場でepoch更新を完了できる。

DB/R2に残る既存blobを新しいDEKで一括再暗号化する「保存中データの再鍵化」は既定にしない。共有相手が過去のblobを保存している可能性があるため、再暗号化しても既に渡したコピーは保護できず、全履歴を処理する費用に対する便益は限られる。必要な要件がある場合だけ、漏えいした旧鍵でサーバー保管中の現行blobを読まれる期間を減らす追加策として実行する。

サーバーがrecipientの秘密鍵またはunwrap権限を持ち、対象データを復号できる場合は、サーバー主体で再鍵化を自動実行できる。ただしその対象は既にserver-readableであり、サーバー運営者・当該サービス侵害からLocker本文を秘匿する保証はない。scan専用principalの権限を一般的なrotationに転用しない。サーバーに復号能力を与えない標準Lockerでは、所有者または残る復号権利者の端末がrotationを行うまで、APIの読み出し停止で保護する。

書込権限と復号権限は別であり、共通DEKを知る複数者間の作成者識別には署名付きrevision等が別途必要となる。

ローカルはIndexedDB。復号済み本文・秘密鍵をlocalStorageに置かない。P1は小さなコレクション単位のスナップショットとし、CRDT・自動マージ・添付ファイルは含めない。

### 8.2 リモート確定手順

1. クライアントは暗号化済みの変更をローカルoutboxに保存する。
2. Workerは認可とサイズを確認し、版ごとに不変なR2オブジェクトへ暗号文を保存する。
3. D1の条件付き更新でexpected revision、grant有効性、operation IDを確認し、headとmutation結果を同時に確定する。確定失敗時は旧headが正本のまま。
4. 応答喪失時は同じoperation IDと同じ要求を再送する。同ID・異なる要求ハッシュは拒否する。成功済みなら同じ結果を返す。
5. クライアントが確定結果をローカルに記録してからoutboxを除去する。

R2保存後のD1失敗で生じる孤立blobは参照状況と猶予期間を確認して回収する。GCと新規公開の競合を避け、公開済みblobを消さない。D1/R2をまたぐトランザクションは仮定しない。

競合時はローカル変更を保持して`Conflict`を返す。削除も版付きtombstoneとして記録し、初期版はtombstoneを自動失効させない。期限切れの同期cursorは全head/tombstone再取得を要求し、古い端末の無条件上書きを禁止する。長期履歴バックアップは初期保証外であることをUIに表示する。

`Missing`、`FetchFailed`、`DecryptFailed`、`UnsupportedVersion`、`Conflict`を区別する。`DecryptFailed`から鍵生成・上書きへ遷移する経路は禁止する。

## 9. 会話アーカイブ（P2）

入力はsource app、source conversation/message ID、送信者の名前空間付きID、source revision、時刻、本文、schema versionを持つ。元アプリ・会話・メッセージIDの組で重複判定する。内容の出所と暗号学的な送信者検証結果を別フィールドにする。

初期は明示的インポートとし、所有者が許可したコレクションにだけ書く。新しいsource revisionで編集を取り込み、同じrevisionで異なる内容は競合とする。削除は出所の削除イベントと本人のアーカイブ削除を区別し、後者は再取り込み抑止を残す。元アプリの削除を個人コピーからの完全回収とは表現しない。

検索は解錠したクライアント内。アプリ間の読取り共有は個別grantを要求する。MLS会話の長期保管には別のVault鍵を使い、過去のMLS秘密状態を履歴復号のために無期限保存しない。

## 10. MLS端末プロトコル（S1/P3）

### 10.1 採用ゲート

RFC 9420 MLSを第一候補とし、OpenMLSを評価する。初期スイート案は`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`一つ。MLSの標準形式を変更せず、PQ独自拡張を入れない。Wasmのビルド成功だけを採用根拠にしない。

OpenMLSの対応ターゲット、利用条件、依存、既知問題、暗号provider、永続化形式を採用時点で固定する。S1が不合格なら採用を止め、vodozemac等を別ADRで比較する。DIDComm全体とMatrix homeserverは初期スタックに含めない。MLS採用はMatrix互換・標準federation互換を意味しない。

初期は2人・各1 messaging deviceをMLSの2 leafとして扱う。複数Passkeyは同じVaultの解錠手段であり、同じMLS状態を複数端末で同時に動かす根拠にはしない。

### 10.2 本人と端末鍵

インスタンスDIDと利用者DIDを分離する。初期案はインスタンス=`did:web`、利用者=`did:key`（Ed25519）。利用者DID鍵とMLS端末署名鍵は別にランダム生成する。PRFからMLS署名鍵・ratchet状態を毎回再生成しない。

利用者は端末ID、MLS署名公開鍵、用途、世代、有効期限、配送先とのbindingを署名する。検証する署名形式とバイト表現はG3で既存形式に固定し、独自の曖昧なJSON署名を作らない。MLS BasicCredentialにDIDを入れただけでは本人確認完了としない。KeyPackageの自己署名・有効期限と、このbindingの両方を端末で検証する。

初回は相互招待と別経路の指紋照合で連絡先を固定する。インスタンス文書更新だけで利用者鍵を自動信頼しない。`did:key`の鍵変更は新DIDとして再確認する。旧鍵がない場合の無人の同一人物認定はしない。任意DID解決・JSON-LD取得はしない。

### 10.3 状態保存と送受信

MLSの秘密状態はVaultスナップショットの一般同期から除外し、端末ローカルの暗号化IndexedDBへ保存する。コピー/バックアップの復元で古いratchetを再利用しない。端末移行は新deviceとして参加し直す。旧履歴は必要に応じてVaultアーカイブから読む。

端末内では一つのwriterに限定する。複数タブはロックと状態revision CASを使い、同じ状態からの並行送信を拒否する。Web Locks等が使えない環境では単一タブに制限し、無保護のフォールバックをしない。

- **KeyPackage**：生成後の秘密状態と公開待ちデータを同じローカルトランザクションに保存してから公開する。配送側の取得は一回消費を原子的に行う。
- **送信**：最新状態から暗号化し、更新状態と送信する正確な暗号文を同じトランザクションに保存する。その後に送信する。失敗時は同じ暗号文を再送し、同じ旧状態から再暗号化しない。
- **受信**：検証・復号後の状態、処理済みID/cursor、必要なら暗号化した表示用履歴を同時保存してから処理済みを通知する。重複でratchetを二度進めない。
- **保存失敗**：メモリ中の更新済みclientを利用し続けず処理停止・再ロードする。例外をbest-effortとして握り潰さない。
- **Commit**：順序付けサービスの採用確認前に無条件mergeしない。pending commitを保存し、競合commitの採用時はOpenMLSの正規手順で解消する。
- **復元失敗**：新規client/groupの自動生成で隠さない。鍵世代不一致・破損・非互換を表示し、明示的な再参加を要求する。

MLS payloadにはアプリ形式版、会話ID、メッセージID、内容を含め、外側の宛先・会話と照合する。署名者はMLSで検証したcredential/bindingから決め、配送サーバーのsender欄を本人の根拠にしない。

S1ではWelcomeのratchet tree受渡し方式、proposal/commit処理、epoch遷移、秘密削除、受信順序窓を実装ライブラリの仕様に合わせ固定する。前方秘匿性・侵害後回復は適切な鍵更新と古い秘密の削除が前提であり、Vault内に保存した本文の保護とは別とする。

## 11. Cloudflare連合配送（P3）

初期接続先は相互許可した2インスタンス。異なるアカウント間をHTTPSで結び、共通D1、共有binding、共通管理資格情報を必要としない。インスタンス内部のみService Bindingを使える。

論理操作は`Publish/ConsumeKeyPackage`、`Submit`、`FetchSince`、`BlockPeer`。KeyPackageの返却は同じものを並行取得できないストア操作にする。公開DIDを知るだけで取得・投入を無制限に許可しない。

会話ごとに一つのhome coordinatorを初回に固定し、Commitの順序を決める。DOはその順序・受理記録を保持し、相手インスタンスは受信箱を保持する。home障害時の自動切替、複数homeでの同時書込みは初期対象外。配送payloadは不透明でも、epoch等の外側申告だけを信用してMLSの正当性を保証しない。

配送envelopeにはversion、delivery ID、送受信インスタンス、recipient、conversation、kind、expires_at、payload hash、payloadを含める。受信インスタンスは送信インスタンスを認証し、宛先・期限・受信許可・サイズを検証する。輸送署名/MACの標準方式とリプレイ窓はG3で固定する。TLSだけで利用者本人を認証したとしない。

送信元は永続outboxを持つ。受信側はsender instanceとdelivery IDの組で一意制約を持ち、同ID・同hashは同じ受理結果、同ID・異hashは拒否する。受理応答は受信箱の永続化後に返す。DO/D1等の複数資源間ではoutboxと再処理を使い、分散トランザクションやexactly-onceを仮定しない。

状態は`queued`、`remote_stored`、`expired/failed`を区別する。`remote_stored`は端末での復号や既読ではない。初期は既読通知を実装しない。指数バックオフ・jitter・試行期限を設け、期限後の欠落や同期不能をUIへ明示する。

DID/配送先取得は許可先HTTPSのみ、リダイレクト既定禁止、接続先/port制限、timeout、応答サイズ上限を適用する。任意URLへのプロキシにしない。ブロック・quota・課金攻撃への制限は認証後も適用する。

Workerは復号しない。暗号化本文の小さな配送から始め、R2添付、WebSocketの最適化、公開探索は後に回す。

## 12. MCP・将来のNative

P4は本人の端末上のMCPを基本とし、`List/Search/Read`のみ。解錠期限と、対象コレクション/会話・操作・提供先・期限を含むgrantを毎回強制する。読み取り許可は送信、削除、権限付与を含まない。検索の件数・抜粋にも同じ制限を適用する。

MCPへ返す平文は利用者が認めた外部開示である。OAuthトークンだけで復号できる設計にはしない。ローカルプロセスとの接続認証と鍵を渡すか操作だけ仲介するかをG4で確定する。会話本文を権限変更命令として扱わない。監査は対象ID・操作・結果を残し、本文や鍵を残さない。

初期OIDCの契約は第6節と専用仕様に従う。ID TokenとAPI access tokenを混同しない。Native実行では同じcoreのストア契約を実装し、Turso/SQLx等はその時点で評価する。WorkersとNativeで判定を別実装しない。

## 13. 初期制限・エラー・運用

以下はmikakiの初期案であり、Cloudflareの製品上限ではない。負荷試験で変更する場合は仕様とテストを一緒に更新する。セッション関連の採用済み初期値は[運用設定](runtime-configuration.md)へ分離し、値の変更だけでコード編集を要求しない。設定スキーマ・適用規則や安全性要件を変える場合は仕様と試験を更新する。

| 対象 | 初期値/規則 |
| --- | --- |
| ceremony | TTL 300秒、challenge 32 byte、1件の完了失敗は最大5回 |
| WebAuthn HTTP body | 64 KiB、JSON/CBORの最大深さ8。個別フィールド上限も実装前に固定 |
| credential | 1 account最大10、有効な最後の1件は削除不可 |
| Vault snapshot | 暗号文1 MiB、ownerあたり初期100 MiB |
| 会話本文 | UTF-8で8 KiB、配送envelope最大256 KiB |
| KeyPackage | 1 deviceあたり未消費最大20、初期有効期間7日。実際のMLS Lifetimeも照合 |
| 配送 | 期限7日、重複記録は有効期限＋24時間以上保持。期限切れenvelopeは常に拒否 |
| 同期 | 無条件上書き禁止、tombstone自動削除なし |

endpoint/caller/account/peerごとのrate limitと総容量、最大再送回数、GC猶予は各段階のリリース前に設定・試験する。未設定を無制限として公開しない。

エラーは不正入力、未認証、権限なし、期限切れ、再利用、競合、未対応、容量超過、一時障害、復号失敗を区別する。外部応答ではアカウント存在や内部情報を不要に漏らさず、内部の構造化理由コードと分ける。任意の例外文字列をそのまま返さない。

ログは相関IDと結果・遅延・サイズ中心。credential識別子等も必要最小限とする。本文、assertion全体、token、鍵、Wasm秘密状態を記録しない。秘密を含むdebug featureはリリースbuildで禁止する。安全な変更ロールバックと、暗号状態/DBを巻き戻す危険な復元を区別する。

## 14. 受入試験

| ID | 必須の検証 |
| --- | --- |
| A1 | 改変署名、origin/RP/目的違い、UP/UV不足、credential/userHandle取り違え、失効credentialを拒否 |
| A2 | 同じchallengeの並行完了は高々一成功。消費/登録の途中失敗、削除との競合、期限境界 |
| A3 | JSON/CBOR/COSEの境界・重複・切断・巨大入力のfuzz、Native/Wasm一致、検証済み型の偽造不可 |
| O1 | OIDC専用仕様の受入条件。code/PKCE/state/nonce/ID Token検証、初回接続、SSO、キャンセル、Vault未解錠、明示的再認証 |
| K1 | PRF既知解、再ログイン解錠、別Passkey wrap、誤った鍵・AAD・改変の拒否。サーバー通信に秘密なし |
| V1 | 端末A→B復元、同時更新の一方競合、R2/D1各失敗、成功応答喪失、削除後の古い端末同期 |
| V2 | MissingとDecryptFailedが別結果。復号失敗時の再生成・上書きなし。grant外の読書き拒否 |
| M1 | 実OpenMLS/Wasmで2者のWelcome参加・往復・状態export/import・更新・除名後の新規通信拒否 |
| M2 | KeyPackage生成直後/送信確定前後/受信確定前後のクラッシュ、保存容量超過、複数タブ競合 |
| M3 | DID/端末鍵/KeyPackageの差し替え拒否、自己申告senderを無視、Commit競合・epoch欠落からの明示的回復 |
| F1 | 異なるCloudflareアカウント間の往復、オフライン受信、重複/順序逆転/再起動/応答喪失 |
| F2 | inbox永続化前の成功応答なし。同ID異payload、期限切れ、block、SSRF、quota超過を拒否 |
| P1 | 許可された会話だけのMCP一覧・検索・読取り、失効・期限・本文からの権限拡大拒否 |

モック試験だけでM1/F1を満たしたとしない。主要ブラウザ/OS/認証器の実測対応表を残す。PRF実機試験とWebAuthn仮想認証器試験を区別する。D1/DO/R2の契約はローカルと隔離した実Cloudflare環境で試験する。実環境の作成・デプロイは別途承認のもと行う。

テストの合格は外部監査や完全な安全性証明ではない。独立したテストベクトル、相互運用試験、依存監査と組み合わせる。Kani/TLA+は対象不変条件が明確になった時だけ導入する。

## 15. 未決事項と着手ゲート

| ゲート | 決めること | 止める対象 |
| --- | --- | --- |
| G0 | 実RP/origin、対象ブラウザ/認証器、パーサー/暗号依存、D1の条件付き確定SQLと契約試験 | P0の本番接続。Native検証器と試験は先行可 |
| G1 | 共通origin/RPの実値、アプリ登録・許可、subject対応、ログイン結果伝達、セッション/接続解除のAPI・永続化・競合制御、cookie属性、運用設定の読み込み・検証・配備、管理入口の分離、OIDCのissuer・署名/鍵更新・token/client認証・依存/実装境界 | P0の本番アプリ接続。Vault実装まで先送りしない |
| G2 | VRK→CK→DEKの鍵階層、PRF/AEAD suite、AADとowner envelope encoding、鍵世代更新、新端末引渡し、対象容量と保持。P1で実装する受信者はowner credentialのみ | Vault形式の確定と永続データ作成 |
| G3 | OpenMLS採用判定、DID組合せ、binding/輸送認証形式、MLS tree/Commit順序・復帰、制限値 | 製品用連合。S1技術検証は先行可 |
| G4 | MCP接続認証、対象の選択UI、解錠期限、監査保持、モデルへの開示表示 | MCP公開 |
| G5 | 共有単位（collection/blob）、共有相手/system principalの暗号化公開鍵登録・差し替え防止/継続性検証、Grant/AuthZENとKeyEnvelopeの原子的な公開・失効、recipient単位の鍵epoch更新、purpose別system key serviceと監査、必須ウイルス検査の隔離/判定/再検査フロー、署名付きrevisionとrollback保証範囲、共有用HPKE suite | Lockerの共有とシステム復号 |

未決の項目を「実装時に適当に決める」状態で残さず、各ゲートでADRと試験を揃える。G2を通過する前に永続Vaultデータを書き始めない。G5を通過する前に共有相手やsystem principalへの鍵包み配布を有効にしない。利用者の配備ドメイン・接続先・AI提供先などの選択は実装者が推測で固定しない。

G1の設計上の選択、HTTP・ストア・運用制限・依存候補・実装順は[初期OIDC実装基準](oidc-implementation-readiness.md)に集約済み。表のG1を通過するには、残る配備実値、ライブラリのNative/Wasm検証、本番SQLの実D1試験、両アプリ相互運用と公開前試験を完了する。設計模型のローカル試験合格を本番接続許可とみなさない。

## 16. 規模管理と既存実装からの学び

変更ごとに自作Rust/TS行数、公開API数、通常/開発/ターゲット別依存、Wasmのraw/gzipサイズ、cold start/処理時間、公開操作数を記録する。数値の絶対目標はP0測定後に定める。未使用featureと依存を削り、検証と障害処理は削らない。

| 参照 | 取り入れる知見 | 引き継がない前提 |
| --- | --- | --- |
| monban / iwato | WebAuthn要件、既存の検証資産 | 既存構成・API互換、機能網羅、webauthn-rs |
| doma | 端末暗号化と配送・保管の分離 | HPKE envelopeだけで継続的会話プロトコルが完成するという前提 |
| tayori | OpenMLS、DID、配送の分担 | 未永続化の鍵状態やコンテナDSをWorkers完成品として扱うこと |
| hako | ファイルごとの鍵、Vault、ローカルMCP | WorkerでVault鍵を復号・返却する経路、広いMCP権限 |
| kakitsu | 小さなRust/Wasmラッパー、暗号化IndexedDB | 復号失敗時の再生成、best-effort状態保存、非原子的KeyPackage消費 |

これらは2026-09-22のローカルソース確認に基づく設計上の知見であり、各プロジェクト全体の監査結果ではない。コードの再利用は対象と依存を再レビューして行う。

## 17. 仕様・公式資料

- [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)：検証手順とPRF拡張の基準。採用時に版を固定する。
- [MLS RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)：端末間プロトコル。配送やアプリ認可は別に定義する。
- [OpenMLS](https://github.com/openmls/openmls)：Rust実装と対応ターゲット。調査時点でWasmはCIビルド対象だがテスト済みサポート対象ではなく、S1で補う。
- [DID Core](https://www.w3.org/TR/did-core/)、[did:web](https://w3c-ccg.github.io/did-method-web/)、[did:key](https://w3c-ccg.github.io/did-key-spec/)：メソッドごとの信頼・更新条件を混同しない。
- [D1 Database API](https://developers.cloudflare.com/d1/worker-api/d1-database/)：batch等のトランザクション特性を実装契約と照合する。
- [R2 Workers API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/)：不変blob保存と条件付き操作を確認する。

本書で初期案とした値・制限は製品プロファイルとしての提案である。採用済みのセッション・ログアウト契約は専用仕様に従う。外部仕様の要約は完全な実装手順の代わりにはならない。
