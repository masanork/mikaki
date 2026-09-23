# sakimori ファイルストレージ API（設計案）

2026-09-23 / Draft 0

sakimori の共有ストレージ基盤と、その上のファイルAPIの設計案。実装済み・採用済みの決定ではない。VaultとファイルストレージでS3 backendを二重に作ることは想定しない。違いは保存基盤ではなく、APIが保証するデータモデル・暗号化・同期契約にある。

## 1. 目的と境界

S3互換オブジェクトストレージを共通blob backendとして利用する。メタデータ・階層・revisionはsakimoriのDBを正本とする。S3は内部backendであり、初期にS3プロトコルを利用者へ直接公開するものではない。FileNode APIは人やアプリが扱う名前付きファイル／ディレクトリを提供する。Vault同期APIは端末暗号化済みデータの保存・条件付き更新を提供する。どちらも共通blob保存・quota・監査・backend運用を利用できるが、Vault暗号文を通常ファイルAPIから平文ファイルとして解釈しない。

| 層 | 責任 |
| --- | --- |
| API / PEP | 認証済みactorの確定、AuthZEN照会、結果の強制、入力検証 |
| Storage core | blob保存、FileNode操作、revisionとchanges、quota |
| Metadata store | node、blob版、mutation、同期stateの永続化 |
| S3 adapter | 不変blobのput/get/delete、multipart処理、provider設定 |
| AuthZEN PDP | subject/action/resource/contextに基づく許可判断 |

認証coreはストレージを知らない。Workerがトークン等からactorを確定してstorageへ渡す。storageはHTTP入力のactor自己申告を信頼しない。Vaultの既存`Grant`契約とAuthZENの関係は別途整理する。GrantをStorageへ複製したり、単にFileNodeのACLへ読み替えたりしない。

### 2.1 FileNodeとVaultの境界

| 観点 | FileNode API | Vault同期API |
| --- | --- | --- |
| クライアントの対象 | 名前・親子関係を持つファイルとdirectory | Vault、collection、暗号化snapshot/object |
| サーバーが読むmetadata | name、type、size、階層、revision等 | object ID、size、revision等。本文やアプリ意味情報は暗号文内 |
| 本文 | ファイルとして取得・更新するblob | 端末で暗号化・復号するopaque blob |
| 同期 | node treeの差分とquery結果 | 条件付きsnapshot更新、tombstone、Vault cursor |
| 認可 | file操作ごとのread/list/write等 | owner/app/collection/operation/期限等の委任範囲 |

共有するのはblob lifecycle、S3 adapter、quota計測、監査の土台である。FileNodeのpath/treeをVaultのsnapshotへ強制しない。Vaultの小さな暗号化snapshotをFileNodeファイルとして公開する必要もない。添付などユーザーがファイルとして扱うデータが必要になった時点で、そのblob参照とVault内の鍵配布・collection許可をどう結ぶかを別途決める。

## 2. 参照モデル

JMAP File Storage extension の FileNodeを相互運用の基準にする。初期の互換性目標はデータモデルと基本操作の対応であり、JMAP wire protocol全体への準拠ではない。JMAPを外部APIに採用するか、sakimori APIからJMAPへadapterを置くかは未決とする。

```text
FileNode {
  id: immutable server ID
  parentId: ID | null
  nodeType: file | directory
  blobId: ID | null
  name: string
  size: integer | null
  type: media type | null
  created, modified, changed
}
```

pathは`parentId + name`から導出し、identityに使わない。rename/moveで`id`を維持する。FileNodeの`blobId`は内容の論理参照、S3 object keyは内部の保存場所とし、クライアントへS3 key/bucketを返さない。

初期スコープはfileとdirectory。symlink、executable、サーバー本文検索、archive変換、blob deduplicationは対象外。兄弟nodeのnameは一意、cycleを作るmoveは禁止。削除は空でないdirectoryを拒否する。再帰削除やtrashは後続判断とする。

## 3. API 操作

仕様上の操作名はJMAPの慣例に寄せる。実HTTP bindingとURLは別途確定する。

| 操作 | 意味 | 必要action |
| --- | --- | --- |
| `FileNode/get` | ID指定でmetadataを取得 | `read` |
| `FileNode/query` | directory/条件から一覧 | `list`（返す各nodeの可視性も確認） |
| `FileNode/changes` | state以降のmetadata差分と削除ID | `read`。結果ごとに可視性を再評価 |
| `FileNode/queryChanges` | query結果集合の増減 | `list`。削除・不可視化も差分に含める |
| `FileNode/set` | create/update/destroy、rename/move | create-child / rename / delete / write-content |
| `FileNode/copy` | fileまたはtreeの複製 | read source + create-child destination |
| blob GET/PUT | file contentの取得・置換 | read-content / write-content |

初期は完全置換PUTのみ。PATCH、S3 multipartのクライアント露出、HTTP presigned URLは後続とする。HTTP uploadは一時blobへ受け、条件付きmetadata確定後にだけFileNodeから参照可能にする。

更新には`ifInState`相当の期待state、content更新にはnode revisionまたはETag条件を要求する。競合はConflictとして返し、無条件のlast-write-winsをしない。`operationId`を受け、同一ID・同一request hashの再試行には確定済み結果を返す。同じIDで異なる要求は拒否する。

`state`はaccount/treeごとのopaque cursorとする。changesは作成・更新・削除を表し、cursor失効時はfull resyncを要求する。権限変更により見えなくなったnodeも削除相当の差分として通知し、存在の漏えいを抑える。

## 4. AuthZEN 認可

sakimori APIがPEP、AuthZEN endpointがPDPとなる。リソースIDはtenant/account境界を含めて一意にする（例: `filenode:<accountId>:<nodeId>`）。subjectはWorkerが確定した安定IDを使う。初期action vocabulary:

| Action | 対象 |
| --- | --- |
| `storage.read` | node metadata取得 |
| `storage.list` | directory配下の列挙・query |
| `storage.create-child` | parentの下にnodeを作る |
| `storage.rename` | name変更またはparent変更 |
| `storage.delete` | node削除 |
| `storage.read-content` | blob取得 |
| `storage.write-content` | blob新規作成・置換 |

AuthZENの標準モデル（subject/action/resource/contextとboolean decision）を使い、これらのaction名・resource type・context属性をsakimori profileとして固定する。PDPはpolicyを評価する。Storage DBに独自のACL/shareWithを複製しない。

各API操作はPEPで認可してから副作用を行う。moveはsourceのrenameとold/new parent双方への必要権限、copyはsource readとdestination createを評価する。query/get/changesは対象nodeごとに可視性を強制し、未許可nodeを返却件数・親情報・エラー差で推測できないようにする。directory列挙では`list`と子nodeの`read`の意味を混同しない。初期profileではlist可能な利用者に子metadataも開示するかを明示して決める。

PDP timeout・不正応答・通信失敗時はfail closed。認可結果のallow cacheは初期には設けず、失効反映遅延を作らない。PDP検索APIで一覧を代用せず、queryの検索条件とDB列挙を行った後にAuthZEN evaluationをまとめて実行する方式を検証する。件数の大きい一覧におけるbatch評価・ページングと、部分許可時のstateの意味は実装前に性能検証する。

`myRights`はAuthZEN decisionの長期projectionとして保存しない。クライアントのボタン表示に必要なら、そのnodeに対するaction search/evaluationから短命に生成する。ただしUI表示は認可の根拠にならず、実操作で必ず再評価する。

外部共有、他ユーザーへのgrant作成・失効、share UIは初期対象外。後で導入する場合も、権限の正本と管理APIはPDP側に置き、StorageのshareWithへ二重管理しない。

## 5. S3互換 backend と整合性

S3互換性だけではconditional write、multipart、versioning、strong consistencyなどの意味が揃わない。backend interfaceは必要機能を明記し、providerごとに適合を確認する。metadata DBをtreeと公開blob参照の正本とする。

推奨するcontent更新順序:

1. 認可、サイズ上限、期待node revision、operation IDを検査する。
2. 新しいblobを一意な内部keyへ保存し、長さ・digestを検証する。
3. metadata DB transactionでblob参照、size/type、node revision、change record、mutation結果を原子的に確定する。
4. DB確定後に旧blobを即時削除せず、参照がないことを確認するGC対象にする。

DB確定に失敗すれば旧blob参照を維持し、新blobは孤立objectとして後で回収する。S3とDB間の分散transactionを仮定しない。copyは同一bucketのserver-side copy最適化が可能でも、権限と確定手順は通常copyと同じにする。

暗号化はAPI/profileごとに定義する。Vaultは端末側暗号化を維持し、共通blob backendへopaque ciphertextを保存する。FileNodeの一般ファイルは、サーバー側暗号化か端末側暗号化か未決であり、用途と脅威モデルから決める。S3 SSEを使う場合でも、provider operatorからの秘匿をE2EEと表現しない。

## 6. 安全性・運用条件

- S3 bucket/key、認証情報、presigned URLをAPI応答や通常ログへ含めない。
- blob取得時もAuthZENを評価する。S3直リンクを返す場合はPDP失効後も期限まで有効になる性質を含め、別途期限と漏えい対策を定義する。
- 外部提供する場合は、利用者がアップロードしたHTML等をsakimori originで実行しない。downloadは安全なContent-Dispositionを既定にする。
- node名は1〜255 UTF-8 byteを暫定上限とし、`/`、制御文字、`.`、`..`を拒否する。case sensitivityとUnicode normalizationは互換性試験前に確定する。
- file size、node数、directory深度、request body、同時multipart数にquota/limitを置く。
- auditにはactor、action、resource ID、decision、operation ID、結果、時刻を記録し、ファイル内容・認証token・S3 secretは記録しない。
- quotaは論理サイズ（FileNodeが参照するcurrent blobの合計）とnode countを基本とし、孤立blob・履歴版の物理容量課金は別に監視する。

## 7. 段階案

1. S3互換providerの選定条件と、Vaultを含む開示・暗号化モデルを確定する。
2. 共通blob storeの不変key、revision pinning、失敗回復、GC、quota契約を確定する。
3. FileNode APIのCRUD、完全PUT/GET、revision/changesを実装し、AuthZEN action profileとfail-closed動作を確定する。
4. Vaultのblob操作を共通backendへ載せる場合、既存P1の競合・暗号文保護・Grant契約を維持できることを確認する。
5. 実クライアントでJMAP互換範囲を検証し、JMAP wire protocol採用またはsakimori API adapterを決める。
6. 必要性を確認してから共有、PATCH、大容量multipart、trash、symlink、blobextを検討する。

## 8. 着手前の決定ゲート

| Gate | 決定事項 |
| --- | --- |
| ST0 | 主な利用者・用途、FileNodeとVaultで共有するblob契約、Vault添付の要否、JMAP wire採用有無 |
| ST1 | S3 provider、メタデータDB、最大file size、multipart、quota、backup/retention |
| ST2 | サーバー側暗号化か端末側暗号化か、metadata開示、共有時の鍵配布 |
| ST3 | AuthZEN PDP配置・認証、subject/resource ID、FileNode action profile、Vault Grantとの関係、timeout/availability |
| ST4 | query時の部分可視性、親directoryの開示、changes/cursorの認可失効時挙動 |
| ST5 | API wire/HTTP binding、ETag・revision形式、エラー、path/name portability |

## 9. 未決事項への推奨案

以下は設計レビュー用の推奨値であり、採用済みの決定ではない。初期profileを小さく保ち、別途明示がなければこの案を基準に実装仕様へ進める。

| 項目 | 推奨案 | 理由・影響 |
| --- | --- | --- |
| ST0: API | JMAP Core + FileNodeのwire protocolを採用し、FileNode v14の基本subsetを実装する。独自HTTP APIは増やさない | この機能の主目的がFileNode互換クライアントと標準への実装フィードバックだから。v14は作業中のdraftなので、実装したdraft版と未対応機能をcapabilityで明示する |
| ST0: 層の境界 | FileNodeとVaultは同一blob storeを使える。FileNode treeとVault snapshot model、各APIの認可契約は統合しない | 共有するのは保存実装で、データの意味と保証は各機能に残せる |
| ST1: backend | Worker構成ではR2を第一候補とし、S3互換adapter contractで閉じ込める。一般S3 providerへの切替はadapter適合試験を通したproviderだけを対象にする | R2は既存Vault案との運用親和性がある。S3互換という表現だけで全providerの意味・機能が同一とは扱わない |
| ST1: DB/整合性 | D1等のtransactional metadata DBを正本とする。blobはランダムな不変keyへ書き、DB確定後にだけ公開する。独自digestを保存し、S3 ETagをchecksumとみなさない | object storeとDBをまたぐtransactionを避け、更新失敗時に旧headを保てる |
| ST1: サイズ | 初期のAPI request上限を100 MiB候補とする。multipartは上限値だけ先に決めず、Worker経由か短命upload URLかを決めてから導入する | 現行Workersのrequest body上限はCloudflare zone planに依存し、Free/Proは100 MB、Businessは200 MB、Enterpriseは最大5 GB。R2自体のmultipart上限とは別。短命URL方式はPDP評価後に直接S3へ書くため、失効・再試行・完成後の検証が必要 |
| ST1: 履歴・削除 | FileNodeのdestroyはtombstoneでchanges同期に反映する。trash/undeleteは初期wire profileに含めず、復旧はbackup/運用復元として別管理する。未参照blobは猶予期間後GC | 同期用削除記録と利用者向け復旧機能を混同しない。復旧要件があればtrashを独立機能として追加する |
| ST2: 一般ファイル暗号化 | 初期FileNodeはTLS + backend SSE、metadataと本文をサーバーが処理できるモデルとし、E2EEを約束しない。Vaultは現行どおり端末暗号化を維持 | FileNodeのMIME、preview、一般クライアントとの相互運用を保てる。秘匿要件の異なる利用者には将来client-encrypted namespaceを設けるが、同じFileNode semanticsへ混在させない |
| ST2: 開示 | FileNodeのname、階層、size、type、時刻、アクセス記録はsakimoriとPDPに見える。本文も一般FileNodeではserver-side処理可能。Vaultは従来どおりアプリ意味情報と本文を暗号文内に置く | サービス運営者・storage providerに対する秘匿境界を明確にする |
| ST3: AuthZEN | WorkerをPEP、AuthZEN 1.0互換PDPをdecision pointとする。subjectは認証済みAccountId、resourceはaccountとnode IDを含む不透明ID。policy管理・PDP運用者は別ゲートで確定 | requestごとの主体・対象が安定し、tenant横断のID衝突を避ける。AuthZENはpolicy管理・配布形式までは決めないため、別に決める必要がある |
| ST3: action | `storage.read-metadata`, `storage.list-children`, `storage.create-child`, `storage.rename`, `storage.delete`, `storage.read-content`, `storage.write-content`をprofile actionにする。共有/grant管理actionは初期対象外 | metadata列挙、content取得、変更操作を分離して最小権限にできる |
| ST3: Vault Grant | 既存GrantはVaultのowner/app/collection/operation/期限を表す業務データとして残す。Vault操作も同じAuthZEN PEP/PDP経路で評価するprofileを設け、Grant属性をPDPが参照する形を目指す。FileNode ACLへ変換・複製しない | GrantはVaultのドメイン要件を持ち、AuthZENは評価APIであってgrant台帳やpolicy authoring規約ではない。PDPがGrant変更をどう即時参照するかは設計が必要 |
| ST3: PDP障害 | deny-by-default、timeout/error時fail closed、初期allow cacheなし。評価はAuthZEN batch endpointを利用する | 失効後の許可継続を避ける一方、PDP障害中はストレージ操作が停止する。PDPを同期経路上の可用性依存として運用する |
| ST4: directory可視性 | `list-children`が許可されたdirectoryでは、直下の子metadata/nameを列挙可能とする。content取得には各fileの`read-content`を別途要求する。個別のread-metadataがdenyでも、list可能な親の直下entryは一覧に含める | 大量の子ごとに認可を走らせず一覧意味を明確にできる。親directoryのlist権限が子の名前・サイズ等を開示することを明記する |
| ST4: changes | changes/queryChangesの返却候補も認可評価する。以前見えていたnodeが見えなくなった場合はremoved相当で通知し、cursorは権限変更で失効させる場合がある。再同期は現在可視な範囲だけ返す | 許可取消し後に古いmetadataを差分APIから読み続けることを防ぐ。共有変更時は広い範囲の再同期が発生し得る |
| ST5: 条件更新 | JMAP state/ifInStateをmetadata更新の前提にし、blob content PUTにはnode revision由来のETagと`If-Match`を追加する。新規作成は`If-None-Match: *`相当を要求 | metadataと大きなHTTP bodyで競合を一貫して検出し、無言の上書きを避ける |
| ST5: name | 兄弟名はcase-sensitive、Unicode NFCへ正規化して比較する。`/`、制御文字、`.`、`..`を拒否する。最大255 UTF-8 byte | 初期互換profileを単純にする。case-insensitive filesystemとの同期はcollisionを検出し、勝手なrenameをしない |

### 鍵管理の初期案

一般FileNodeはサーバー可読とし、sakimori独自のアプリケーション暗号鍵は初期には導入しない。TLSで転送を保護し、R2等のbackendが提供する保存時暗号化を必須とする。R2ではobjectとmetadataが自動で暗号化され、鍵はCloudflareが管理する。この選択は生の保存媒体・storage provider内の暗号化前データを直接得る脅威を下げるが、Worker侵害、S3資格情報侵害、許可されたAPI読み出し、providerの通常read経路から本文を秘匿しない。

```text
JMAP client --TLS--> sakimori Worker (本文を平文処理可能)
                           |
                           +-- S3/R2 credentials --> encrypted-at-rest object store
                                                     provider-managed key
```

鍵・資格情報の役割を分ける。

| 秘密 | 保管・利用 | 保護するもの / 保護しないもの |
| --- | --- | --- |
| R2/S3 access credential | Worker Secret。必要なbucket操作だけを許可し、環境別に分離 | DBだけを持つ攻撃者等からobject API操作を制限する。Worker侵害中の利用は防がない |
| Provider at-rest key | storage provider管理 | 生のmedia/snapshotに対する保護。sakimoriから独立した復号境界ではない |
| Vault root/data keys | 端末側で導出・使用。サーバーへ送らない | Vault暗号文の機密性。FileNode一般ファイルには使用しない |
| AuthZEN PDP credential | Worker用の別Secret | PDP API呼出しだけに使う。S3 credentialや暗号鍵と共有しない |

Worker SecretはWorker実行時に通常の環境値としてWorkerコードへ渡るため、アプリ暗号鍵をそこへ置いても、実行中のWorker侵害に対する独立KMS境界にはならない。R2 SSE-Cも、要求ごとにWorkerがcustomer keyを扱うため同じ制約があり、鍵紛失で復号不能になる運用リスクも加わる。[Workers Secrets](https://developers.cloudflare.com/workers/configuration/secrets/)、[R2 SSE-C](https://developers.cloudflare.com/r2/examples/ssec/)

将来、storage credentialを持つ主体からもobject本文を保護する要件が出た場合は、アプリ層envelope encryptionを別profileとして設計する。blob/versionごとにランダムなDEKで暗号化し、DEKは外部KMS/HSMにあるKEKでwrapしてciphertextと一緒に保存する。Workerは読込時にKMSへunwrapを要求するので、KEKの平文を永続保存しなくてよいが、WorkerがKMS利用権限を持つ限り侵害中の復号要求は可能である。KMS分離の利点は、object store単独の資格情報漏えいではwrapped DEKを復号できない点、KMS権限を停止・監査できる点にある。単一のWorker Secretに全利用者共通の暗号鍵を置く方式は採用しない。

KMS案を採用する場合の最低条件は、accountごとの暗号化境界、認証済みaccount IDを含むKMS encryption context、鍵用途別IAM、KMS監査、鍵versionとwrap formatの記録、既存データを読める鍵を残したrotation、バックアップ復元試験である。鍵削除は、その鍵versionを参照するblob・backup・retention期間がゼロだと確認できるまで禁止する。KMS鍵を失うと本文も復元できなくなるため、可用性と復旧責任を仕様化する。

VaultのPRF-derived鍵はこのFileNode暗号化へ流用しない。PasskeyでログインできることはPRF出力やVault鍵が利用可能なことを意味しない。Vault鍵をサーバー側FileNodeの鍵ラップに使えば、Vaultの端末境界とサーバー可読の境界が混ざる。

### 推奨案から確定する前に必要な確認

- 100 MiBの単一PUT上限、5 GiBの将来multipart上限、quota値が利用予定のprovider・Worker実行制限・料金に合うか。
- PDPをsakimori運営下に置くか、外部PDPを許容するか。認可不能時の停止を許容できるか。
- 一般ファイルのserver-readableモデルが用途に合うか。FileNodeでもE2EEを要求するなら、MIMEやpreview等を諦めるclient-encrypted profileが必要。
- 「サーバーに鍵を永続化しない」の要件が、アプリSecretにmaster keyを置かない意味か、アプリ運用者・storage providerも復号できない意味か。後者はFileNodeのserver-readable方針と両立しない。
- RFC 9670 SharingをFileNodeのpolicy authoringの基礎に残すか。AuthZENは判断APIを提供するが、誰がどのUIでpolicyを作るかは定義しない。

## 参照

- [JMAP File Storage extension draft-ietf-jmap-filenode-14](https://datatracker.ietf.org/doc/html/draft-ietf-jmap-filenode-14)（2026-05-15公開のActive Internet-Draft。規範ではなく作業中）
- [RFC 9404: JMAP Blob Management](https://datatracker.ietf.org/doc/html/rfc9404)
- [RFC 9670: JMAP Sharing](https://datatracker.ietf.org/doc/html/rfc9670)
- [OpenID AuthZEN Authorization API 1.0](https://openid.net/wg/authzen/specifications/)
- [JMAP Blob Extensions draft-ietf-jmap-blobext-01](https://datatracker.ietf.org/doc/html/draft-ietf-jmap-blobext-01)（作業中。初期実装の依存にしない）
- [Cloudflare Workers limits](https://developers.cloudflare.com/workers/platform/limits/)、[R2 upload methods and multipart limits](https://developers.cloudflare.com/r2/objects/upload-objects/)（request body制約とobject-store上限を区別するため）
