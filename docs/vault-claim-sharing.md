# Vault属性のUserInfoへの開示（設計案）

2026-09-23 / Draft 2。本人専用Storage APIと暗号化画面以外は設計案であり、採用・実装済みの契約ではない。

## 本人専用Storage API

Rust Workerに本人専用の`GET`/`PUT`/`DELETE /vault/attributes/{attribute}`を追加した。`/vault`は`name`の暗号化・解錠画面で、ログイン済みSSOとPRF対応Passkeyを要する。`0002_vault_attribute_storage.sql`がD1のhead、操作再試行記録、回収カーソルを作る。R2 bindingのないWorkerではVaultを404にする。現在の認可判断はAuthZENのsubject/action/resource/decision形状を持つRustのローカルowner policyであり、HTTP PDP配置とGrant照会は未実装である。UserInfoのclaim公開とsystem recipientは未実装である。

ローカルprofileのsubjectは検証済みAccountIdを`type=mikaki-account`で表し、resourceは`type=mikaki-vault-attribute`、IDは`vault-attribute:<owner>:<attribute>`とする。許可するactionは`vault.attribute.read-ciphertext`、`vault.attribute.read-owner-envelope`、`vault.attribute.write`、`vault.attribute.delete`の4つだけ。service principalや未知actionはdenyする。これらは[AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)の情報モデルを使うmikaki固有の語彙で、外部PDP相互運用を実証したものではない。

`attribute`は1〜64文字の小文字ASCII英数字・`-`・`_`。PUTは`format_version: 1`、base64urlの`ciphertext`（最大24 KiB）と`owner_envelope`（最大8 KiB）のJSONを受ける。サーバーは暗号文をR2のランダムな不変keyに保存し、D1のheadにSHA-256 digestと本人用envelopeを記録する。GETは同じ値とrevisionを返し、保存blobのdigestを検証する。サーバーは暗号文を復号しないため、復号可能性は本人端末で確認する。

ブラウザのversion 1形式では、属性ごと・revisionごとにランダムな32 byte data keyを生成し、AES-256-GCMで本文を暗号化する。`ciphertext`のバイト列は`0x01 | nonce(12) | ciphertext+tag`。本人用鍵包みはPasskeyのWebAuthn PRF出力からHKDF-SHA-256で導いたAES-256-GCM鍵でdata keyを包む。`owner_envelope`は`0x01 | credential ID長(u16 BE) | credential ID | PRF入力(32) | HKDF salt(32) | wrap nonce(12) | wrapped data key(48)`。HKDF infoはorigin・attribute・credential IDに、両方のGCM AADはorigin・attribute・revisionに結び付ける。PRF出力とdata keyはサーバーに送らない。PRF非対応Passkey、紛失したPasskey、移転前のoriginで作った値はそのまま復号できない。別Passkeyへの再包み・復旧機能はまだない。

PUTの新規作成には`If-None-Match: *`、更新・DELETEには`If-Match: "<revision>"`を要求する。書込みには同一originの`Origin`と43文字の`X-Operation-ID`が必要であり、SSO cookieから本人を確定する。同じoperation IDと同じ要求は既存結果を返し、異なる要求は409とする。D1の条件付き確定時にもSSO・credential・accountの有効性を再確認する。削除はrevision付きtombstoneで、古い端末の上書きを防ぐ。1アカウントの属性IDは最大32個、直近60秒の書込みは20回まで。日次Cronが24時間以上前のR2 blobを走査し、D1 headに参照がないものだけを削除する。操作再試行記録は90日後に少しずつ削除する。R2とD1をまたぐtransactionはないため、回収が成功するまで孤立blobは残る。

## 目的と信頼境界

利用者が任意に登録する`name`等の属性は、認証アカウントの必須カラムではなく、Vault内の属性として扱う。通常の登録と`openid`だけのログインにはVault作成・解錠を要求しない。属性がない利用者にも`sub`だけのUserInfoを返せる。

本人が特定の属性をIdPから提供したい場合、対象属性のdata keyを本人の端末と**UserInfo専用system principal**に別々に包む。このprincipalは当該属性を単独で復号できる。その属性は「サーバーに読めないVaultデータ」ではなく、本人が選択してシステムと共有したデータである。会話、ほかの属性、Vault root keyやcollection keyへの包括的な復号権限を与えない。OIDC署名鍵やWorkerの一般SecretをVault鍵として流用しない。

AuthZENはアクセス判断のインターフェースであり、復号鍵や同意台帳ではない。Vaultの`Grant`は共有対象・相手・操作・期限・失効版の正本として残す。鍵包みの公開・unwrap、UserInfoとしてのRPへの開示はそれぞれ別の判断と監査を要する。OIDCのAccess TokenはVault権限にしない。

## 提案する読み出し経路

1. 利用者がVaultを解錠し、属性値を端末で暗号化する。属性単位の不変な暗号文と版をStorage APIに保存し、本人向けwrapを登録する。属性の種類、目的、共有先と「IdPが復号できる」ことを示した操作で、UserInfo専用principal向けのenvelopeと共有Grantを追加する。暗号文、envelope、Grantの版の不一致を公開しない。
2. RPが`name`を要求した場合、OIDC側は対象client、要求claim、利用者の開示同意を確認する。Vault共有Grantとは別に、**このRPへこのclaimを返す許可**を確認する。ログインへの同意だけで属性開示を推定しない。
3. UserInfo claimサービスは検証済みAccountId、client、属性ID、版、目的を受け、AuthZEN PDPに読取とenvelope取得を照会する。許可後も対象の有効なGrant・版をストレージで確認し、専用鍵で属性だけを復号する。OIDC Workerは任意のVault暗号文やenvelopeを指定できない。claimサービスと鍵管理の分離方法は実装前に確定する。
4. UserInfoはその認可取引に結び付いたpairwise `sub`と、許可された属性だけを返す。初期の拡張候補はUserInfoのみとし、ID Tokenへの属性埋込みは別の判断にする。利用者が入力した`name`は本人申告値であり、本人確認済みの氏名と表示しない。

属性なし、Vault未作成、共有なし、開示同意なしの場合、`name`を作り出さない。PDP・鍵サービス・Storageが使えない場合は復号済みの古い値へフォールバックしない。任意claimを省略して`sub`だけ返すか、一時エラーにするかは、要求の種類とOIDC仕様に照らしてHTTP契約で決める。claimサービスに平文の永続コピーやallow cacheを初期導入しない。

共有解除は以後のAPI読取、envelope取得、claim発行を止める。既にRPへ渡した値やシステムが得た平文は回収できない。以後の暗号学的な分離が必要な場合は新しいdata keyで属性を再暗号化し、残るrecipientにだけwrapを作る。属性更新も新しい版とenvelopeを一緒に確定し、古い値を新しいclaimとして返さない。

## System recipient共有の状態契約案

現在の`owner_envelope`は本人にだけ返す。system recipientの実装では、次の情報を別レコードで管理する。暗号suiteとバイト表現は鍵形式のテストベクトルを作ってから固定する。

| レコード | 必要な値 | 正本の責任 |
| --- | --- | --- |
| `AttributeRecipientEnvelope` | AccountId、属性ID、ciphertext revision、recipient service ID、recipient key ID、用途、suite/version、包まれたdata key | どの暗号文をどの鍵で復号できるか。owner envelopeと共用しない |
| `AttributeGrant` | AccountId、属性ID、recipient service ID、操作、用途、期限、active、単調増加のgrant version | system principalの取得・unwrap権限。鍵包みの存在だけで許可しない |
| `ClaimRelease` | AccountId、client ID、claim名、同意画面版、期限、active、単調増加のconsent version | 復号した値をどのRPへ開示できるか。Vault Grantから推定しない |

初回共有では、本人が解錠した端末で**対象属性のdata keyだけ**を公開済みUserInfo service keyに包む。鍵directoryの真正性と継続性を端末で検証できない間は共有操作を有効化しない。既存ciphertext revisionに対応するenvelope、Grant、監査記録をD1の一回の確定操作として公開し、一部だけが見える状態を作らない。R2に新しいciphertextが必要なら先に不変keyへ書き、D1確定失敗時は旧headを正本に保つ。

属性更新時は新しいrevisionに対する本人用とsystem用のenvelopeを同じ操作に含める。system envelopeを作れない場合、旧revisionのsystem envelopeを新しい暗号文へ流用せず、UserInfoへの属性提供を止める。共有解除では先にGrantとClaimReleaseのactiveを落とし、以後の新規取得・unwrap・発行を拒否する。必要なら本人端末が新しいdata keyで再暗号化し、残るrecipientだけにwrapする。過去に配布済みの平文・鍵を回収したとは主張しない。

PEPが作るAuthZEN評価では、subjectを検証済みの`mikaki-service`とservice ID、resourceを対象属性、actionを`vault.attribute.read-ciphertext`または`vault.attribute.read-system-envelope`とし、contextに用途と要求clientを含める。PDPは有効なGrantを参照し、未知service・用途・action・失効済みGrantをdenyする。別途、UserInfo発行前に`oidc.claim.release`をclientとclaimに対して評価し、ClaimReleaseも再確認する。PDPのallowだけで鍵をunwrapせず、保存層が同じ属性版・鍵ID・Grant版を再確認してから対象envelopeを渡す。HTTP PDPの配置と認証方式、同期したGrant読取方法は着手前に決める。

この段階の受入試験では、別属性のenvelope差し替え、旧revisionの再利用、別service keyへの差し替え、Grant取消しと同時の取得、RP同意なしのUserInfo要求、PDP停止時のfail closed、同じ操作IDで異なる共有内容の再試行を拒否する。監査にはprincipal、属性ID、目的、client、版、判断と結果を残し、属性平文・data key・envelope暗号文を残さない。

## Storage APIの最初の縦切り

1. 本人だけが読める小さな暗号化属性snapshotを一つ保存・取得する。D1をhead、revision、operation IDの正本とし、R2には不変ciphertextを置く。期待revisionによる競合検出、同じ操作の再試行、削除tombstone、孤立blob回収を実装・試験した。
2. WorkerをPEPとし、[AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)のsubject/action/resource/contextとdecisionに対応する評価境界を設ける。actorは認証済みの内部AccountIdから確定し、HTTP本文の自己申告を使わない。deny・timeout・不正応答は失敗として閉じ、失効後のallow cacheを作らない。PDPの配置・認証・Grantの即時参照方法は別途決める。
3. 属性単位のsystem recipient envelopeと共有Grantを追加し、公開版の一致・鍵用途分離・解除と再鍵化を確認する。その後でRP別のclaim開示同意とUserInfo投影を実装する。

FileNode/JMAPの名前付きファイル操作はこのVault属性経路とは異なるAPIとして進める。共有するのはblob保存・quota・監査等の実装基盤であり、Vault暗号文を一般ファイルの本文として扱わない。OIDC Conformanceの`name` WARNINGだけを理由に属性収集やsystem共有を必須化しない。

## 実装前に確定する事項

- system recipientの鍵管理と鍵継続性、別端末での解錠・鍵再包み・復旧手順。
- 属性の存在や種類をmetadataとして公開する範囲。RPごとの同意画面、保存期間、再同意、取り消しと監査。
- Claim serviceとOIDC Workerの信頼境界、PDPの配置・認証、Grantと開示許可の原子的更新・失効反映。
- UserInfoでの要求とエラーのHTTP契約、RPが保存した属性の更新・削除の扱い。

これらが確定するまでは`name`をDiscoveryに追加せず、既存の`sub`のみのUserInfoを維持する。
