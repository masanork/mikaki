# Vault属性のUserInfoへの開示（設計案）

2026-09-23 / Draft 1。以下の限定したStorage API以外は設計案であり、採用・実装済みの契約ではない。

## 実装中の最初のStorage API

Rust Workerに本人専用の実験的な`GET`/`PUT`/`DELETE /vault/attributes/{attribute}`を追加した。dev Workerだけに`VAULT_BLOBS` R2 bindingを置き、bindingのない本番Workerでは404を返す。`0002_vault_attribute_storage.sql`がD1のheadと操作再試行記録を作る。UserInfoのclaim公開、system recipient、AuthZEN PDP、属性の暗号化・解錠UIは未実装である。このAPIを実利用者のデータ保存先として公開しない。

`attribute`は1〜64文字の小文字ASCII英数字・`-`・`_`。PUTは`format_version: 1`、base64urlの`ciphertext`（最大24 KiB）と`owner_envelope`（最大8 KiB）のJSONを受ける。サーバーは暗号文をR2のランダムな不変keyに保存し、D1のheadにSHA-256 digestと本人用envelopeを記録する。暗号形式と鍵包みの中身はまだ確定しておらず、サーバーは復号可能性を保証しない。GETは同じ値とrevisionを返し、保存blobのdigestを検証する。

PUTの新規作成には`If-None-Match: *`、更新・DELETEには`If-Match: "<revision>"`を要求する。書込みには同一originの`Origin`と43文字の`X-Operation-ID`が必要であり、SSO cookieから本人を確定する。同じoperation IDと同じ要求は既存結果を返し、異なる要求は409とする。D1の条件付き確定時にもSSO・credential・accountの有効性を再確認する。削除はrevision付きtombstoneで、古い端末の上書きを防ぐ。R2とD1をまたぐtransactionはないため、確定失敗でできる孤立blobのGCは別途実装する。

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

## Storage APIの最初の縦切り

1. 本人だけが読める小さな暗号化属性snapshotを一つ保存・取得する。D1をhead、revision、operation ID、Grantの正本とし、R2には不変ciphertextを置く。期待revisionによる競合検出、同じ操作の再試行、削除tombstone、D1確定失敗時の孤立blob回収を試験する。
2. WorkerをPEPとし、[AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)のsubject/action/resource/contextとdecisionに対応する評価境界を設ける。actorは認証済みの内部AccountIdから確定し、HTTP本文の自己申告を使わない。deny・timeout・不正応答は失敗として閉じ、失効後のallow cacheを作らない。PDPの配置・認証・Grantの即時参照方法は別途決める。
3. 属性単位のsystem recipient envelopeと共有Grantを追加し、公開版の一致・鍵用途分離・解除と再鍵化を確認する。その後でRP別のclaim開示同意とUserInfo投影を実装する。

FileNode/JMAPの名前付きファイル操作はこのVault属性経路とは異なるAPIとして進める。共有するのはblob保存・quota・監査等の実装基盤であり、Vault暗号文を一般ファイルの本文として扱わない。OIDC Conformanceの`name` WARNINGだけを理由に属性収集やsystem共有を必須化しない。

## 実装前に確定する事項

- 属性形式、属性ごとの鍵粒度、暗号suite/AAD、system recipientの鍵管理と鍵継続性、別端末での解錠手順。
- 属性の存在や種類をmetadataとして公開する範囲。RPごとの同意画面、保存期間、再同意、取り消しと監査。
- Claim serviceとOIDC Workerの信頼境界、PDPの配置・認証、Grantと開示許可の原子的更新・失効反映。
- UserInfoでの要求とエラーのHTTP契約、RPが保存した属性の更新・削除の扱い。

これらが確定するまでは`name`をDiscoveryに追加せず、既存の`sub`のみのUserInfoを維持する。
