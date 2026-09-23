# OIDCのデータモデルと原子操作

2026-09-22 / Draft 1（レビュー用）

初期実装の決定・運用値・検証範囲は[統合実装基準](oidc-implementation-readiness.md)を参照する。原子操作のSQL模型とローカル試験を追加したが、本番migrationではない。

[ログイン取引](oidc-login-flow.md)、[セッション契約](session-lifecycle.md)、[Access Token](oidc-access-token-and-userinfo.md)を永続化するための論理設計。初期はsakimoriの認証・OIDCの確定状態を一つのD1データベースに置く。各アプリのDBとの分散トランザクションは仮定しない。SQL migrationや実装済みのストア契約ではなく、G1でSQLと実環境試験に落とす提案とする。

## 確定の単位

暗号検証と署名生成はDBの外で行い、最後の条件付き書込みで期限・版・失効状態を再確認する。HTTP成功応答やcookieは確定後にだけ返す。署名できたこと、DBへの書込みを開始したことを成功扱いにしない。

ストアAPIはResolveSubject、CompleteAuthentication、ExchangeCode、RevokeSession等の業務操作とする。呼出し側が個別のread/updateを組み合わせて原子性を作る汎用Repositoryは設けない。成功、条件不成立、確定結果不明の一時障害を区別する。

## sakimori側の論理レコード

| レコード | 主な情報と制約 |
| --- | --- |
| AccountSecurity | account_id、login_epoch、状態。全ログアウトでepochを増加 |
| Credential | 既存のcredential情報と、有効状態・認証確定用の版。削除後も関連セッションを拒否できる記録を保持 |
| OidcClient / ClientKey | client設定版・状態、sector・登録URI、用途別公開鍵・alg・鍵状態・版 |
| PairwiseSubject | account_id、sector、sub。UNIQUE(account_id, sector)、UNIQUE(sub)。接続解除で削除しない |
| AppConnection | account_id、client_id、grant_version、許可scope・表示版・状態。UNIQUE(account_id, client_id) |
| SsoSession | 内部ID、cookie秘密値のハッシュ、account_id、login_epoch、本人認証credential、auth_time、expires_at、失効状態、policy_revision |
| AuthorizationTransaction | ブラウザ結び付け、client設定版、redirect URI、nonce、PKCE challenge、scope、期限、処理状態・版。要求確定後に内容を差し替えない |
| ClientSession | client_id、sid、SSO参照、sub、grant_version、状態、expires_at。UNIQUE(client_id, sid) |
| AuthorizationCode | codeハッシュ、認可取引参照、client・redirect URI・PKCE、sid、期限、未使用/消費済み、消費操作ID。取引につき発行は一件 |
| TokenIssue | code参照、sid、ID Token署名kid・発行時刻・期限、Access Tokenハッシュ・用途・scope・期限・失効状態。一つのcodeから成功発行は一件 |
| ClientAssertionUse | UNIQUE(client_id, jti)、対象endpoint、受理時刻、再使用拒否の保持期限 |
| ManagementAuthorization | 既存の一回限りの管理許可。account・操作・対象・期待版・本人認証・期限・消費状態 |
| RevocationEvent | 操作ID、失効対象と世代範囲、理由、確定時刻、通知展開状態。秘密値や署名済みtokenを保存しない |
| LogoutDelivery | event参照、client_id、sid、状態、試行回数、次回時刻、lease所有者・世代・期限。UNIQUE(event_id, client_id, sid) |

sidは初期案では一回の認可取引につき新しく生成する。同じSSOから再ログインしても新sidとし、元codeの再使用による失効を他のログインへ波及させない。SSOを止めた場合は、その全sidが無効になる。

code発行時のClientSessionは保留状態とし、TokenIssueの確定によって初めて/session/checkでactiveになる。未交換codeの期限切れに伴い保留状態も終了し、GC待ちの行を有効session件数に数えない。code交換前の適格性と、アプリから確認できるactive状態は別の問い合わせにする。TokenIssueのAccess Token期限切れだけではactiveを終了させない。

秘密値と公開識別子を分ける。SSO cookie、code、Access Tokenは高エントロピーの乱数とし、照合用ハッシュだけを保存する。外部入力を結合キーとして直接信用せず、clientと所有関係を検証する。複合一意制約・外部キーで他clientのsub/sidへの誤結合を防ぐ。

期限はUTCの整数時刻で単位を統一し、最終SQL操作でも期限切れを確認する。アプリサーバーが事前に取得した古いnowだけを最終判定に使わない。設定から計算した期限は保存し、GC時に現在のTTLから再計算しない。

## 有効性の判定

有効なClientSessionには、当該clientが有効で、本人のAccountSecurityが有効、SSOのlogin_epochが現在値と一致、SSOと本人認証credentialが未失効、SSO期限内、AppConnectionが有効でgrant_versionが一致、sid自身が未失効であることを要求する。credentialの署名カウンター更新等の通常変更だけで既存SSOを失効させない。

/session/checkはこれらとsub・auth_time・SSO期限を一つの整合した読取りで取得する。UserInfoは同じ条件にTokenIssueの用途・scope・期限・失効を加える。ClientSessionのactive列だけで認可せず、通知処理やGCが遅れても失効が効くようにする。

client設定版の変更は進行中の認可・code交換を停止する。既存セッションへの影響はclient停止・接続解除等の明示操作で定め、表示名変更等だけで一律に全失効させない。

## 原子操作の契約

| 操作 | 同時に確認・確定する内容 |
| --- | --- |
| CompleteAuthentication | ceremonyの未消費・期限・ブラウザ結び付け、credential有効性と検証時の版、認証取引が保持したaccount epochを確認。ceremony消費、credential更新、認証結果とSSO作成を確定 |
| IssueAuthorizationCode | 認可取引の未完了・期限、client設定版、SSO有効性、表示に結び付いた許可を確認。PairwiseSubjectの取得/作成、必要な接続許可、ClientSessionとcode、取引完了を確定 |
| AcceptClientAssertion | 検証済み署名のclient・鍵状態/版・期限を再確認し、jtiを一度だけ記録。これは後続code交換とは別の確定であり、codeが不正でも巻き戻さない。予約行の`accepted_by`をreceiptとして保持し、code交換自身のoperation_idとは別に照合する |
| ExchangeCode | 認証済みclientと鍵状態/版、codeの結び付け・未使用・期限、認可時のclient設定版、SSO・grant・sid、OP署名鍵の有効世代を再確認。code消費とTokenIssueを同時に確定 |
| RevokeCodeIssue | 正しく認証・結合確認した消費済みcodeの再使用に対し、そのTokenIssueとsidを失効し、RevocationEventを同時に作成 |
| RevokeSso | 対象SSOの失効と、そのSSOを対象にしたRevocationEventを同時に確定 |
| RevokeAllSessions | 管理許可消費、accountのlogin_epoch増加、旧epoch以下を対象にしたRevocationEventを同時に確定 |
| DisconnectClient | 管理許可消費、grant_version増加と許可停止、旧版以下の対象sidへのRevocationEventを同時に確定。subは維持 |
| DisableCredential | 管理許可消費、credentialの無効化と版更新、当該credentialで認証したSSOへのRevocationEventを同時に確定 |

全ログアウト中に進行していた認証は、最後に新epochを読み直して成功にしない。既知アカウントではceremony開始時のepoch、discoverable認証では署名検証に先立つアカウント特定時のepochを保持し、確定時の不一致で中断する。新epochで新たなPasskey認証を行ったログインだけを継続させる。

初回接続でgrantが存在しない場合も「存在しない」という期待状態を条件にする。接続解除と認可が競合した場合、古い同意の記録で許可を自動再作成しない。許可の再作成には新しい取引と確認が必要。並行初回接続の一意制約競合では既存subを再読取りし、旧取引を新しいgrant版へ黙って読み替えない。

## D1への対応方針

D1のbatchはSQLエラー時に全体をロールバックする。一方、条件付きUPDATEが0件でもSQLエラーとは限らないため、batchに並べただけで業務操作の成功を保証したことにしない。assertion予約は独立した先行batchなので、そこで発行した`accepted_by`を型付きreceiptに保持し、後続のcode交換operation_idと混同しない。Workerの`POST /token`は条件付きcode消費、token issue挿入、`valid_client_session`を使うCHECK guardを一batchにまとめる。失敗時のrollbackはCloudflareのAPI契約とworker-rs型を根拠に実装しており、このSQLを含む隔離D1実測は未実施。

一回のbatchで、条件付き更新に操作IDを記録し、後続INSERTはその操作IDを条件に実行する。最後に必要な件数・関連レコードの存在を検査し、不足ならDB制約違反を起こして全体をロールバックする。検査行が必ず一件評価されることを必要とし、INSERT SELECTが0行だっただけで成功するガードは使わない。実SQLは[交換設計](../design/sql/exchange-code.sql)およびWorker実装にあるが、D1上の実測は未完了。

呼出し側でbatch結果を見て不足を検知するだけでは、既に確定した書込みを取り消せない。SQLの最終条件が全書込みを保護すること、途中の一意制約違反や例外でもcodeのみ消費されないことを確認する。対話的なBEGIN→外部署名→COMMITを前提にしない。

失効確認には、毎回新しいwithSession("first-primary")の最初のSQLとして有効性全体のJOINを実行する案とする。first-primaryは後続SQLまで常にprimaryで読む指定ではないため、別SQLの事前読取りで消費しない。古いbookmarkや長寿命sessionの順序保証だけを、他要求の最新失効を読む保証とみなさない。

署名や通知のHTTP送信はbatchに含めない。署名済み応答はメモリに保留し、ExchangeCode成功後に返す。鍵停止との競合では確定時に停止世代を再検査する。確定後にネットワーク配送中の応答を回収する保証はせず、緊急停止時は既存設計のkid拒否・セッション失効を適用する。

## 失効通知と再試行

大量のsidを失効操作中にすべて列挙する必要はない。失効条件とRevocationEventを同時に確定し、そのイベントを永続outboxの親レコードとする。停止済みSSO・旧account epoch・旧grant版等から対象を分割列挙し、LogoutDeliveryを重複なく作成する。新しいepoch・grant版のsidを対象に含めない。

対象集合は失効条件で閉じており、失効後に旧条件の有効sidを新規作成できないことをIssueAuthorizationCodeで保証する。列挙カーソル更新とdelivery挿入は同時に確定する。列挙完了までは元sid等をGCしない。途中停止後も同じ対象集合から再開できる。

通知workerは期限付きleaseを条件付きで取得し、DB確定後にHTTP送信する。成功記録はlease所有者と世代が一致する場合だけ更新し、期限切れworkerが後続workerの状態を上書きしない。送信成功後の記録失敗では再送されるため、受信側は重複を成功扱いにする。再送時には新しいLogout Tokenを作るが、失効対象sidを変更しない。

再送期限を過ぎた通知は失敗として記録・監視し、失効そのものを戻さない。アプリ側の確認期限が通知未達を補う。再送間隔・lease・最大試行/期限・展開batch件数は次の運用制限設計で設定化し、実装内の隠れた定数にしない。

## アプリ側の確定

各アプリはLoginTransaction、ExternalIdentity、AppSession、RevokedSidを自分のストアへ保持する。callback処理の獲得は取引版による条件付き更新とし、code交換を複数workerが並行実行しない。処理中workerが失われた場合は同じcodeを別workerが交換し直さず、新しいログイン取引から再開する。

ID Token検証と/session/checkの後、取引期限・ブラウザ結び付け・失効記録・参加資格を再確認し、ExternalIdentity取得/作成、AppSession作成、取引完了を同じローカル原子操作で確定する。確認開始時からのlease期限が確定前に過ぎていれば再確認し、期限切れの結果でcookieを発行しない。

Logout受信はRevokedSid作成と既存AppSession無効化を同時に確定する。セッション未作成でも失効記録を残し、並行callbackの確定を拒否する。有効性確認応答の保存もこの記録と競合制御する。アプリDBとsakimori DBをまたぐ即時確定は保証せず、通知と確認期限によって反映を保証する。

## 応答喪失・保持・試験

DB応答の喪失は未確定と同義ではない。管理操作は内容に結び付いた操作IDで結果を照会でき、同一ID・異なる内容を拒否する。code交換の結果が不明な場合は成功tokenを再発行・再配信せず、新しいログイン取引へ進む。秘密の応答を保存して再送する仕組みは初期には設けない。

消費済みcodeの再使用検知、失効sid、assertion jti、署名鍵の保持は、関連する発行済み期限・通知展開/再送期限・許容時計ずれを覆うretain_untilで管理する。現設定の短縮だけで保持期限を縮めない。DBバックアップ復元は通常の配備ロールバックと別に扱い、復元時に外部管理の復旧世代を進め、旧cookie・code・tokenを受け入れない手順を実装前に定める。復元したDBだけから失われた失効履歴を再現できるとは仮定しない。

G1では、並行code交換の成功が一件、各SQL位置での失敗時の全体ロールバック、UPDATE 0件、assertionとcodeの異なる消費契約、全ログアウト中の認証、接続解除と初回許可、callbackと通知の順序逆転、outbox展開中断、lease引継ぎと遅延応答、primary/replica差、DB応答喪失を試験する。ローカルSQLiteでの成立だけではD1契約の検証完了とせず、隔離した実環境でも確認する。

## 参照

- [D1 Database API](https://developers.cloudflare.com/d1/worker-api/d1-database/)：batchのトランザクションとSessions API。
- [D1 Read replication](https://developers.cloudflare.com/d1/best-practices/read-replication/)：first-primaryと後続読取りの順序保証。
