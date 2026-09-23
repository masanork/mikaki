# OIDCの運用制限・通知・復旧

2026-09-22 / 初期実装向け設計

設定の正本となる見本は[runtime-policy.example.toml](../config/runtime-policy.example.toml)。従来のsession・flow・keyの見本を明示的に統合し、追加値を揃えた。運用値は実測後に調整する。秘密・配備ドメイン・client登録・暗号プロファイルは別の型付き設定で管理する。

## 入力と応答の境界

設定のbytes値はUTF-8/HTTP上のバイト数。bodyは読込み中に上限を適用し、Content-Lengthだけを信用しない。初期の要求body圧縮は受け付けない。JSON/JWTの重複キー、切断、深すぎる構造、不正UTF-8を拒否し、form/queryはパーセント復号後の値にも個別上限を適用する。未知のOAuthパラメーターは規格に従って無視するが、パラメーター数・サイズには数える。重複したプロトコルパラメーターは拒否する。

| 対象 | 初期上限・扱い |
| --- | --- |
| URL request target | 8 KiB。超過は414 |
| header合計 | 32 KiB。超過は431。前段のより小さい制限も配備試験で確認 |
| form/JSON | 32 KiB。超過は413。対応しないContent-Type/Content-Encodingは415 |
| WebAuthn body | 64 KiB、JSON/CBOR深さ8。証明書チェーンの追加をこの枠だけで許容したとは扱わない |
| JWT / JWKS | 16 KiB / 64 KiB、JWKSは16鍵。方式ごとの構造・署名長も別途検証 |
| OIDC等の一般JSON | 深さ16。JWTの各segmentはbase64url復号前後の両方を制限。WebAuthnは専用の深さ上限を使う |
| nonce/state | 各256 byte。自前生成は32 byteの乱数をbase64url化 |
| redirect URI | 2048 byte。サイズ内でも登録値完全一致が必要 |

PKCE verifierは規格上の43〜128文字、S256 challengeは規格の形式で検証する。運用設定の変更でこの規格制約を緩めない。JWTのcrit等の未対応拡張、alg=none、圧縮payloadは受け入れない。暗号方式の追加は既定サイズに収まると仮定せず、PQC移行時にHTTP・cookie・JWKS・ライブラリの上限を一緒に試験する。

初期のtoken/assertionをcookieへ格納しない。ID Token hintによるログアウトはフォームPOSTを用意し、将来の大きな署名をURL長に依存させない。現行の小さいtokenでは規格どおりGETも扱う。

## レートと容量

設定値は初期の小規模配置向け。IP単位の制限はNAT等で共有されるため、補助的な入口防御とし、アカウントの永久ロックにしない。IPを得るのは信頼された配備入口に限り、任意のX-Forwarded-Forを信用しない。ブラウザ単位はサーバー発行のランダムcookieに結び付ける。cookie未発行・無効の場合はIPの入口制限を適用し、cookieの大量再作成にも同じ制限をかける。

client/accountごとの制限は認証成功後に適用する。攻撃者が他者のclient_idやaccount_idを送るだけで、その主体の利用枠を消費させない。未認証の高コスト署名検証はIP/ブラウザ制限とサイズ制限の後に行う。

Cloudflare Rate Limiting APIはlocationごとの概算・結果整合である。グローバルな厳密カウンターと称しない。一回性、ceremonyの最大5失敗、同時状態数、管理許可の消費はD1の条件付き操作と一意制約で守る。KVキャッシュや入口のrate limitで代替しない。

pending loginはブラウザごと8件、SSOはaccountごと32件、client sessionはSSO/clientごと64件を上限とする。期限切れを除いた件数を作成と同じ原子操作で確認する。上限時は新規作成を拒否し、既存の有効セッションを勝手に消さない。利用者には不要なログインの終了を案内する。攻撃のたびに全ログアウトを起こさない。

ceremony失敗回数は無効なassertionでも当該ブラウザ取引の範囲で原子的に増加し、上限到達で終了する。暗号検証成功時も最後に失敗上限と未消費状態を再確認する。外部へaccountの存在・停止理由を詳細に返さない。

429はRetry-Afterを付け、クライアントは自動再ログインしない。レート制御基盤が故障した場合、書込みや認証の入口は503で停止する。既存アプリセッションは取得済みleaseまで利用できる。失効や通知の生成をキューの件数制限のために取り消さない。outbox肥大化時は警報と新規ログインの抑制で対処し、失効操作の余力を確保する。

## 公開endpointと登録

Discovery、JWKS、/authorize、/token、/userinfo、/session/check、/logoutを公開する。WebAuthn・同意・管理画面の状態変更はPOSTとし、originとCSRFを確認する。GETの認可要求から直接永続同意や管理操作を確定しない。アプリのbackchannel logout URIとpost-logout URIは静的登録し、要求から任意の送信先を受け取らない。

client登録は環境ごとにUUIDv4を割り当て、HTTPSのredirect/post-logout/backchannel URI、sector、公開鍵、private_key_jwt、id_token_signed_response_alg=ES256を明示する。RSA互換clientはRS256を明示する。ライブラリやOIDC登録時の省略値に任せてRSAを選ばせない。ワイルドカード、fragment、userinfo付きURLは登録しない。開発localhost例外は本番設定と分離する。

外向きHTTPは登録済みHTTPS宛先のみ。redirectを追わず、DNS解決後の内部/loopback/link-local宛先を拒否できる実行境界を用いる。許可hostからのDNS変更でも内部アクセスにならないことを検証する。初期に外部の動的jwks_uri/sector_identifier_uriを受け付けない。任意のtokenヘッダーURLは参照しない。

Discovery/JWKSは公開キャッシュ可能。それ以外の認証・token・UserInfo・失効確認・ログアウト応答はno-store。認証画面はCSPのdefault-src 'self'を基準に外部scriptを置かず、frame-ancestors 'none'、Referrer-Policy: no-referrerを付ける。CSP例外はWebAuthnの実ブラウザ試験で必要性を確認してから追加する。

## JWKS取得

issuerごとに同時取得を1件へ集約する。未知kidでの強制更新は最短30秒に一回、見つからないkidも30秒・issuerごと最大64件のnegative cacheとする。上限では古いnegative entryを捨てるが、issuer単位の取得間隔は解除しない。入力kidを無制限にキーへ追加せず、同時取得と要求サイズで負荷を抑える。鍵が見つからなければ拒否し、別鍵で総当たり検証しない。

timeoutは5秒。TTL内の既知鍵は取得障害中も使用できるが、期限切れキャッシュを無制限に延命しない。漏えいkid拒否はキャッシュ有効性に優先する。通常更新は24時間の事前公開と疎通確認により、未知kid更新の頻度制限で正規ログインを妨げないようにする。

## Logout配送

失効と同時に永続RevocationEventを作り、最大100件ずつdeliveryへ展開する。schedulerは1分ごとに走査し、即時起動の補助が失われても再開できる。leaseは実行直前に取得する。10件を走査しても、その全部を長時間leaseしたままローカル待機させない。clientごとの同時送信上限4件はlease獲得時にDBで確認する。

送信timeoutは10秒、leaseは30秒。最初の試行は準備完了次第実施。失敗n回後はU(base_delay, min(max_delay, base_delay × 2^(n-1)))のjitterで次回時刻を決める。上限付き計算で桁あふれを防ぐ。初期値は5秒〜1時間、最初の送信を含め最大48回、失効確定から24時間まで。展開の遅延で24時間を数え直さない。

2xxは受理。timeout・接続障害・408・429・5xxを再試行する。Retry-Afterは有効なら下限として尊重し、期限を超える場合は期限到達として停止する。3xxは追従せず設定障害、他の4xxは恒久失敗として警報にする。応答bodyは最大4 KiBで打切り、ログへ本文を保存しない。

再送時は新しいjti/iat/expでLogout Tokenを署名し、同じsidを送る。受信側は署名、aud、iss、events、sid、時刻を検証してから重複排除する。sidのみで無署名要求を成功扱いにしない。subだけで後から作られた新sidを消す通知は初期配送では送らない。受信成功は失効記録の永続化後に返す。

監視はpending最古15分、backlog 10,000件、恒久失敗と期限到達を対象とする。これらは警報値で、超過を理由に失効記録を捨てない。運用者の再配送は同じeventの対象だけを再試行し、明示した延長期限と保持期限を記録する。

## 監査・GC

監査の既定保持は30日、配送結果は7日、GCは1時間ごと500件、GC猶予は24時間。これらは保持の下限計算に加える運用値であり、存命のstateや未展開outboxを先に消さない。失効sidの最短保持期限は、対応するSSO/アプリセッション上限、遅延code/token、通知再送期限の最大値＋時計ずれ＋GC猶予。発行時・期限延長時にretain_untilを単調増加させる。

ログには操作ID、client、理由コード、遅延、サイズ、policy_revisionだけを基本とし、必要なaccount参照も閲覧権限を限定する。token/code/state/nonce、cookie、assertion、メール、credential原文、IP全文を通常ログへ書かない。レートキーは専用secretによる用途別HMACで仮名化し、保持は10分。秘密は監査用ハッシュと共用しない。

GCは期限を満たした行だけ条件付きで削除し、delivery展開・再配送延長と競合させる。署名鍵の削除は一般GCと別の運用操作にする。DB容量、確定失敗、lease期限超過、署名失敗、client別invalid_client/invalid_grant、session確認障害、設定版混在も監視する。

## 障害・復旧手順

| 状況 | 初動と復帰条件 |
| --- | --- |
| D1が確認不能 | 新規認証・交換・UserInfoを503。アプリはlease期限後停止。復旧後に期限・失効を再確認 |
| client鍵漏えい | client鍵を停止し当該clientの派生token/sessionを失効、通知を記録。新鍵登録とアプリ反映確認後に再開 |
| OP署名鍵漏えい | 新規発行停止、kid拒否を両アプリへ配布。影響を絞れなければ全セッション失効。新鍵と拒否設定の適用確認後に再開 |
| outbox障害 | 失効状態は維持。leaseと保存カーソルから再開。失効確認による反映上限を監視 |
| 設定不正 | 新配備を有効化しない。旧設定を維持し、暗黙の既定値へ戻さない |
| アプリ配備のrollback | 停止鍵・grant・epochを復活させない。新旧設定の長いleaseが満了するまで短い保証を表示しない |
| DBの過去時点への復元 | 入口停止、外部管理の復旧世代を変更、認証・許可の再確認を行ってから再開 |

復旧世代は通常DBと独立した配備secretのランダム値として管理し、アダプターが照合用ハッシュの名前空間と取引へ適用する。DBに保存された世代と配備値が一致しなければ認証を停止する。復元時は新世代を配備し、全SSO/code/token/管理許可を無効化、アプリへ全ローカルセッション終了を指示して適用を確認する。署名鍵も更新する。外部配備設定を古い値へ戻すrollbackは禁止する。

復元したcredential削除・account停止・client公開鍵/停止・grant履歴はDBだけでは正しさを再現できない。独立した監査/登録バックアップから照合し、不確かな主体の再ログインは停止したままとする。復旧世代だけで削除済みcredentialの復活を防げたとは扱わない。復旧訓練が通るまで本番復元を成功扱いにしない。

## 参照

- [Cloudflare Rate Limiting API](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/)：location単位・結果整合の制限。
- [OIDC Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)：署名付き通知とRPでの失効。
- [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html)：PKCE形式。
