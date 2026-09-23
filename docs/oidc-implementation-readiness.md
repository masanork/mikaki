# 初期OIDCの実装基準と受入計画

2026-09-22 / 設計統合版。製品実装・認証取得・本番配備は未実施。

これまでの初期OIDC設計を実装へ進めるための基準としてまとめる。過去文書の旧候補のうち以下で絞り込んだ事項を示すが、採用済みADRの契約を上書きしない。担当範囲・決定状態・ADR未記録の項目は[文書案内](README.md)を参照する。実ドメイン、依存の実測、実環境での成立は確認済みとせず、末尾の公開条件に残す。Vault・連合・MCPの後続ゲートは本書の対象外。

## 実装へ渡す決定

| 項目 | 初期基準 |
| --- | --- |
| アカウント | sakimori共通アカウント、アプリごとのSubjectId。メール一致の統合なし |
| ID | 通常IDはUUIDv4、小文字36文字。初期D1ではTEXTとして保存。内部v7は必要性を測定するまで導入しない |
| sub | account/sectorごとの永続UUIDv4。接続解除・鍵更新で維持 |
| ログイン | 静的登録のサーバー側client、Code＋PKCE S256、state・nonce必須 |
| client認証 | private_key_jwt、client/環境/用途別鍵、assertion一回限り |
| 署名 | 通常はJOSE ES256。client登録にも明記。RS256は規格適合・明示的な互換プロファイルで実装対象 |
| EdDSA/PQC | 初期既定にはしない。鍵・方式の境界は追加可能にし、標準と実装の対応を確認して導入 |
| SHA-1 | 必要な互換用途の実装を許容。通常署名では有効化せず、用途別に許可 |
| Access Token | CSPRNG 32 byte、不透明、UserInfo専用、既定5分、refreshなし |
| UserInfo | subのみ、GET/POST＋Bearer、通常ログインで呼出し不要 |
| セッション | SSO最大30日、アプリ未操作7日かつ親期限内、失効確認lease最大5分 |
| ログアウト | RP-Initiated＋Back-Channel、失効と永続outboxを同時確定 |
| 設定 | 単一の[runtime-policy.example.toml](../config/runtime-policy.example.toml)から型付き入力を作る。秘密・配備情報は別 |
| ストア | D1一つでsakimoriの認証/OIDCを確定。アプリDBとの分散transactionなし |

詳細は[UX](oidc-login.md)、[ログイン取引](oidc-login-flow.md)、[token/UserInfo](oidc-access-token-and-userinfo.md)、[ストア](oidc-store-contract.md)、[運用制限・復旧](oidc-operations.md)、[暗号移行](crypto-agility.md)に従う。

## モジュール境界

G0のWebAuthn検証は従来の3 crateで進め、G1のOIDC coreは`sakimori-oidc`へ実装する。現在、静的client向け認可要求とtoken endpointのcode/PKCE入力の検証済み型、token formの厳格なdecode/validate型、不透明code生成・digest・期限計算、ES256 `private_key_jwt`署名/claim検証を実装済み。token formは未知・重複項目を拒否し、authorization_code、private_key_jwt種別、client ID、code、redirect URI、verifier、assertionを一つの要求へ束ねる。交換入力は正規形の32-byte code、RFC 7636 verifier、限定長のredirect URIを検証し、bearer codeとverifierを保持せずD1照合用digest/challengeへ変換する。assertionは登録済みP-256公開鍵・固定ES256・完全一致audience・iss/sub/jti/exp/iat・期限上限を検証し、成功型はD1再確認用のclient/key revision、jti、設定由来のretain_untilを保持する。時間設定はassertion lifetimeとclock skewを一体化した検証済みpolicy型で渡し、workerは統合TOMLから生成されたschema version/revision/hash付きstrict JSON projectionを検証して値を構築する。ただし、HTTP endpointからの読み込みは未接続。workerには未検証headerのkidを登録検索にだけ使い、D1から公開鍵を取得してcoreで検証後、同じclient/key revisionを条件にassertion jtiを原子的に予約するadapter関数と初期schema migrationを追加した。HTTP requestのform decodeとassertion認証関数はあるが、fetch routeから未接続で、migrationも未配備。未配備の`0001`にはclient/key/assertion replay、account/credential/client session、SSO context、authorization codeとnonce、signing key、token issuance、revocation、原子batch guardおよびsession有効性viewを含めた。これは保存関係の土台であり、authorization code消費、認証/session証拠との結合、token発行処理、HTTP routeは未実装である。migrationに合わせた本番D1動作も未確認で、完成したendpointを意味しない。依存はworker → oidc → auth → webauthnとし、workerはauthの管理APIも直接呼べる。oidcはWorkers/D1/HTTPクライアントの型に依存しない。空crateを先行作成することは求めない。

sakimori-oidcは認可取引、client認証、JOSEの用途別検証、セッション、outboxの業務契約を担当する。authが返す検証済み本人認証の型を受け取り、HTTPから同型をdeserializeできないようにする。認証結果はaccount・credential・ceremony・ブラウザ取引・epoch・期限に結び付け、再利用可能な裸のAccountIdを本人認証の証拠にしない。

workerはHTTP制限、cookie、秘密管理、D1、時刻・乱数、外向き通信を担当する。ストアと署名のポートは必要な業務操作に限り、汎用プラグインを作らない。署名ポートは将来KMS/WebCrypto等を利用できる非同期境界とし、公開鍵形式や署名サイズをRSAへ固定しない。

## HTTP契約の補足

| Endpoint | 処理と代表的な失敗 |
| --- | --- |
| Discovery / JWKS | GET、固定issuer、公開情報のみ。秘密鍵・非公開client一覧を含めない |
| GET /authorize | code/openid/S256を検証。無効client/redirectはローカル400、それ以外の認可エラーは検証済みredirectへstateとともに返す |
| POST /token | form body、authorization_codeとprivate_key_jwt。invalid_client、invalid_grant、invalid_request、unsupported_grant_typeを区別。外部へ細かい内部失効理由は出さない |
| GET・POST /userinfo | Bearer、subのJSON。詳細はUserInfo仕様 |
| POST /session/check | client署名＋sid。200 active=falseと通信障害503を区別。存在照会は認証後に限定 |
| GET・POST /logout | 標準のhint/登録済み戻り先/stateを検証し、必要な確認を表示。SSO失効とevent確定後に完了へ |
| 各アプリのbackchannel URI | POST、logout_tokenを検証し、失効記録を保存して200。不正通知は400、一時ストア障害は503 |

OAuthのエラーコードとHTTP statusは対象規格の規則に従う。サイズ超過・過負荷・一時障害をすべてinvalid_grantへ丸めない。内部結果はInvalidInput / Unauthenticated / Forbidden / Expired / Replayed / Conflict / Limited / Unavailable / OutcomeUnknownに分け、外部へはendpointごとに写像する。

/session/checkのactive=true応答はsub、auth_time、expires_at、lease_ttl（秒）、app_idle_timeout（秒）、policy_revisionを返す。app_idle_timeoutは新規アプリセッションに適用し、既存値を延長しない。active=falseには他の主体情報を付けない。issuer、client、sidは照会先と認証済み要求から結び付ける。

Discoveryはresponse_types_supported=[code]、grant_types_supported=[authorization_code]、subject_types_supported=[pairwise]、scopes_supported=[openid]、code_challenge_methods_supported=[S256]、token_endpoint_auth_methods_supported=[private_key_jwt]を公開する。署名方式は実装・相互運用試験に通ったES256とRS256を掲載し、まだ使えない方式を予告掲載しない。backchannel_logout_supportedとbackchannel_logout_session_supportedをtrueにするのは実装後とする。

ID Tokenはiss、sub、aud、exp、iat、nonce、auth_time、sidを発行する。通常は単一aud。acr/amrは検証済みの意味と値の体系を決めずに推測で付けない。claims_supportedは実際のID Token/UserInfoのclaimを記載する。独自のsession APIをUserInfo claimとして宣伝しない。

request/request_uri、動的登録、claims parameter、署名/暗号化UserInfoは初期未対応としてメタデータと要求処理を一致させる。request/request_uriを送られた場合は規定の非対応エラーを返し、URLを取得しない。promptのnone/login/consent/select_account、max_ageとauth_timeを実装する。display、ui_locales、claims_locales、acr_valuesは規格の最低対応を満たし、未提供の言語/保証を偽って返さない。max_age=0は再認証要求として扱い、noneと対話が必要な条件が両立しなければ規定のエラーにする。

## 依存の評価と採用条件

暗号プリミティブとJWT形式は既存ライブラリを利用する。JSON/URL/PKCE等を含むOPの状態遷移はsakimoriの契約として実装するが、独自の暗号方式や署名検証を作らない。

| 対象 | 評価対象と選択条件 |
| --- | --- |
| Rust JOSE | jsonwebtoken 11.1.0を検証候補とする。default algを使わず用途別にES256/RS256等を指定。署名発行は同期`Signer` traitで非同期KMS/WebCrypto portに直結できないが、外部で署名した値を公開JWS構造体へ渡す境界はprobe済み。鍵形式、重複JSON、時刻注入、配備先Wasmを確認して採否を確定 |
| ES256/WebAuthn | RustCrypto p256等の保守された実装。JOSEの固定長R\|SとWebAuthnのDER署名を混同しない。各仕様の形式変換は既存のパーサーを使用 |
| RSA互換 | 保守されたruntime/KMS等の秘密鍵操作を優先評価。RS256 3072 bitを初期互換発行プロファイルの基準とし、client公開鍵検証は明示登録された2048 bit以上を評価 |
| RustのRP相互運用 | openidconnect-rs。これはRP用でありsakimori OPの実装を提供するものではない。private_key_jwtを含む対応は実試験で確認 |
| JSON/URL/UUID/秘密型 | serde/serde_json、url、uuid、zeroize等。入力検証と秘密のDebug禁止は呼出し側でも契約化。重複JSONキー拒否は通常のmap deserializeに任せない |
| Workers/D1 | workers-rsの採用版でbatch・session APIの可用性を確認。不足時はworkerアダプター内だけに小さなJS境界を置き、coreへJS型を漏らさない |

2026-09-23の隔離spikeでは、公開版jsonwebtoken 11.1.0のRustCrypto backendがES256/RS256のNode jose署名をNativeとWasmで検証し、alg・改変・issuer・audience・期限・鍵差替えを確認した。release Wasmは638 KB、gzip 253 KB。検証APIが毎回JWKをparseするベンチで、10,000回の1検証はNative/WasmでES256が約214/690 µs、RS256が約109/461 µsだった。実アプリのJWKS cacheを反映しない保守的な上限値として扱う。

組込みbackendを無効にした独自CryptoProviderでもES256/RS256検証を保ったまま308 KB（gzip 121 KB）に縮んだ。probeではissuer/audience/expiryとduplicate claimも確認した。Native/Wasmの10,000回測定ではES256が約216/681 µs、RS256が約228/417 µs。毎回JWKから鍵を作るため、cache済み鍵の性能値ではない。RSA JWKのn/eをDERへ変換する独自前処理が必要である。[crypto module](https://docs.rs/jsonwebtoken/11.1.0/jsonwebtoken/crypto/)の`JwtSigner`は同期traitのためasync KMS/WebCrypto signerを直接統合できないが、Node WebCrypto署名のJWS構造体受渡しに加え、workerd 1.20260921.1の`crypto.subtle.sign`が作ったcompact ES256 JWSをRust/Wasmで検証するprobeも成功した。これは一時生成鍵によるローカルruntime確認であり、Workers KMS binding・永続鍵形式・エラー処理は未検証。時刻注入、重複header/payloadの全境界、キャッシュ済み鍵の性能、実D1との統合を確認して依存選択を確定する。依存spikeの再実行・制約は[隔離JOSE probe](../design/probes/README.md#rust-jose-依存スパイク初期評価)に記録した。

2026-09-23時点で`rust_crypto` featureはrsa/p256/p384/ed25519-dalek等をまとめて有効化し、本番で使わないアルゴリズムも依存グラフに入る。openidconnect-rsのmain manifestは4.0.1で、既定HTTP依存はreqwest/rustls。Workers向けに既定featureを無検討で有効化しない。

RustSecのRUSTSEC-2023-0071は、参照時点でRustCrypto rsaの秘密鍵操作に対するtiming問題を未修正としていた。RSA対応自体を取りやめる理由とはせず、当該実装を公開サービスの秘密鍵処理へ採用する根拠が揃うまで採用しない。公開鍵検証だけの経路と秘密鍵操作を分け、依存監査で脆弱なコードがリンク/到達する範囲も記録する。勧告を丸ごとignoreして先へ進めない。

したがって本段階で本番Cargo.lockを作ったり、未検証のWasm対応を断言したりしない。依存spikeは同じテストベクトルによるNativeとwasm32-unknown-unknownのビルド・実行、ES256/RS256の相互署名検証、鍵更新、JWT改変、バンドルサイズ/遅延、cargo auditを採用条件とする。jsonwebtokenが署名境界を満たさなければ、crypto agilityのインターフェースを維持して別JOSEライブラリを比較する。

## 実行可能な設計検証

[ES256/JOSE・ローカルD1の試作](../design/probes/README.md)で、Nativeの3試験、Node上のWasm/JOSE相互運用6試験、workerd/D1互換環境の6試験が通った。製品のRust JOSE層、RSA互換経路、遠隔D1のread consistency、ログインUIを検証済みとはしない。依存版と再実行方法は試作READMEに記録した。

[縮小SQL schema](../design/sql/oidc-critical-schema.sql)、[assertion受理](../design/sql/accept-assertion.sql)、[code交換](../design/sql/exchange-code.sql)、[全ログアウト](../design/sql/revoke-all.sql)を用意した。本番schemaではなく、暗号検証済み入力を前提とする原子性の検証模型である。管理許可消費、認可code作成、ブラウザ結び付け、復旧世代、全レコードの保持は本番実装で加える。

```sh
python3 scripts/test_oidc_sql.py
python3 scripts/check_design.py
```

設定検証はPython 3.11以降が必要。SQL試験は標準sqlite3を使い、外部サービスへ接続しない。13試験で並行交換、一回性、endpoint取り違え、0件更新、全SQL段階の失敗、制約違反、失効・世代変更・期限境界、token発行前後のsession状態を確認する。D1 batchの実行コンテキストでchanges()とCHECK制約が同じ契約を満たすことは、実D1でも確認する。

設定検証は未知/欠落キー、型・単位・整数上限、設定間の関係、正規化したpolicy_revision、旧断片との一致と文書リンクを確認する。これらは設計用ツールであり、Rustの製品loaderの代わりではない。

## 実装順と公開条件

現在の[ローカル縦切り実装と検証範囲](../local/README.md)を別記した。単一RPでのブラウザ経路が動いても、下記の本番migration、運用、conformanceの完了を意味しない。

フロントのSvelte 5・初期ja/en・規模とcoverage測定・CIの具体的な推奨案は[フロントと品質CI](frontend-and-ci.md)を参照する。製品コード追加時から対象の品質ゲートを導入する。

| 段階 | 実装・確認 | 完了の証拠 |
| --- | --- | --- |
| 1 | 型付き設定、秘密/配備情報の分離、Native/Wasm暗号依存spike | lock・監査結果・既知解・両targetの実行結果 |
| 2 | 本番migration、authからOIDCまでの原子操作 | 全失敗点/競合試験、隔離D1でのbatch・primary読み取り確認 |
| 3 | Code Flow・client認証・Discovery/JWKS・UserInfo | 標準RPとの相互運用、token取り違えと鍵更新試験 |
| 4 | tossa・tsudoiのcallback、cookie、セッション確認 | 両アプリの通常/初回/複数タブ/キャンセル/応答喪失のブラウザ試験 |
| 5 | 管理、RP/Back-Channel Logout、outbox、GC、監視 | 失効上限、通知重複・欠落、GC競合、鍵漏えい/DB復元の訓練 |
| 6 | 対象OPプロファイルのconformanceと負荷・公開前確認 | 試験スイートの版・設定・結果、未対応範囲、実測と運用手順 |

2026-09-23時点で、段階5のうち単一RP向けログアウトoutboxのlease・再試行・期限・scheduled復旧・集計警告を[ローカル実装](../local/README.md#ログアウト通知の配送2026-09-23)で検証した。期限切れ認証取引・再使用防止記録・RPセッションに加え、OPのSSO配下と完了した単一SSO通知履歴のGC、標準入力からの運用者再配送と原子的な監査記録、アカウント全セッション失効と旧epochへの通知展開もローカルD1で検証済み。本番migration、管理操作、アカウント停止・監査の外部保管、外部監視連携と復旧訓練は残り、段階5全体の完了ではない。

conformanceは対象プロファイルを選び、そのスイートに必要な互換機能を明示して実装する。RS256が使えることだけで全面適合とせず、試験用の例外を本番既定へ持ち込まない。署名方式以外のprompt・claim・エラー・Discovery等も確認する。

受入試験には、(1)既存UXの画面数、(2)code/state/nonce/PKCE/aud/iss/alg、(3)assertion再使用と鍵停止、(4)親SSO・grant・credential失効、(5)通知/確認/callbackの全順序、(6)新旧設定/鍵の混在とrollback、(7)body/JSON/パラメーターの境界・fuzz、(8)負荷時の容量とrate制御、(9)秘密がログ/ブラウザ保存へ出ないこと、(10)PQC向けの大きな公開鍵/署名を想定した制限変更を含める。

残る外部入力は本番issuer・RP ID・origin、両アプリのredirect/post-logout/backchannel URL、配備先アカウント、対象ブラウザ/認証器である。これらを推測した実値で埋めない。実環境の作成や公開を伴わず進められる設計作業は本書で一式まとめたが、公開条件は実装・検証を終えるまで未達である。

## 参照

- [jsonwebtoken公式manifest](https://github.com/Keats/jsonwebtoken/blob/master/Cargo.toml)・[README](https://github.com/Keats/jsonwebtoken)：暗号featureと対応方式。
- [openidconnect-rs公式manifest](https://github.com/ramosbugs/openidconnect-rs/blob/main/Cargo.toml)：RP用実装と依存。
- [RustSec RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)：RSA実装のtiming勧告。
- [OIDC Core §15](https://openid.net/specs/openid-connect-core-1_0.html#ImplementationConsiderations)：必須実装と静的接続の区分。
