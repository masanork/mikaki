---
type: article
profile: sorane-okf/0.1
title: 'mikakiのConformance試験結果一覧 — OpenID・FAPI・FIDO'
description: 'OpenID Connect、ログアウト、FAPI 2.0、FIDO2 Server、OID4VCの試験日・ツール版・結果・検証範囲と残る課題を一覧で提示します。'
lang: ja
translation_key: conformance
updated: 2026-10-03
---

mikakiの公開リポジトリにあるConformance試験記録の索引です。**OpenID・FAPI・FIDOの正式認定は取得していません。** 結果は記載した日付・版・構成に限定され、現在の本番環境の認定や、全端末の動作保証を示しません。

## 結果の読み方

`PASSED`はそのモジュールの成功、`REVIEW`は人による評価が残る結果、`SKIPPED`は選択した構成での未実行、`WARNING`は警告です。レビューや省略を成功数に加算しません。0 FAILEDでも、任意機能の網羅や正式な審査完了を意味しません。

以下の件数は最新の記録された実行単位です。後続の個別再実行を足してモジュール数を増やしたり、nativeとWasmを一つの実行と扱ったりしません。

## OpenID Connect OP

**2026年9月29日 / OIDF Conformance Suite 5.3.1、rev `4bfcdf8`。** 分離したRust Worker、workerd、使い捨てD1、HTTPS、Chromium仮想パスキーの構成です。

| プラン | 結果 |
| --- | --- |
| Config OP | 1 PASSED |
| Basic OP、35モジュール | 22 PASSED、4 REVIEW、8 SKIPPED、1 WARNING、0 FAILED |

REVIEWは認証画面や未登録redirect URIの画面証跡などです。名前を返さない任意要求ではWARNINGが残り、未対応の任意scope・request object・refresh tokenなどは省略されています。架空の属性を返して成功扱いにはしていません。

[実行記録](https://github.com/masanork/mikaki/blob/main/docs/oidf-conformance-2026-09-29.md)と[モジュール・版・ビルド情報の機械可読記録](https://github.com/masanork/mikaki/blob/main/design/probes/oidf/results-2026-09-29.json)を公開しています。

## OpenID Connectのログアウト

**2026年9月27日 / OIDF Conformance Suite 5.3.1。** ローカルOP fixture、Codeフロー、Chromium仮想パスキーの試験です。

| プラン | 結果 |
| --- | --- |
| RP-Initiated Logout、11モジュール | 3 PASSED、8 REVIEW、未完了0 |
| Back-Channel Logout | 2 PASSED：DiscoveryとRP起点の通知 |

画面をローカルで確認した後も、8件の判定はREVIEWのままです。Back-Channelの成功は一つの正常な通知経路を確認したものです。fixtureと受信サーバーのホスト名の不一致を避けるため、**当該ローカル試験プロセスのみTLS証明書検証を無効化**しています。本番TLS、通知の再試行や受信側障害の全網羅を証明しません。[実行と制約の記録](https://github.com/masanork/mikaki/blob/main/docs/oidc-logout-conformance.md)を参照してください。

## FAPI 2.0 Security Profile

**2026年9月30日 / OIDF Conformance Suite 5.3.1、rev `4bfcdf8`。** 分離したFinal ASの`plain_fapi`、`private_key_jwt`、DPoP、OIDCの選択構成です。ローカルHTTPS relayと仮想パスキーを使っています。

| 最新の完了実行 | 結果 |
| --- | --- |
| Final AS、52モジュール | 45 PASSED、4 REVIEW、3 SKIPPED、0 FAILED、未完了0 |

4 REVIEWはPARなしの直接認証と、再利用・期限切れ・別クライアントの参照値の画面評価です。3 SKIPPEDは追加claims指定、選択構成のRSAクライアント署名ケース、refresh tokenなどの条件付きモジュールです。初回の52件は36 PASSED・8 FAILED・3 REVIEW・3 SKIPPED・未完了2で、その後に実装修正と実行上の問題を解決して上の結果になりました。

[修正と再実行を含む記録](https://github.com/masanork/mikaki/blob/main/docs/fapi2-conformance-2026-09-30.md)と[準備状況](https://github.com/masanork/mikaki/blob/main/docs/fapi2-readiness.md)があります。本番エッジTLSと独立したクライアント・リソースサーバーの検証、人による審査は別に残っています。

## FIDO2 Server

**2026年9月29日 / FIDO Conformance Tools 1.9.2。** 全Server Testsと10個のoptionalチェックを選択した分離アダプターの開発試験です。

| 実行対象 | 結果 |
| --- | --- |
| nativeアダプター | 167成功、0失敗 |
| Wasmアダプター | 167成功、0失敗 |

通常の製品設定より広いアルゴリズム・attestationを許す試験構成です。MDSは明示的に`mds3.0`を選択し、厳密な既定設定は維持しています。ツールのES256Kケースはpendingで実行されていません。正式提出、対象版・設定の固定、MDS要件確認と相互接続試験が残っています。

[認定準備と結果](https://github.com/masanork/mikaki/blob/main/docs/webauthn-certification-readiness.md)、[詳細実行記録](https://github.com/masanork/mikaki/blob/main/local/conformance/results-2026-09-28.md)、[実端末の互換性記録](https://github.com/masanork/mikaki/blob/main/docs/webauthn-device-compatibility.md)を確認できます。

## OID4VCの限定的なコンポーネント試験

**2026年9月29日 / OIDF Conformance Suite 5.3.1、rev `4bfcdf8`。** 公開IdPとは別の合成データを使う構成です。

| 対象 | 結果と範囲 |
| --- | --- |
| OID4VCI issuer metadata | 1 PASSED。OWF 0.6.0のメタデータのみ |
| OID4VP verifier選択9モジュール | 7 PASSED、2 REVIEW。`@openeudi/openid4vp` 0.12.0を使う検証コンポーネント |

OID4VCIアダプターはtoken・nonce・credential endpointを公開しません。メタデータ試験の成功は発行フロー全体やDPoP対応の成功ではありません。OID4VPは合成PID、URL query、`direct_post`、`dc+sd-jwt`/ES256の限定範囲で、正常系と最小`cnf.jwk`の2件は受理の証跡を付けたREVIEWです。残る7件は署名、audience、nonce、`sd_hash`、時刻などの拒否試験です。完全なwallet/verifierプラン、HAIP、mdoc、署名付き要求は含みません。[試験対象と証跡](https://github.com/masanork/mikaki/blob/main/docs/oidf-conformance-2026-09-29.md)を参照してください。

## 補助検証と正式認定

リポジトリのCIやcomponentテスト、実端末チェックは上のConformance実行とは別です。DPoPの45 component/policyケースと11 loopback HTTPSケースなどの[補助記録](https://github.com/masanork/mikaki/blob/main/docs/fapi2-readiness.md)もありますが、公式試験の成功数には加えません。

正式な認定には[OpenID Foundation](https://openid.net/certification/)や[FIDO Alliance](https://fidoalliance.org/certification/functional-certification/functional-certification-servers/)の対象版・プロファイル・提出・審査条件が適用されます。新しい実装のCI成功だけでこの一覧の日付や認定状態は更新しません。再実行した構成と結果が公開記録として確認できた時に更新します。秘密鍵、トークン、生のユーザー情報を含むログは公開対象にしません。

## 次に読む

- [仕様・対応標準](specifications.md)：公開IdPで接続できる機能を確認します。
- [セキュリティと対応状況](security.md)：Vault、端末互換性、導入前の制約を確認します。
