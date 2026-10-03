---
type: article
profile: sorane-okf/0.1
title: 'mikakiのセキュリティとOpenID・FAPI・FIDO対応状況'
description: 'mikakiのパスキー認証とVault暗号化、OpenID Connect・FAPI 2.0・FIDO2の試験記録、正式認定の状況と導入前の確認事項を説明します。'
lang: ja
translation_key: security
updated: 2026-10-03
---

mikakiはパスキー認証と暗号化したVaultを開発するOSSのプロジェクトです。**正式なOpenID認定・FAPI認定・FIDO認定は取得していません。** このページでは、公開している試験記録の対象と、利用する前に確認する制約を説明します。

## パスキーによる認証

mikakiはWebAuthnのパスキーで認証します。ログイン画面では接続先アプリを確認できます。Web版は[Webサインイン](https://auth.mikaki.org/signin?lang=ja)から、アプリへのログインは連携先アプリから開始します。

通常の本人認証とVaultの解錠は別の操作で、Vaultの復号には対応パスキーとPRF機能が必要です。端末変更や解錠の確認手順は[パスキーの説明](passkeys.md)を参照してください。

## Vaultと情報の共有

Owner Vaultでは、名前やノートを暗号化して保存する仕組みを開発しています。アプリへの属性提供やAIへのエクスポートには、それぞれ同意する操作があります。対応端末、復旧、運用の検証には残る課題があります。

サーバーには暗号文と、項目の種類・更新時刻など運用上のメタデータを保存します。相手への共有を承認した場合は、選んだデータを復号できる相手が増えます。ダウンロードした平文ファイルや、相手に渡した内容をあとから回収することはできません。

[Vaultの使い方](vault.md)で保存・共有・移行の制約を確認してください。すべての解錠手段を失った場合の復旧や、すべての実端末での互換性は保証していません。設計は[Vaultの説明](https://github.com/masanork/mikaki/blob/main/docs/personal-vault.md)に公開しています。

## OpenID・FAPI・FIDOが扱う範囲

| 仕様・認定の対象 | mikakiで確認する範囲 |
| --- | --- |
| OpenID Connect | アプリへログインするための認証応答、コード交換、ID Tokenなど |
| FAPI 2.0 Security Profile | 高い安全性を求めるAPIの認可、トークン発行と利用など |
| FIDO2 Server | パスキーの登録・認証をサーバーが検証する処理など |

これらは対象が異なります。パスキーでログインできることや、ある試験で失敗がなかったことだけで、ほかの仕様への適合、正式認定、Vaultの復旧を証明できるわけではありません。FAPIのローカル構成と、通常の[Webアプリ連携](integration.md)の構成も区別してください。

## Conformanceテストと認定

以下は日付と構成を限定した開発・ローカル試験の記録です。現在の本番環境を同じ認定プロファイルで検証した結果ではありません。

**OpenID Connect — 2026年9月29日：** 分離したConformance環境でConfig OPはPASSED、Basic OPは22 PASSED・4 REVIEW・8 SKIPPED・1 WARNING・0 FAILEDでした。HTTPSとChromiumの仮想パスキーを使った試験です。[OIDCの試験範囲と記録](https://github.com/masanork/mikaki/blob/main/docs/oidf-conformance-2026-09-29.md)を参照してください。

**FAPI 2.0 — 2026年9月30日：** 分離したFinal ASの選択プロファイルで、52モジュール中45 PASSED・4 REVIEW・3 SKIPPED・0 FAILED・未完了0でした。クライアントの鍵認証、認証要求を事前に送るPAR、トークンを送信者の鍵に結び付けるDPoPを使っています。人によるレビュー、本番エッジのTLS、独立したクライアントとリソースサーバーの検証は別に残っています。[FAPIの試験記録](https://github.com/masanork/mikaki/blob/main/docs/fapi2-conformance-2026-09-30.md)と[対応状況の詳細](https://github.com/masanork/mikaki/blob/main/docs/fapi2-readiness.md)を参照してください。

**FIDO2 Server — 2026年9月29日：** Tools 1.9.2を使った開発試験では、分離したnativeアダプターとWasmアダプターで、それぞれ167成功・0失敗でした。製品の通常設定より広いアルゴリズム・attestationを扱う試験用構成で、正式提出用の結果ではありません。MDSは`mds3.0`を選択し、ツールのES256Kケースはpendingで未実行でした。[認定準備と検証範囲](https://github.com/masanork/mikaki/blob/main/docs/webauthn-certification-readiness.md)を参照してください。

[試験結果一覧](conformance.md)にはログアウトとOID4VCの限定試験も含め、ツール版、結果の内訳、未検証範囲を掲載しています。公開環境の機能は[仕様・対応標準](specifications.md)で確認できます。

## 試験結果の読み方と残る課題

`REVIEW`は人による確認が残る結果、`SKIPPED`は選択した構成で実行しなかった結果です。どちらもPASSEDに合算しません。`WARNING`も独立した結果として残します。

FAPIの残るレビューは、PARなしの認証要求と、再利用・期限切れ・別クライアントの参照値を扱うケースです。省略された任意機能には、追加のclaims指定やrefresh tokenなどがあります。個別のアプリがそれらを必要とする場合は、対応と検証を追加する必要があります。

仮想パスキーや試験用アダプターの結果を、すべての実端末の動作保証へ広げることはできません。[端末互換性の記録](https://github.com/masanork/mikaki/blob/main/docs/webauthn-device-compatibility.md)には、確認できた操作と未検証のOS・ブラウザ・認証器を分けて記載しています。FIDO2の認定準備にも、提出対象の版・設定の固定、MDS要件の確認、相互接続試験などが残ります。

## 認定制度の確認先

OpenID Foundationは[Conformanceテストと認定制度](https://openid.net/certification/)を提供しています。テストを実行できることと、正式認定を取得することは別です。[OSS向け費用免除](https://openid.net/certification/open-source-project-certification-policy/)には主要な保守担当者が雇用主からプロジェクト開発の報酬を受けているかなど条件があり、申請ごとの判断です。OSSであるだけで認定や無料適用が確定するわけではありません。最新条件は[公式料金表](https://openid.net/certification/fees/)も確認してください。

FIDO Allianceの[FIDO2 Server認定](https://fidoalliance.org/certification/functional-certification/functional-certification-servers/)では、自己検証、相互接続試験、提出などが必要です。OpenIDの制度とは別で、[FIDOの公式料金・条件](https://fidoalliance.org/fido-certification-fees/)を確認する必要があります。

## 導入前に確認する

1. 実際に使う端末・ブラウザ・パスキーの保存先で、ログインと保存済みVaultの解錠を別々に確認します。
2. 端末を手放す前に移行先で項目を開き、失うと困る情報の控えと復旧手順を確認します。
3. アプリ連携では、登録したコールバック、セッション確認、失効、ログアウト、OP停止時の挙動をそのアプリから検証します。
4. 認定が利用条件になっている場合は、必要な製品・版・プロファイルの正式認定を確認します。このページの開発試験だけで要件を満たすとは判断しないでください。

実装と課題は[ソースコード](https://github.com/masanork/mikaki)と[セッションの制約](https://github.com/masanork/mikaki/blob/main/docs/session-lifecycle.md)を参照してください。

## 次に読む

- [はじめ方](getting-started.md)：利用上の制約を確認したら、登録とWeb版の操作へ進みます。
- [アプリ連携ガイド](integration.md)：導入を検討する構成の接続手順と検証事項を確認します。
