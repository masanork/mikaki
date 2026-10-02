---
type: article
profile: sorane-okf/0.1
title: "mikakiのセキュリティと対応状況"
description: "パスキー認証、Vaultの暗号化、OpenID Conformanceテストと正式認定の状況を説明します。"
lang: ja
translation_key: security
updated: 2026-10-02
---

## パスキーによる認証

mikakiはWebAuthnのパスキーで認証します。ログイン画面では、接続先アプリを確認できます。ログインは連携先アプリから開始してください。

## Vaultと情報の共有

Owner Vaultでは、名前やノートを暗号化して保存する仕組みを開発しています。アプリへの属性提供やAIへのエクスポートには、それぞれ同意する操作があります。対応端末、復旧、運用の検証には残る課題があります。

詳しくは[Vaultの説明](https://github.com/masanork/mikaki/blob/main/docs/personal-vault.md)と[セッションの制約](https://github.com/masanork/mikaki/blob/main/docs/session-lifecycle.md)を参照してください。

## Conformanceテストと認定

2026年9月29日のローカルテストでは、OpenID ConnectのConfig OPがPASSED、Basic OPが22 PASSED・4 REVIEW・8 SKIPPED・1 WARNING・0 FAILEDでした。これは分離したConformance環境の結果です。

**正式なOpenID認定・FAPI認定・FIDO認定は取得していません。** テスト結果は、正式認定や本番環境の検証を意味しません。

[テストの範囲と記録](https://github.com/masanork/mikaki/blob/main/docs/oidf-conformance-2026-09-29.md)と[ソースコード](https://github.com/masanork/mikaki)を公開しています。
