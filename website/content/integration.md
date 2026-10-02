---
type: article
profile: sorane-okf/0.1
title: "mikakiとアプリを連携する"
description: "OpenID Connectでmikakiのパスキー認証をアプリへ接続するための開発者向けガイド。"
lang: ja
translation_key: integration
updated: 2026-10-02
---

## OpenID Connectで接続する

mikakiはOpenID Connect Provider（OP）として動作します。連携先アプリはRelying Party（RP）として、Authorization CodeフローとPKCE S256を使ってログインを開始します。

Discovery URLは次のとおりです。

```
https://auth.mikaki.org/.well-known/openid-configuration
```

エンドポイントや公開署名鍵のURLはDiscoveryから取得します。通常の連携では、`openid`スコープとES256の`private_key_jwt`によるクライアント認証を使います。クライアント登録は管理者による事前登録です。

## 導入の流れ

1. アプリのクライアント情報と正確なコールバックURLを登録します。
2. アプリからログインを開始し、mikakiの画面で接続先を確認します。
3. コールバックでコードを交換し、ID Tokenを検証します。

設定と検証の詳細は[RP連携ガイド](https://github.com/masanork/mikaki/blob/main/docs/rp-integration.md)と[クライアント登録手順](https://github.com/masanork/mikaki/blob/main/docs/rp-client-operations.md)を参照してください。

[セキュリティと対応状況](security.md)も確認してください。
