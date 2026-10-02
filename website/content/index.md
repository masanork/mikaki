---
type: index
profile: sorane-okf/0.1
title: 'mikaki — OSSのパスキー認証・OpenID Connect'
description: 'パスキー認証とOpenID Connectを提供するRust製OSS。招待からのはじめ方、暗号化Vaultの使い方、アプリ連携と対応状況を案内します。'
lang: ja
translation_key: index
updated: 2026-10-02
---

## パスキーでアプリにログイン

mikakiは、Rustを中心に開発しているOSSの認証サービスです。パスキーによる本人認証と、OpenID Connectによるアプリへのログインを提供します。

Web版は[サインイン画面](https://auth.mikaki.org/signin)から利用できます。連携先アプリへのログインは、そのアプリから始めます。接続先を確認してから、パスキーでサインインしてください。アカウント登録は現在、招待コードが必要です。

## はじめて使う方へ

- [招待からはじめる](getting-started.md)：登録、Webサインイン、連携アプリへのログイン
- [Vaultの使い方](vault.md)：保存と解錠、共有、パスキー移行の注意点
- [よくある質問](faq.md)：招待コード、端末の互換性、復旧と認定の状況

## 開発者・導入を検討する方へ

- [アプリへの連携方法](integration.md)：OpenID Connect、Authorization Code、PKCEの利用方法
- [セキュリティと対応状況](security.md)：パスキー、暗号化、Conformanceテストと認定の状況
- [GitHubでソースコードを見る](https://github.com/masanork/mikaki)

mikakiは実験的なプロジェクトです。対応状況や運用上の制約を確認してから利用してください。
