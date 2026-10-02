---
type: index
profile: sorane-okf/0.1
title: "mikaki — OSSのパスキー認証・OpenID Connect"
description: "パスキーでアプリにログインする、Rust製のOSS認証サービス。開発者向けの連携ガイドと対応状況を公開しています。"
lang: ja
translation_key: index
updated: 2026-10-02
---

## パスキーでアプリにログイン

mikakiは、Rustを中心に開発しているOSSの認証サービスです。パスキーによる本人認証と、OpenID Connectによるアプリへのログインを提供します。

Web版は[サインイン画面](https://auth.mikaki.org/signin)から利用できます。連携先アプリへのログインは、そのアプリから始めます。接続先を確認してから、パスキーでサインインしてください。アカウント登録は現在、招待コードが必要です。

## mikakiを知る

- [アプリへの連携方法](integration.md)：OpenID Connect、Authorization Code、PKCEの利用方法
- [セキュリティと対応状況](security.md)：パスキー、暗号化、Conformanceテストと認定の状況
- [GitHubでソースコードを見る](https://github.com/masanork/mikaki)

mikakiは実験的なプロジェクトです。対応状況や運用上の制約を確認してから利用してください。
