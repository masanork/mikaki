---
type: index
profile: sorane-okf/0.1
title: 'mikaki — OSSのパスキー認証・OpenID Connect'
description: 'パスキー認証とOpenID Connectを提供するRust製OSS。招待からのはじめ方、暗号化Vaultの使い方、アプリ連携と対応状況を案内します。'
lang: ja
translation_key: index
updated: 2026-10-03
---

## パスキーでアプリにログイン

mikakiは、Rustを中心に開発しているOSSの認証サービスです。パスキーによる本人認証と、OpenID Connectによるアプリへのログインを提供します。

Web版は[サインイン画面](https://auth.mikaki.org/signin?lang=ja)から利用できます。連携先アプリへのログインは、そのアプリから始めます。接続先を確認してから、パスキーでサインインしてください。アカウント登録は現在、招待コードが必要です。

mikakiは実験的なプロジェクトです。対応状況や運用上の制約を確認してから利用してください。

## はじめて使う方へ

招待から登録し、いつもの端末で使い始めたい方へ。パスキーでのログインと、Vaultの解錠をそれぞれ確認できます。

- [招待からはじめる](getting-started.md)
- [招待について相談する](contact.md)
- [パスキーと端末の対応を確認する](passkeys.md)
- [Vaultの保存と共有を知る](vault.md)
- [よくある質問を見る](faq.md)

## 開発者・導入を検討する方へ

自分のWebアプリにパスキー認証を組み込みたい方へ。OpenID Connectの登録、Authorization CodeとPKCE、セッション確認の手順を案内します。

- [アプリ連携ガイドを読む](integration.md)
- [アプリの接続・登録を相談する](contact.md)
- [仕様・対応標準を確認する](specifications.md)
- [API referenceで要求・応答を確認する](api.md)
- [ローカルの連携例を動かす](integration-example.md)
- [GitHubで実装を確認する](https://github.com/masanork/mikaki)

## 安全性を評価したい方へ

採用前に、何を検証できていて、何が残っているか確認したい方へ。暗号化と復旧の制約、OpenID・FAPI・FIDOの試験記録と正式認定の状況を説明します。

- [セキュリティと対応状況を確認する](security.md)
- [Conformance試験結果の一覧を見る](conformance.md)
- [運用・サービスの条件を確認する](operations.md)
- [Vaultの共有と復旧の制約を読む](vault.md)
