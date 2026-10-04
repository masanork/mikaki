---
type: index
profile: sorane-okf/0.1
title: 'mikaki — OSSのパスキー認証・OpenID Connect'
description: 'Rust製OSSの認証サービス。招待からのはじめ方、パスキーとVault、アプリ連携、仕様・対応標準と検証結果を案内します。'
lang: ja
translation_key: index
updated: 2026-10-04
---

mikakiは、パスキー認証とOpenID Connectを提供するRust製OSSの認証サービスです。利用者のはじめ方、アプリ開発者の接続手順、導入前の評価資料をここから探せます。

## 使いはじめる

招待から登録し、いつもの端末でサインイン。パスキーでのログインとVaultの解錠は、別々に確認します。

- [招待からはじめる](getting-started.md)
- [パスキーと端末の対応](passkeys.md)
- [Vaultの保存・共有・復旧](vault.md)
- [よくある質問](faq.md)

## アプリを接続する

自分のWebアプリにmikakiの認証を組み込みたい方へ。登録依頼からログイン・セッション確認までを案内します。

- [アプリ連携ガイド](integration.md)
- [公開IdPへの接続デモ](integration-demo.md)
- [ローカルで動く連携例](integration-example.md)
- [API reference](api.md)

## 仕様と検証を確認する

何に対応し、何を検証できていて、どこに制約があるか。導入判断のための情報をまとめています。

- [仕様・対応標準](specifications.md)
- [セキュリティと制約](security.md)
- [Conformance試験結果](conformance.md)
- [運用・サービスの条件](operations.md)

## 招待・連携について相談する

招待を持っていない方、自分のアプリの登録を依頼したい方へ。必要な情報と、相談から試用までの流れを説明します。

[招待・アプリ連携の相談窓口へ](contact.md)。現在は招待制の実験公開です。利用・導入前に[提供条件](operations.md)をご確認ください。
