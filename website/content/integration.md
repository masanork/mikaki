---
type: article
profile: sorane-okf/0.1
title: 'mikakiとアプリを連携する'
description: 'OpenID Connectでmikakiのパスキー認証をアプリへ接続するための開発者向けガイド。'
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

## 登録に必要な情報

環境ごとに別のクライアントを用意し、アプリ名、ホスト名、正確なHTTPSコールバックURL、ES256用の公開JWKとその鍵IDを管理者へ提供します。秘密鍵はアプリのバックエンドに保管し、mikakiへ送らないでください。公開の動的クライアント登録APIはありません。

このガイドは秘密鍵を保持するWebアプリのバックエンド向けです。ネイティブの公開クライアントには別の登録・認証・コールバックのルールがあります。

## 導入の流れ

1. アプリのクライアント情報と正確なコールバックURLを登録します。
2. アプリからログインを開始し、mikakiの画面で接続先を確認します。
3. コールバックでコードを交換し、ID Tokenを検証します。

ログインごとに`state`、`nonce`、PKCEの検証値を生成し、ブラウザのトランザクションと結び付けます。コールバックで`state`と発行者を確認してから、バックエンドでコードを交換します。ID Tokenの署名、発行者、対象クライアント、有効期限、`nonce`を検証し、`sub`をアプリ側のユーザーへ対応付けます。`sub`はメールアドレスではありません。

## セッションとログアウト

管理対象RPは、アプリのセッション作成時と検証期限を過ぎた保護リクエストで、バックエンドから`/session/check`を呼びます。これはmikaki固有の拡張です。確認先に対応する新しいクライアントアサーションが必要で、トークン交換用のアサーションを再利用できません。

ログアウト先も登録が必要です。Back-Channel Logoutや状態確認をアプリ側で処理し、通知が届かない場合やOP停止時に保護操作を続けないことを確認します。アプリ自身のセッションCookieを管理し、mikakiのCookieを共有しないでください。

## 現在の対応範囲

本番連携の基本スコープは`openid`です。名前の属性提供には別の同意・運用設定・検証が必要で、通常のログインだけでVaultの名前やノートを受け取れるわけではありません。`email`スコープ、動的登録、一般的なFAPI対応を提供していると仮定しないでください。

登録完了だけでは動作確認になりません。コード交換に加え、不正な`state`・`nonce`・PKCE・署名、再送、失効、ログアウト、OP停止時の挙動をそのアプリから検証してください。正式認定とローカルのテスト結果は[対応状況](security.md)に分けて掲載しています。

設定と検証の詳細は[RP連携ガイド](https://github.com/masanork/mikaki/blob/main/docs/rp-integration.md)と[クライアント登録手順](https://github.com/masanork/mikaki/blob/main/docs/rp-client-operations.md)を参照してください。

[セキュリティと対応状況](security.md)も確認してください。
