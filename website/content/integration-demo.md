---
type: article
profile: sorane-okf/0.1
title: 'mikaki公開IdPに接続するログインデモ'
description: '公開IdPと専用RPを使い、パスキーログイン、アプリのセッション再確認、ログアウトを試す手順と検証範囲を説明します。'
lang: ja
translation_key: integration-demo
updated: 2026-10-04
---

[公開接続デモを開く](https://demo.mikaki.org/)。実際の`auth.mikaki.org`へ接続する、ログイン状態の確認専用アプリです。mikakiに登録済みのパスキーを使います。招待がない方は、先に[招待・連携相談](contact.md)を確認してください。

このデモは`openid`だけを要求し、名前・メール・Vaultの内容を要求しません。問い合わせ本文やメモを投稿する機能もありません。ログインに必要なアプリ別の識別子とセッション情報は、IdPとは別の専用DBに一時保存します。

## 公開IdPでサインインする

1. `https://demo.mikaki.org/`で「mikakiでサインイン」を選びます。
2. 認証画面のdomainが`auth.mikaki.org`で、接続先が`demo.mikaki.org`であることを確認します。
3. 初回の接続確認と、登録済みパスキーの本人確認を行います。
4. デモに戻り、「ログイン状態」に「サインイン済み」と表示されることを確認します。

登録とサインインは別の操作です。新しいアカウントを作る場合は、招待を受け取って[はじめ方](getting-started.md)の登録を先に済ませてください。端末・ブラウザーの対応は[パスキーの説明](passkeys.md)にあります。

## セッションを再確認する

「セッションを再確認」は、RPのサーバーから公開IdPへ現在のセッション状態を問い合わせます。確認が成功するとログイン状態へ戻ります。失効や期限切れが確認された場合は、RPのセッションも削除し、古い確認期限が残っていてもログイン済みとは扱いません。

通常の表示は、前回の確認が有効な期間内で使います。通信障害で再確認できない場合は期限を延ばしません。認証画面へ戻るだけ、または画面上にボタンがあるだけでは、コード交換やセッション確認が成功した証拠にはなりません。

このデモのRPセッションは最長1時間です。IdP側の期限が先に来る場合は、その期限を超えません。日時はUTCで表示します。

## このデモからログアウトする

「このデモからログアウト」を選ぶと、RPのセッションとCookieを削除します。ログイン状態の画面が開けなくなることを確認してください。mikakiのSSOは終了しないため、同じブラウザーでの次のログインが短い操作で済む場合があります。

「mikaki側のログアウト確認画面」は、IdPのSSOを終了する別の操作です。確認画面の対象を読み、他の接続アプリへの影響も含めて判断してください。

## 実装と確認範囲

デモは既存の[Helpdesk RP Worker](https://github.com/masanork/mikaki/tree/main/crates/helpdesk-rp)のログイン専用モードです。独立したHTTPS origin、D1、RP専用ES256鍵、完全一致するcallbackを登録しています。秘密鍵はWorkerのsecretに保管します。

| 確認項目 | 範囲 |
| --- | --- |
| PKCE・state・nonce・ID Token署名・issuer / audience | 既存RP実装とローカル統合テスト |
| パスキーログイン、再確認、RPログアウト、失効後の拒否 | [デモのブラウザーテスト](https://github.com/masanork/mikaki/blob/main/local/test/demo-rp.test.ts)。使い捨てローカルOPと仮想認証器 |
| 公開IdPへのクライアント登録 | デモ専用の公開鍵・callback・Back-Channel受信先を管理者手順で登録 |
| 公開環境でのパスキー往復と実通知の到達 | 本人操作を伴う試験。登録やローカルの成功だけでは確認済みとしない |

デモはOpenID Foundationの認定や第三者監査を示すものではありません。[conformance testの結果一覧](conformance.md)と区別してください。自分のRPを作るときは、[運用手順と構成](https://github.com/masanork/mikaki/blob/main/docs/public-rp-demo.md)と[ローカル実行例](integration-example.md)を参照できます。

## 次に読む

- [アプリ連携ガイド](integration.md)：管理者登録と接続試験の流れ。
- [API reference](api.md)：公開OPの要求・応答とセッション確認の契約。
