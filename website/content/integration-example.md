---
type: article
profile: sorane-okf/0.1
title: 'mikakiと連携するローカルRPの実行例'
description: '既存のHelpdesk RPをローカルで起動し、パスキー登録、OIDCログイン、PKCE、private_key_jwt、セッション失効とログアウトを確認します。'
lang: ja
translation_key: integration-example
updated: 2026-10-03
---

実行できる接続例として、リポジトリの[Helpdesk RP](https://github.com/masanork/mikaki/tree/main/crates/helpdesk-rp)を使います。Rust/WasmとWorkerでできた小さなアプリに、ログインと保護されたページがあります。**この例は使い捨てのローカルOPへ接続します。公開IdPへの登録済み接続や本番向けサポートサービスではありません。**

## 準備して起動する

NodeとRustはリポジトリの[.node-version](https://github.com/masanork/mikaki/blob/main/.node-version)と[rust-toolchain.toml](https://github.com/masanork/mikaki/blob/main/rust-toolchain.toml)に合わせます。RustのWasm targetとwasm-packが必要です。依存ツールの準備は[開発環境の説明](https://github.com/masanork/mikaki/blob/main/docs/getting-started.md)を参照してください。

```sh
git clone https://github.com/masanork/mikaki.git
cd mikaki
npm ci
npm run build
npm run dev:helpdesk
```

`npm run build`はポリシー、ブラウザーWasm、Helpdesk Wasm、UIを生成します。RPのWasmだけをビルドしても、OP画面のassetsが揃いません。

ブラウザーで`http://127.0.0.1:18878`を開きます。OPは`http://localhost:18877`です。ポートを他のプロセスが使っていないことを確認し、`localhost`と`127.0.0.1`を勝手に置換しないでください。異なるoriginとして扱う構成です。起動時に表示される招待コードは15分・一回限りです。

## 最初のログインを確認する

1. RPのログインボタンを押し、ローカルOPへ移動することを確認します。
2. 招待コードを使い、discoverable passkeyに対応するブラウザーで登録します。
3. RPへ戻り、保護されたticketsページが表示されることを確認します。
4. 自分用のテストticketを作り、返信・クローズを試します。本文はRPのD1に平文保存されるため、合成データを使います。
5. RPのログアウトを試します。アプリのCookieとセッションを削除する操作で、OPのSSO終了とは別です。

Ctrl+Cで終了すると、このrunnerの鍵とデータベースを破棄します。公開サービスのアカウントや保存済みVaultを使う手順ではありません。

## 実装を読む場所

| ソース | 確認できる処理 |
| --- | --- |
| [RP Worker](https://github.com/masanork/mikaki/blob/main/crates/helpdesk-rp/worker.ts) | browserに結び付けたstate/nonce、S256 PKCE、ES256 client assertion、ID Token検証、Cookieとlease、Back-Channel受信 |
| [Rustアプリ](https://github.com/masanork/mikaki/tree/main/crates/helpdesk-rp/src) | 公開記事とticket検証 |
| [ローカルrunner](https://github.com/masanork/mikaki/blob/main/local/runtime.ts) | 独立したOP/RP鍵、使い捨てD1、クライアントと招待の初期化 |
| [ブラウザーテスト](https://github.com/masanork/mikaki/blob/main/local/test/helpdesk.test.ts) | 仮想パスキーでの登録・ログイン、他人のticket拒否、権限、失効、署名付きlogout通知 |

小さな接続例でもstateやnonceの検証、署名検証、セッション期限の処理を削りません。アプリ固有のticket機能は自分の保護されたページに置き換えられます。

## 自動で再現する

ビルドを終え、開発runnerを停止してから次を実行します。PlaywrightのChromiumが未導入なら先に取得します。

```sh
npx playwright install chromium
node --test local/test/helpdesk.test.ts
```

テストはChromium仮想認証器を使うため、実端末の生体認証操作は不要です。登録・ログイン、ticketのアクセス制御、セッション更新・失効、署名不正の拒否と重複logout通知を検証します。この成功は実端末、本番OP、本番RPの相互接続試験の代わりではありません。

## 公開IdPへ接続するときの差分

ローカルOPはTypeScriptの試験用アダプターで、公開環境のRust OPとは別です。特にローカルrunnerは`LOCAL_ONLY=true`でformの`/session/check`を選びますが、**公開IdPはJSON**です。ローカル設定を本番へ流用しないでください。

本番接続には独自のHTTPS originとD1、登録client ID、完全一致するcallback、RP専用P-256公開JWKの管理者登録が必要です。秘密鍵はRP Workerの`RP_PRIVATE_JWK` secretに保管し、OPの鍵やDBを共有しません。RPの2つのmigration、Back-Channel受信先、運用ポリシー、障害時の挙動も確認します。[RPのREADME](https://github.com/masanork/mikaki/blob/main/crates/helpdesk-rp/README.md)に準備条件があります。

この例の本番公開には、スタッフ権限管理、濫用対策、ticketの保持・削除・バックアップ、監視、実端末確認が別途必要です。

## 次に読む

- [API reference](api.md)：公開OPに送る要求と応答の契約を確認します。
- [アプリ連携ガイド](integration.md)：管理者登録から公開環境での検証へ進みます。
