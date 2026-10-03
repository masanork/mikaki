---
type: article
profile: sorane-okf/0.1
title: 'mikakiの運用・サービス情報 — 利用条件とサポート'
description: '公開サイトとIdPの役割、招待・クライアント登録、実験段階の提供、ライセンス、障害時の挙動、問い合わせと脆弱性報告を説明します。'
lang: ja
translation_key: operations
updated: 2026-10-03
---

mikakiを利用・導入するときに確認するサービス情報です。**実験的な開発プロジェクトで、サポート対象の正式リリースはありません。** このページは現在公開している条件を説明するもので、SLAや有償サポート契約を設けるものではありません。

## 公開サイトと接続先

| ホスト | 役割 |
| --- | --- |
| [mikaki.org](https://mikaki.org) | 製品説明、使い方、仕様・試験結果 |
| [auth.mikaki.org](https://auth.mikaki.org/.well-known/openid-configuration) | 公開IdPの認証、OIDC、Web版の操作 |
| [app.mikaki.org](https://app.mikaki.org) | ネイティブアプリの案内とcallback関連の導線 |

ローカル開発・Conformance用環境は別のissuer、鍵、DBを使います。そこでの成功を本番の全機能の提供や配布版の保証に読み替えないでください。日英の説明ページは同じ仕様を案内しますが、判断時は最新Discoveryと対象の実装記録も確認します。

## 登録と利用の条件

ユーザー登録は招待コードが必要です。アプリの接続は管理者がクライアントを登録します。一般公開の動的クライアント登録や、セルフサービスでの本番SaaS導入を提供するものではありません。ユーザーのパスキー登録と、開発者のclient登録は別の手順です。

[セキュリティ方針](https://github.com/masanork/mikaki/blob/main/SECURITY.md)はサポート対象リリースがなく、ローカル実装は実アカウント・実データを保護する用途を想定していないとしています。導入評価にはテストアカウントと合成データを使い、公開サービスを含め、失うと困る情報を預ける運用は避けてください。

## 可用性と障害時の扱い

可用性SLA、性能・容量の保証、サポート応答期限、セキュリティ報奨金はありません。HTTP疎通やCI成功は、利用者のログイン、通知の到達、Vaultの復旧をすべて保証する指標ではありません。

連携アプリは、OPが停止したときに新しいセッションを作らず、既存セッションも最後に確認したleaseの期限を越えて延長しません。UserInfoの503は無効tokenや同意撤回と区別します。クライアントごとに、停止、失効、再送、Back-Channel受信障害を検証する必要があります。

セッション期限などは運用設定で変わります。[API reference](api.md)の応答値を使い、初期設定の秒数を本番の固定保証と扱わないでください。

## データと復旧について

パスキー認証、アプリのセッション、Vaultの復号鍵は別です。Vaultでは暗号文に加えて種類や更新時刻などの運用メタデータをサーバーが保持します。開示先やダウンロードした平文から情報を回収することはできません。

すべての解錠手段を失った場合の復旧、全端末互換性、保持期間や削除完了期限を包括的に保証するサービス条件は整備されていません。実データの導入前には、対象構成の保持・削除・バックアップ・復旧手順と責任分担を運用者が確定する必要があります。[Vaultの制約](vault.md)と[復旧・リリース手順](https://github.com/masanork/mikaki/blob/main/docs/release-and-recovery.md)を確認してください。

## バージョンと変更の確認

実装、変更履歴、開発状況は[GitHubリポジトリ](https://github.com/masanork/mikaki)と[CI](https://github.com/masanork/mikaki/actions)で確認できます。mainの実装と、公開IdPで有効な版・設定は常に同じとは限りません。新機能の実装、ローカル試験、デプロイ、運用上の提供開始はそれぞれ確認します。

[試験結果一覧](conformance.md)の実行日・ツール版・対象構成は、現在の全デプロイを認定するものではありません。変更後は必要な接続試験をそのアプリで再実行します。

## ライセンスとセルフホスト

ソフトウェアは[MIT](https://github.com/masanork/mikaki/blob/main/LICENSE-MIT)または[Apache-2.0](https://github.com/masanork/mikaki/blob/main/LICENSE-APACHE)を選べるOSSです。ソフトウェアの利用許諾と、公開サービスの可用性・サポート契約は別です。

現在のWorker構成はCloudflare Workers、D1、Vault用のR2などを使います。自分で運用する場合は独立したissuer、秘密鍵、DB、client登録、監視と復旧体制が必要です。[開発環境](https://github.com/masanork/mikaki/blob/main/docs/getting-started.md)と[運用設計](https://github.com/masanork/mikaki/blob/main/docs/oidc-operations.md)を参照してください。ローカル例の起動は、本番の運用準備完了を意味しません。

## 問い合わせと脆弱性報告

一般的な不具合や改善提案は[GitHub Issues](https://github.com/masanork/mikaki/issues)で、対象commit・環境・合成データによる再現手順を添えてください。アカウント、秘密鍵、招待コード、OAuth callback URL、codeやtoken、Vault内容を公開Issueへ貼らないでください。

脆弱性はGitHubのprivate vulnerability reportingが有効なら、その機能から非公開で報告します。利用できない場合は、**非公開の報告経路を求める依頼だけ**をIssueに投稿し、脆弱性の詳細や攻撃手順は掲載しません。手順は[SECURITY.md](https://github.com/masanork/mikaki/blob/main/SECURITY.md)に従います。

## 次に読む

- [仕様・対応標準](specifications.md)：接続に必要な機能とクライアント条件を確認します。
- [セキュリティと対応状況](security.md)：データと試験の制約を踏まえて導入を評価します。
