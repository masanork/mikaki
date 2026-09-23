# Vault UserInfo recipientの鍵管理

2026-09-23時点。これはUserInfo専用system recipientを実装するための鍵管理契約であり、実際の秘密鍵の作成・Secrets Storeへの登録・共有操作の有効化はまだ行っていない。

## 鍵を扱う主体

- **本人ブラウザー**は、有効なUserInfo recipient公開鍵へ属性のdata keyだけを包む。鍵directoryは同じoriginのWorkerから取得し、`key_id`を公開鍵のSHA-256 digest（base64url、paddingなし）として照合する。以前見た鍵の世代より古い応答を受理しない。本人用PRF envelopeとVault本文は従来どおり維持する。
- **OP Worker**はD1の公開鍵directoryとGrantを扱うが、ML-KEM秘密鍵bindingを持たない。OIDC署名鍵も流用しない。
- **UserInfo claim Worker**だけがML-KEM秘密鍵を読む。専用のCloudflare Secrets Store bindingに64-byte ML-KEM seedを保管し、D1/R2、ログ、応答には出さない。呼び出し元を内部service bindingで認証し、固定のclaim取得操作以外を提供しない。Workerが動く間は秘密鍵にアクセスできるため、このWorkerのコード・配備権限を鍵管理境界として扱う。

Secrets Store bindingは[Cloudflare公式手順](https://developers.cloudflare.com/secrets-store/integrations/workers/)の`secrets_store_secrets`と非同期`get()`を使う。binding追加には配備が必要である。一方、公開鍵のactive/disabled切替はD1で行い、緊急停止に再配備を要求しない。Secretの値をD1の設定として扱わない。

## D1の鍵directory

[`0007_vault_recipient_keys.sql`](../crates/worker/migrations/0007_vault_recipient_keys.sql)は、`key_id`、service `userinfo`、algorithm `ML-KEM-768`、1184-byte公開鍵、秘密鍵binding参照、世代、状態、単調増加revisionと時刻を保持する。秘密鍵カラムはない。初期状態は空で、migration適用だけでは共有は始まらない。

状態は`staged → active → decrypt_only → disabled`、または`staged/active → disabled`。同時にactiveにできるUserInfo鍵は一つ。鍵本体・binding参照・世代は登録後に変更できず、行も削除できない。`disabled`は再有効化しない。これらはD1のCHECK・unique index・triggerと[SQL試験](../scripts/test_vault_recipient_keys_sql.py)で拘束する。

公開鍵・秘密鍵の対応は、登録前にseedから公開鍵を再生成して確認する。公開鍵の`key_id` digest、秘密鍵bindingのseedから再生成した公開鍵、D1の公開鍵をclaim Worker起動時と利用時に照合する。D1の状態だけで秘密鍵の存在や対応を推定しない。鍵をactiveにする管理操作は、bindingの存在と照合が成功するまで実行しない。

隔離されたNative CLIの[`recipient_key`](../design/probes/pqc/src/bin/recipient_key.rs)は、OSのCSPRNGで64-byte seedを作り、秘密seedを所有者のみ読めるファイルへ、公開鍵・digest・binding参照を別JSONへ書く。秘密seedの標準出力やリポジトリ内への書込みを拒否する。`verify`はseedから公開鍵を再生成して照合する。これは鍵素材を準備する道具であり、Secrets Storeへの登録やD1のactive切替は実行しない。

```sh
cargo run --locked --manifest-path design/probes/pqc/Cargo.toml --bin recipient_key -- generate /private/tmp/vault-userinfo-seed.txt /private/tmp/vault-userinfo-public.json VAULT_USERINFO_MLKEM_A 1
cargo run --locked --manifest-path design/probes/pqc/Cargo.toml --bin recipient_key -- verify /private/tmp/vault-userinfo-seed.txt /private/tmp/vault-userinfo-public.json
```

実運用では専用の保護された一時領域を使い、秘密seedをSecrets Storeへ登録した後に一時ファイルを確実に廃棄する。CLIの公開JSONはDB登録時に`key_id`と公開鍵を検証する入力にする。

## 切替と失効

1. 独立した新しいseedを生成し、保護された手段でSecrets Storeに登録する。公開鍵は`staged`としてD1へ登録する。秘密seedの複製は必要な復旧手順に限って保管し、ログやCI artifactに残さない。
2. claim Workerを新旧両方の秘密鍵bindingが利用できる状態に配備し、公開鍵との対応を検証する。D1の一回のbatchで旧`active`を`decrypt_only`、新`staged`を`active`へ変更する。batchに失敗した場合は旧鍵をactiveのままにする。
3. 旧鍵のenvelopeは有効なGrantがある属性に限って再包みし、属性revisionとrecipient key IDを照合する。残数が0になり、復旧保持期間を過ぎてから旧鍵を`disabled`にし、bindingとseedを廃棄する。offline端末が旧公開鍵で作ったenvelopeは失効した世代として拒否する。
4. 漏えい時はD1で該当鍵を直ちに`disabled`にし、読取・unwrap・claim発行を失敗として閉じる。その鍵にだけ依存する共有属性は、本人が再度解錠して新鍵に包むまでUserInfoへ出さない。既に渡した平文は回収できない。

directory API、binding検証、管理操作、recipient envelope、Grantは後続の実装対象。公開鍵を返すAPIはこれらの検証が整うまで公開しない。使用するHPKE envelopeのsuite/versionは[現行草案](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05)との相互運用試験後に固定する。
