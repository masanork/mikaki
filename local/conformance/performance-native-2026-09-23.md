# ローカル常駐nativeのConformance性能

このページは1.9.1 x86_64での記録。更新後の[1.9.2 ARM64追試](performance-arm64-2026-09-23.md)では同じファイルSQLite条件で155/155、5.31秒／3.09秒を確認した。

2026-09-23、Apple M3／macOS、Rust 1.98.1、release（opt-level=s、LTO）。FIDO Conformance Tools 1.9.1、全Server Tests、OPTIONAL off、AUTOSCROLL off、http://localhost:8080。ビルド・別の負荷試験は測定中に実行しない。

## 結果

| 常駐nativeの保存先 | Suite | 全体 | handler合計 | Rust検証合計 | DB操作合計 | handler p95 / p99 |
|---|---:|---:|---:|---:|---:|---:|
| ファイルSQLite、WAL/FULL | 155成功・0失敗 | 40.68秒 | 112.784ms | 45.685ms | 40.269ms | 1.661 / 2.815ms |
| メモリーSQLite | 155成功・0失敗 | 40.78秒 | 96.651ms | 47.441ms | 21.341ms | 1.309 / 2.416ms |

各320リクエスト。respond呼出しの合計は15.464ms／14.861msで、上表のhandlerとは別計上。両実行ともoptionsは165成功、登録は24成功・80拒否、認証は8成功・43拒否。Suiteの異常系を含むため、HTTP 400は試験失敗数ではない。ファイルDBは停止後にも24 users／24 credentialsを読み出せ、integrity_checkはokだった。

今回確認した改善は常駐nativeからの直接呼出しであり、コアの暗号処理を省略・変更したものではない。旧プロセス起動方式のhandler合計544.764msに対し、SQLiteの同期保存を加えた今回でも112.784msだった。ただしHTTP実装や入力も異なる単発試行の比較なので、差をそのまま特定変更の効果量とはしない。

ファイルからメモリーへの変更でDB操作は約19ms減ったが、Suite全体は短くならなかった。約15秒という他実装の歴史的な総時間との差を、この検証・DB操作だけでは説明できない。受付前・クライアント側・Suite内部処理等を含む未計測時間が大きく、どれが主因かは今回断定しない。DBを迂回する最適化は導入しない。

[機械可読の集計とSHA-256](performance-native-2026-09-23.json)にroute別分位点と再現対象を保存した。両サーバーは計測後に停止した。

検証: workspaceの22テストと2 compile-fail doc tests、fmt、clippy全targets、設計チェック、変更JSのPrettier、cargo auditを通過。新しいnative依存の追加後もworkerのWasm向けcargo checkは通過した。

## 変更した計測経路

新しいconformance_server exampleは、常駐Rust HTTPサーバーからauth/WebAuthnコアを直接呼ぶ。旧Nodeアダプターにあった検証ごとのプロセス起動とWasm補助処理を含まない。製品の暗号コアは変更していない。

[HTTP入口](https://docs.rs/tiny_http/0.12.0/tiny_http/)と[SQLite](https://docs.rs/rusqlite/0.40.2/rusqlite/)はnative専用のdev-dependenciesとし、製品／Wasmの通常依存には追加しない。userとcredentialをSQLiteから読み、登録はトランザクション、counter更新は同期SQLで応答前にcommitする。書込み失敗時は成功を返さない。登録の重複時はuserの追加もrollbackする。ファイルDBは毎回新規作成、WALとsynchronous=FULL。メモリーDBでも同じSQLと検証を実行する。

ceremonyは上限・期限付きのメモリー取引で、検証前に一回限りで消費する。リクエスト処理は直列化し、counterの読込みからcommitまで別のリクエストを割り込ませない。これはローカル試験アダプターであり、製品のセッション発行、OIDC、高並行負荷、再起動復元のベンチマークではない。

## 比較の限界

monban／iwatoとの比較軸はローカルnativeとする。WasmをNodeで実行した過去の試験もCloudflare上の計測ではなかったが、nativeとは分けて扱う。

iwatoの現行Conformance実装はメモリーのcredential参照と非同期DB書込みを使い、run-conformance.shの既定DBは:memory:。monbanのConformance経路にはStore経由の読込み・登録・counter更新のawaitがある。今回両リポジトリは変更・再計測していない。歴史的な約15秒というSuite総時間と直接順位付けしない。mikakiはDB書込み完了を待つ条件を明示して測る。

msはHTTPリクエストを受け取ってから応答構築までのwall timeで、受付待ちとログ出力を含まない。response_msはrespond呼出しの経過時間であり、クライアント側の受信完了時間ではない。verify_msは実際のRust検証呼出し、db_msはSQLite操作とcommitの経過時間、metadata_msは候補選択。すべて成功・失敗の両方を含み、Suiteの多くは異常系なので通常ログインの分位点には使わない。

## 再現

リポジトリルートでmetadata準備を済ませてから実行する。

```sh
cargo test --locked --workspace
cargo build --release --locked -p mikaki-browser-wasm --example conformance_server
FIDO_TIMING=1 target/release/examples/conformance_server > target/performance-native-file.log 2>&1
# サーバー停止後、新しいプロセスで再実行
FIDO_DB=memory FIDO_TIMING=1 target/release/examples/conformance_server > target/performance-native-memory.log 2>&1
node local/conformance/summarize-timing.mjs target/performance-native-file.log target/performance-native-memory.log
```

MDSの署名・CRL・期限は起動時にnativeコアで確認し、完了後にlistenする。各Suite実行前にRESETし、毎回AUTOSCROLLをoffへ戻す。試験APIと状態は製品入口へ組み込まない。
