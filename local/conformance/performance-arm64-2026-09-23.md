# FIDO Conformance Tools 1.9.2 ARM64での追試

2026-09-23、同じApple M3／macOS 27.0、同じmikaki常駐nativeサーバーとファイルSQLiteで再測定。新しいSuiteのRendererがARM64であることをmacOS sampleのCode Typeで確認した。アーキテクチャ確認は試験開始前に終了し、本測定中にはプロファイラー・開発者ツール・ビルドを動かしていない。

## 結果

| 条件 | Suite結果 | 全体 | handler合計 | Rust検証合計 | SQLite操作合計 |
|---|---:|---:|---:|---:|---:|
| 1.9.1 x86_64/Rosetta（旧記録） | 155成功・0失敗 | 40.68秒 | 112.784ms | 45.685ms | 40.269ms |
| 1.9.2 ARM64、起動後初回 | 155成功・0失敗 | **5.31秒** | 40.388ms | 13.940ms | 16.597ms |
| 1.9.2 ARM64、同じSuiteで再実行 | 155成功・0失敗 | **3.09秒** | 42.374ms | 14.773ms | 17.855ms |

各回ともサーバーは再起動し、新しいファイルSQLiteを作った。2回目はSuiteプロセスのみ継続している。暗号検証、期限、一回限りのceremony、credential読込み、登録・counter更新と同期commitを維持した。製品のコアは変更しておらず、今回のサーバー変更はログへのsequence／received_ms追加のみ。

各回320 HTTPリクエスト、options 165成功、登録24成功・80拒否、認証8成功・43拒否。正常系・異常系とも従来と同じ件数。2回目のサーバー停止後にもSQLiteから24 users／24 credentialsを読み出せ、integrity_checkはokだった。handler p95は0.583／0.586ms、p99は0.853／0.981ms。異常系も含むSuite全体の分位点であり、通常ログインの指標とは区別する。

更新でSuiteの版と実行アーキテクチャが同時に変わったため、この差をRosetta単独の効果とは断定しない。生成される試験データ、CPUの実行状態、外部MDS通信等も完全固定ではない。少なくとも今回、検証やDBを省略することなく約40秒から3〜5秒の全項目通過を確認できた。他実装の過去の約15秒と速度順位を付けるものではない。

## 通信と未計測時間の切り分け

新しいreceived_msはサーバー起動後の単調時刻。最初のhandler開始から最後のrespond完了までの区間は初回5305.234ms、2回目3085.945msで、Suite表示の全体時間と整合する。前のrespond完了から次のhandler開始までの区間合計は5260.283／3039.343ms、最大の単一区間は2873.175／863.296msだった。この区間にはSuite内部処理、外部通信、ローカル通信、サーバーの受付待ち・ログ出力等が含まれ、純粋なネットワーク遅延とは呼ばない。

独立したNode HTTPクライアントでも計測した。transport-benchmark.mjsは自前の合成ES256鍵で登録し、challenge取得・署名・検証・counter更新を繰り返す。各条件は5回warmup後100回、直列実行。クライアントの署名生成はHTTP時間の外で、タイマーはリクエスト開始から応答本文の受信完了まで。全応答の成功を確認し、DBや検証を迂回しない。

| ローカルHTTP接続 | options p95 | 認証result p95 | 認証result p99 |
|---|---:|---:|---:|
| keep-alive | 0.139ms | 0.349ms | 0.377ms |
| 毎回接続 | 0.444ms | 0.611ms | 0.703ms |

この独立計測はSuite更新前、同じnativeサーバーのファイルSQLite上で行った。Electron固有の通信経路を完全に再現するものではないが、通常のloopback HTTP往復では秒単位の遅延は再現しなかった。

### チューニングの優先度

2回目のSuiteでは最初のhandlerから最後の応答まで3,085.945msに対し、handlerの合計は42.374ms（約1.4%）、Rust検証は14.773ms（約0.5%）、SQLite操作は17.855ms（約0.6%）だった。測定対象・集計の重なりに注意は必要だが、handler外の待ち時間が支配的であることは明確。従ってSuite全体の秒数を下げる目的で暗号検証やDB耐久性を省略するのは測定結果に沿わない。現時点では通常経路のp95/p99と成功・拒否動作を守り、暗号・DBの最適化は特定のhandler hot spotや利用者向け遅延を再現してから検討する。

旧RendererへのOSサンプリングを伴う診断実行は155成功・0失敗、64.77秒だった。Rosetta下のスタックは未解決シンボルも多く、特定JavaScript関数への正確な帰属はできなかった。この実行はプロファイラーの影響を含む可能性があるため速度比較から除外した。

## 再現と記録

[機械可読記録](performance-arm64-2026-09-23.json)に両実行の集計、HTTPの成功／拒否数、リクエスト間隔、独立HTTP計測、ソースとバイナリーのSHA-256を保存した。旧記録はそのまま残す。

条件はFIDO2 Server Tests全選択、OPTIONAL off、AUTOSCROLL off、http://localhost:8080、Rust 1.98.1 release opt-level=s／LTO、SQLite WAL／synchronous=FULL。1.9.2同梱の公開metadataを再抽出し、公式MDS BLOB／CRLも再取得して、native検証完了後にlistenした。

```sh
python3.14 local/conformance/extract-metadata.py
node local/conformance/prepare.mjs
cargo build --release --locked -p mikaki-browser-wasm --example conformance_server
FIDO_TIMING=1 target/release/examples/conformance_server > target/performance-native-profile.log 2>&1
# Suiteを実行して停止し、各回のログを別名で保存する
node local/conformance/summarize-timing.mjs target/performance-native-1.9.2-run1.log target/performance-native-1.9.2-run2.log
# 独立HTTP計測はSuite実行と重ねず、サーバー起動中に実行する
node local/conformance/transport-benchmark.mjs
```

fmt、全targetsのclippy、変更JSのPrettierを通過し、独立HTTP計測も全応答成功を確認した。両Suite実行後に試験サーバーを停止した。現在の開発優先度は暗号やDBの省略による秒数短縮ではなく、コンパクトさ・検証の完全性・通常の製品経路の品質維持とする。
