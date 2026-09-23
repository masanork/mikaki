# WebAuthn性能調査 — 2026-09-23

性能改善の余地はあるが、現在のSuite所要時間の支配要因はサーバー内の検証CPUではない。まず試験アダプターの重複解析を除去し、nativeの比較条件をreleaseへ揃えた。暗号検証、期限・失効検証、取引消費、credential更新を省略する変更は行っていない。

## 比較条件の確認

以前のmikaki native測定はdebugバイナリーを検証ごとに子プロセス起動していた。製品のnativeサーバー性能を表す構成ではない。試験アダプターは元からメモリー保存であり、今回DBを外す変更はない。Wasmはrelease/サイズ最適化の既存バンドルを使用する。

iwatoの`docs/performance/fido.md`には14.82秒の記録に加え、その後の同じ155件成功で33.02秒・40.03秒の記録がある。後者では320リクエストのサーバー内時間の合計はミリ秒切捨て後23 ms（切捨て誤差を足しても343 ms未満）。過去の15秒と現在の48秒を、そのまま検証器の速度比にできない。今回monban/iwatoは再実行していない。

monbanの現在の`src/handlers/conformance-fido.ts`はceremonyをメモリーに置く一方、ユーザー・credentialの検索、保存、counter更新ではStoreをawaitしている。iwatoのfast pathはメモリー優先と非同期DB書込を含む。両者も保存契約が同一とは限らない。

## 独立fixtureのマイクロベンチマーク

Apple M3、Node 26.9.0、Rust 1.98.1。同一の公開fixtureで毎回検証し、成功・拒否の結果も照合した。5回warmupの後、7バッチの平均時間の中央値。native debugは20回/バッチ、releaseとWasmは100回/バッチ。全ビルド完了後に逐次実行した。

| 操作 | native debug | native release | Wasm/JSON境界 |
| --- | ---: | ---: | ---: |
| none / ES256登録 | 28.94 µs | 2.65 µs | 8.86 µs |
| ES256認証 | 2,327.29 µs | 139.24 µs | 416.43 µs |
| packed証明書チェーン | 11,247.35 µs | 780.16 µs | 2,740.33 µs |
| U2F | 8,806.81 µs | 633.44 µs | 2,278.55 µs |
| TPM RSA | 9,568.12 µs | 707.26 µs | 2,528.59 µs |

nativeコアの測定には所有権付き応答のコピーを含むが、JSON、HTTP、DBは含まない。Wasm側は既存WorkerのJSON解析・ceremony検証・結果serializationとJSからの呼出しを含む。同一境界での言語間速度比較ではない。none登録にはattestation署名がなく、署名付き方式との単純な比較にも使わない。

releaseも既存の`opt-level="s"`、LTOを使用する。速度優先`opt-level=3`とのサイズ・速度比較は今回行っていない。独立fixtureの証明書・鍵構成は公式Suiteとは異なるため、これらの時間をSuite件数に掛けて総時間を推定しない。

2026-09-23 09:00 JSTに、今回のMDS結果型変更後のWasmと同じbenchmarkを再実行した。release中央値はnone登録2.63 µs、ES256認証138.65 µs、packed 781.03 µs、U2F 635.65 µs、TPM RSA 708.00 µs。Wasm/JSON境界は順に9.43、417.09、2,721.66、2,299.89、2,539.87 µsだった。WasmにはJSON入出力が含まれるのでnativeとの数値を同じ処理境界の速度比較として扱わない。metadata entryはfixture 25件で、metadata検索4方式も結果一致を確認した。生データは[今回の機械可読記録](performance-core-2026-09-23.json)。前回は125件で測っており、metadata件数が違うため検索時間を前回値と直接比較しない。

更新時点の成果物サイズはWebAuthnを含むWorker Wasm全体が644,011 bytes、native conformance serverが2,604,224 bytes。後者はHTTP/SQLiteの試験用example、前者はWebAuthn単体ではなくWorker/OIDCを含むため、どちらもコア単体サイズとは呼ばない。`mikaki-webauthn`の直接依存はbase64, ciborium, der, ed25519-dalek, p256, p384, rsa, serde, serde_json, sha1, sha2, x509-cert。依存tree全体の実行時寄与・ピークメモリーはこの測定で切り分けていない。

### プロセス起動の影響

releaseコアのES256認証は139.24 µsだが、現在のnative試験用JSON/stdin/stdout・子プロセス起動込みでは1,791.37 µs。none登録は2.65 µsから1,647.61 µsになる。毎回起動する輸送層が比較を大きく歪める。これはコアをHTTPサーバーへ直接組み込めば自然になくなる費用であり、試験だけの常駐RPCを増やす必要性は低い。

## 実施した改善

metadata検索のfilter内で、同じattestationのCBOR/証明書を125回解析していた。検索前に1回だけ解析してから同じ条件でfilterするよう変更した。未検証ヒントを検証済みと扱う変更ではなく、コア側のAAGUID・certificate key identifierと信頼情報の照合は維持する。

| 検索入力 | 変更前 | 変更後 |
| --- | ---: | ---: |
| packed | 592.79 µs | 6.43 µs |
| U2F | 1,035.01 µs | 9.20 µs |
| TPM | 1,122.27 µs | 10.19 µs |
| none | 170.18 µs | 2.46 µs |

同じ125 metadata entriesと入力で比較し、選択結果の一致も確認した。これに加えnative試験バイナリーの参照先をreleaseへ変更し、`FIDO_TIMING=1`でmetadata検索・検証呼出し・HTTP handlerの時間を記録できるようにした。ログに識別子・応答本文は含めない。

## 修正後の公式Suiteと内訳

| 対象 | 成功 / 失敗 | Suite全体 | HTTP handler合計（320件） | 検証呼出し合計 | metadata検索合計 |
| --- | --- | ---: | ---: | ---: | ---: |
| Wasm | 155 / 0 | 46.66秒 | 157.452 ms | 68.457 ms | 4.489 ms |
| native release（毎回プロセス起動） | 155 / 0 | 48.20秒 | 544.764 ms | 448.250 ms | 9.674 ms |

HTTP handlerのp95はWasm 1.834 ms、native 5.003 ms。認証結果routeだけのp95はそれぞれ1.003 ms、5.192 ms。正常・異常系を合わせたSuiteの分布であり、製品の正常ログインp95とは異なる。nativeの検証呼出しにはプロセス起動・JSON/stdin/stdoutを含む。

HTTP handler時間はリクエスト処理開始からレスポンスをキューへ渡すまでで、送信完了、ソケット待機、GUI処理は含めない。MDS検証は起動時に完了しており、この表の対象外。残りの時間はSuite側の入力生成・描画・外部通信、HTTP輸送、スケジューリング等を分解していないため、個別の原因は断定しない。

以前の最終値（native debug 47.49秒、Wasm 48.35秒）と比較して、Suite全体の短縮は確認できていない。今回確認したのは局所的な重複処理の削減と、全155件通過の維持。15秒を狙ってDBや検証を省く根拠は得られていない。

[機械可読の測定記録とSHA-256](performance-2026-09-23.json)には全バッチのmin/median/max、route別p50/p95/max、ツール版と再現対象を保存した。両試験終了後にサーバーを停止した。

## DBを含む性能評価について

Conformanceで暗号・プロトコルの適合性を確認し、コア単体の測定でCPU費用を分離することには意味がある。一方、DBを省いたConformanceの秒数を製品のレイテンシとして宣伝する意味は薄い。

当初は次の評価をD1としていたが、monban／iwatoとの比較にはローカル常駐nativeを先に測る。[常駐nativeの追試](performance-native-2026-09-23.md)を参照。D1は別の製品評価とし、challenge消費、credential読込、署名検証、counter更新、セッション発行・commitまでを完了した時点のp50/p95/p99とCPU時間を測る。cold/warmと並行リクエスト数を分け、失敗・競合時の整合性も維持する。今回DB付き経路の性能分解は行っておらず、DBがボトルネックだと断定するものではない。

証明書の解析済み公開鍵の再利用やビルド最適化には追加の余地がある。ただしキャッシュはmetadata revision・失効・期限更新との整合性が必要で、現状の通常認証がサブミリ秒であることを踏まえ、実負荷とサイズ増加を測ってから導入する。

## 再現

```sh
cargo build --locked --workspace --examples
cargo build --release --locked --workspace --examples
node local/conformance/benchmark.mjs
FIDO_TIMING=1 node local/conformance/server.mjs > target/performance-wasm.log 2>&1
# 前のサーバーを停止し、別の全Suite実行で測る
FIDO_TARGET=native FIDO_TIMING=1 node local/conformance/server.mjs > target/performance-native.log 2>&1
node local/conformance/summarize-timing.mjs target/performance-wasm.log target/performance-native.log
```

GUI Suiteは1.9.1、全Server Tests、追加OPTIONAL off、AUTOSCROLL off、localhost:8080。各サーバーを再起動して状態を初期化し、MDS検証を完了してから開始する。コンパイル・別の負荷試験を並行実行しない。通常CIでは速度閾値を設けず、手動測定として比較条件を保存する。
