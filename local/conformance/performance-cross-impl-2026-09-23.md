# iwato / mikaki FIDO Suite比較

2026-09-23、同じMac上のFIDO Conformance Tools 1.9.2 GUIで、iwatoとmikakiのnative常駐サーバーを連続して測定した。両方とも`http://localhost:8080`、Server Tests全選択、OPTIONAL off、AUTOSCROLL off、メモリーDB。Suiteプロセスは同じものを使い、各サーバー起動後に初期状態から1回実行した。

| 実装 | 必須テスト（各回） | 1回目 | 2回目 | 2回中央値 |
| --- | ---: | ---: | ---: | ---: |
| iwato | 155成功・0失敗 | 5.85秒 | 4.92秒 | 5.385秒 |
| mikaki | 155成功・0失敗 | 3.25秒 | 3.32秒 | 3.285秒 |

2回ともSuite全体時間の中央値はmikakiが短かった。測定は同じSuite版・選択項目・ホストで行ったが、これだけで検証器自体が速いとは結論しない。Suite時間にはテストデータ生成、HTTP往復、Suite内部処理、OSスケジューリングが含まれる。実装ごとにDB/ceremony設計やmetadata初期化も異なり、iwatoの2回の差からもSuite所要時間に揺れがあることが分かる。

mikaki側はreleaseのnative `conformance_server`、`FIDO_DB=memory`を使用し、Rust検証とSQLite memory操作を省略していない。各Suiteは320 HTTPリクエストを生成した。1回目の保存ログにはSuite前の到達確認HEADリクエストが1件余分に含まれる。2回目のログは320件で、HTTP timing集計ではSuite外リクエストを含めない。各Suite後にサーバーを停止した。iwato側は`bash scripts/run-conformance.sh`で起動し、同スクリプトの`:memory:`設定を使用した。両方のサーバーを終了後、試験UIの結果を確認した。

mikakiの2回目はhandler処理合計83.288ms、Rust検証呼出し合計47.842ms、SQLite操作合計14.656ms、handler p95 1.364msだった。これらは320件の正常・異常リクエストを含むサーバー内部の単一実行値で、Suite全体時間とは測定境界が異なる。iwatoで同じ内部時間を取得できていないため、ここから両者のhandler/検証速度を比較しない。

## 同一fixtureによる検証コア比較

Suite比較とは別に、mikakiのオフラインfixture exporterが出力する同一の`none ES256`登録応答と`assertion ES256`認証応答を、両ライブラリーの検証APIへ直接渡した。両方で成功し、登録から得たCOSE公開鍵もmikakiのfixture credentialとバイト単位で一致することを確認した。iwato側のregistration/authentication challenge、config、登録済みcredentialは測定外で事前構築した。各呼び出しの所有レスポンスバッファ複製は両方に含め、HTTP、JSON wire decode、DB、challenge発行・消費は含めない。

同一ホスト・同一Rust release設定（`opt-level=3`, LTO, 1 codegen unit）で、各方式を10回warm-up後、5,000回×9サンプルの測定を独立に2回行った。下表は18サンプルの中央値と全サンプルの最小〜最大。iwatoとmikakiの両crateを単一の一時Cargo harnessから同時にビルドした。これは両プロジェクトの本番release設定を再現するものではない。

| 検証方式 | iwato | mikaki | mikaki / iwato |
| --- | ---: | ---: | ---: |
| none ES256 登録 | 1.366 µs (1.229–2.553) | 2.440 µs (2.342–2.637) | 1.79× |
| ES256 assertion | 158.333 µs (156.030–164.184) | 96.853 µs (96.359–100.028) | 0.61× |

このfixture・境界ではnone登録がmikakiで遅く、署名付きassertion検証はmikakiが約39%短い。特にnone登録は短時間処理のためOSスケジューリング等の外れ値の影響を受けやすい。結果を他のattestation形式、MDS検証、Wasm、DB/HTTP込みの製品経路へ一般化しない。Suite比較は製品経路における別の参考値であり、iwatoのSuite server内時間は未取得。process peak memoryの限定測定は後述する。

## Nativeの一時heap使用量

同じfixture・release build・検証API境界で、global allocatorを計測用に差し替えて、1呼出し中の要求済みheap bytesのhigh-water deltaを採った。測定前にfixture/context/credentialを構築し、10 warm-up後に5,000回×9 sampleと500回×9 sampleで繰り返した。2回の結果はバイト単位で一致した。

| 検証方式 | iwato | mikaki |
| --- | ---: | ---: |
| none ES256 登録 | 1,159 bytes | 2,094 bytes |
| ES256 assertion | 1,119 bytes | 1,366 bytes |

ここでの「peak heap」は呼出し中に生存していたRust allocatorへの要求量で、応答cloneと検証処理の一時割当を含む。fixture/context/credentialなど事前保持データ、stack、allocator内部の実消費、実行ファイルのresident pagesは含まない。allocator instrumentationは性能時間へ影響するため時間比較に使っていない。この限定測定からprocess peak RSSやWorker heap上限への適合を推定しない。process RSSは後述のSuite実行全体で測ったが、検証handler単位のheapは未測定。

これはローカルの適合Suiteと限定した同一fixtureコア比較の記録であり、正式なFIDO認証や一般的な速度順位ではない。製品workerは責務・依存が異なるため、全機能を揃えた製品単位の順位付けは行わない。比較可能なfixture/coreとSuiteの測定、サイズ・メモリー範囲の記録を完了し、残る非同等性は明示した。WG-08の範囲と完了判断は[fit-gap一覧](../../docs/webauthn-fit-gap-todo.md)を参照。

## Native server process peak memory

上記Suite条件で、各native serverを`/usr/bin/time -l`配下で2回起動し、起動後にFIDO Conformance Tools 1.9.2の必須155件を実行した。各実行で両実装とも155成功・0失敗。iwatoは既存release binary、`:memory:`、Suite付属MDS metadata、登録済みMDS3 endpointを使い、mikakiはrelease `conformance_server`、`FIDO_DB=memory`を使った。

| 実装 | `maximum resident set size` median (range) | macOS `peak memory footprint` median (range) |
| --- | ---: | ---: |
| iwato | 45,867,008 bytes (43.73 MiB; 45,268,992–46,465,024) | 32,236,156 bytes (30.75 MiB; 32,146,032–32,326,280) |
| mikaki | 18,251,776 bytes (17.41 MiB; 18,219,008–18,284,544) | 16,146,876 bytes (15.40 MiB; 16,105,904–16,187,848) |

この2回の中央値ではmikakiの報告RSSはiwatoの約40%、peak footprintは約50%だった。これはプロセス起動から終了までのOS high-water値で、live Rust heapと同義ではなく、ライブラリーmapping等も含む。`peak memory footprint`はmacOSが別に報告する値なのでRSSと混同しない。Suite時間は先の測定でiwato 4.92–5.85秒、mikaki 3.25–3.32秒だったが、プロセスの計測区間は起動から停止までであり、特にiwatoは今回の停止までの経過時間がmikakiより大幅に長かった。各サーバーのMDS初期化も一致していないため、メモリ差は同じSuiteを通した参考値であり、起動条件と計測時間を揃えた確定比較ではない。2つのserve processは測定後に停止した。

## Wasm assertionと成果物サイズ

同じES256 assertion fixtureをwasm32-unknown-unknownへコンパイルした最小wasm-bindgen harnessでも比較した。Rust 1.98.1、`opt-level=z`, LTO、1 codegen unit、strip symbols、panic abortを両方に適用し、wasm-optは使わず、Node 26.9.0で実行した。各実装を10回warm-up後、1,000回×9サンプルを3回測定し、3回分のrun中央値の中央値を取った。

| 検証方式 | iwato | mikaki | mikaki / iwato |
| --- | ---: | ---: | ---: |
| ES256 assertion | 805.156 µs (run中央値の範囲 799.679–836.706) | 411.036 µs (410.004–418.760) | 0.51× |

測定境界はwasm-bindgen export call、検証コア、所有応答bufferの複製を含み、fixtureのJSON parse/setupは除く。assertion用の登録済みcredentialは事前にfixtureから構築した。各wasm-bindgen shimのraw `.wasm` はiwato 363,714 bytes、mikaki 373,840 bytes。これはverification shimとwasm-bindgen glueが到達可能な部分だけを含む実験用artifactで、製品workerやWebAuthn crate単体のサイズではない。サイズは近いが、同じnative/Wasm assertion入力ではmikakiの時間が短かった。サンプル間に外れ値があるので、厳密な速度倍率として一般化しない。

同じrelease設定でbuildした製品workerのraw Wasmはiwato 2,303,854 bytes、mikaki 738,618 bytesだった。iwato WorkerにはD1とPostgres store adapterがあり、製品機能・依存グラフが一致しないため、この差をWebAuthn実装のサイズ差とは解釈しない。wasm32向けnormal dependency graphはユニークpackage名でiwato 76、mikaki 63だったが、proc-macro等を含む解決グラフの数であり、最終binaryへのlink量ではない。

iwatoの`verify_registration`は成功結果の`created_at`を埋める際に`SystemTime::now()`を呼ぶ。今回のwasm32-unknown-unknown/Node実行ではこの呼出しが「time not implemented on this platform」でtrapした。したがってiwatoのnone-registration Wasm比較は実行できず、上表は両方で動作したassertionだけを比較した。この結果はNode runtimeでの観測で、Cloudflare実行環境の動作を直接試験したものではない。なおmikakiのWasm none-registration core-only shimは約7.5 µsだったが、対応するiwato値がないため順位比較に使わない。

上記製品worker・shimサイズ、Wasm assertion、native呼出し単位のpeak live heap、native suite server process peak RSSを追記した。process memoryは各2回、Suite成功は全回再確認した。稼働時間とMDS初期化の差、製品workerの機能差を限界として明記し、これ以上の比較をWG-08完了条件にしない。追加調査は具体的な遅延・回帰・hot spotが現れた場合に再開する。
