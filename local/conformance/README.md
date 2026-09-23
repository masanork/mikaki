# FIDO2 Server Conformance接続

隔離した試験用アダプター。native性能計測には常駐Rustサーバー、WasmにはNodeのHTTP入口を使い、同じRust auth/WebAuthnコアを呼ぶ。製品用の認証入口には組み込まない。localhostのIPv6 loopbackだけで待ち受ける。

```sh
npm run build:wasm
cargo build --release --locked -p mikaki-browser-wasm --example conformance
python3 local/conformance/extract-metadata.py
node local/conformance/prepare.mjs
node local/conformance/server.mjs
# native側で再測定する場合（先に前のサーバーを停止する）
cargo build --release --locked -p mikaki-browser-wasm --example conformance_server
FIDO_TIMING=1 target/release/examples/conformance_server > target/performance-native-file.log 2>&1
# メモリーSQLiteとの比較では FIDO_DB=memory を追加する
```

MacのFIDO Conformance Tools v1.9.2でFIDO2 Serverを開き、URLを`http://localhost:8080`とする。Server Testsを全選択する。追加のOPTIONAL algorithms/attestationsは全て未選択、AUTOSCROLLはoff。自動的な結果提出はしない。

試験APIの4経路はiwatoの接続を参考にした。attestation・extensions・UV・resident keyの要求をoptionsへ反映する。UVとアカウント・allow-listをサーバー側の取引に保存し、結果の検証時に同じポリシーを使用する。対応していないattestationの結果は拒否する。製品の既定値は変更しない。この試験入口は製品へ組み込まない。

常駐nativeは入力のstrict JSON検証、metadata選択、署名検証までRustで直接実行する。credential・userはSQLiteから読み、登録・counter更新を同期commitしてから応答する。既定のFIDO_DB=fileはtarget/fido-native-<random>.sqliteへ新規保存し、WAL/synchronous=FULLを使う。FIDO_DB=memoryも同じSQLを実行するが、ディスク耐久性は持たない。ファイルは測定後もtargetに残る。ceremonyは期限付きの一回限りのメモリー取引で、処理は直列化する。製品のセッション発行・OIDCは含まない。

Wasmは既存workerバンドルをNodeで実行し、状態もメモリーのみ。Cloudflare/workerd/D1での試験とは区別する。旧FIDO_TARGET=nativeのNode入口は検証ごとにRustプロセスを起動する診断用として残すが、nativeサーバーの性能比較には使わない。

成功数だけを適合率としない。未対応方式を拒否しただけで異常系が成功する場合や、登録前処理で失敗して認証試験へ到達しない場合がある。noneを強制してSuiteの生成入力を変えてしまった試行も採用しない。試験条件・未到達・未対応を結果とともに記録する。

[2026-09-22の測定結果と制約](results-2026-09-22.md)を参照。

現在の試験プロファイルはES256・Ed25519・RS256・RS1を広告する。鍵保存はCOSEへ変更済み。旧結果のrequired固定プロファイルとは区別する。

最新の[1.9.2 ARM64での測定](performance-arm64-2026-09-23.md)は、ファイルSQLite付きnativeで155/155、初回5.31秒・再実行3.09秒。1.9.1 x86_64での過去の記録とは区別する。

## Metadataと試験結果

2026-09-22に必須155件を両ターゲットで全通過した。任意14件は未選択で、正式認証の提出は別手続き。

extract-metadata.pyはインストール済みSuiteの公開metadataをtarget/fido-metadataへ抽出する。prepare.mjsはlocalhostのRP originを公式MDS試験サービスへ登録し、BLOB/CRLをtarget/fido-mdsへ保存する。FIDO_ASAR/FIDO_PORTでインストール先・ポートを指定できる。いずれもignoredの試験用データで、Suiteのコードや秘密鍵は抽出しない。

HTTP取得はHTTPSの公式2ホストに限定し、リダイレクト先にも同じ制限・サイズ上限・タイムアウトを適用する。失敗BLOBのルートやmetadataを信頼情報に取り込まない。サーバー起動時に、現在時刻と各ターゲットのRust検証器でBLOB/CRLを再検証する。検証できたmetadataだけを、AAGUID/certificate key identifierで選んでceremonyへ渡す。試験rootのSPKIはprepare.mjsだけにあり、同梱SuiteのmdsRoot.jsの公開鍵に対応する。製品のtrust storeには追加しない。

長期間保存したデータの期限切れや公式試験データの更新時はprepare.mjsからやり直す。MDSの期限検証を外して再実行しない。GUI Suiteとこのテスト用ネットワーク取得は通常CIへ含めず、独立した固定fixtureによる同一コアの回帰試験をCIで実行する。

## 性能を分けて測る

native試験はreleaseバイナリーを使う。FIDO_TIMING=1でmetadata検索・Rust検証・SQLite操作・HTTP handlerの所要時間を記録する。msは処理開始から応答構築まで、response_msはrespond呼出しの経過時間で、受付待ちやクライアント受信完了を含まない。失敗時の検証・DB時間も計上する。sequenceとreceived_msで受付順と単調時刻も記録する。識別子や応答本体は記録しない。summarize-timing.mjsで集計する。

常駐サーバーの回帰試験はcargo test --locked --workspaceに含まれ、counter更新、再利用・期限切れ・challenge不一致の拒否、DB失敗時の拒否と登録のrollbackを確認する。[常駐nativeの計測結果](performance-native-2026-09-23.md)を参照。

コア単体と旧プロセス境界の独立ベンチマークも残す。

```sh
cargo build --locked --workspace --examples
cargo build --release --locked --workspace --examples
node local/conformance/benchmark.mjs
```

全ビルド終了後に単独で測定する。既存の公開fixtureで毎回検証を実行し、結果も照合する。出力はartifacts/webauthn-performance.json。nativeコア、Wasm/JSON境界、nativeのプロセス起動込み、metadata検索を区別する。DB・HTTP・正式Suiteの所要時間はこのマイクロベンチマークに含まない。[性能調査](performance-2026-09-23.md)を参照。

## OIDC Basic OP のローカル試験

Colima の OIDF Conformance Suite 5.2.4 を `https://localhost:8443` で起動してから、別のターミナルで次を実行する。`local/generated/` の証明書、試験用passkey、client secret、詳細ログはgitに含めない。

```sh
npm run build:policy
worker-build --release crates/worker
openssl req -x509 -nodes -newkey rsa:2048 -days 1 -keyout local/generated/oidf-local.key -out local/generated/oidf-local.crt -subj '/CN=host.docker.internal'
node local/conformance/oidf-local-worker.mjs
```

fixtureの起動時に隔離D1を作り、passkey認証と一回限りのログイン取引を事前確認する。Chromiumの仮想認証器を使う試験driverは別のターミナルで実行する。fixtureを再起動するとテストcredentialとcounterが新しくなる。

```sh
node local/conformance/run-passkey-oidf.mjs all 1
node local/conformance/run-passkey-oidf.mjs oidcc-discovery-endpoint-verification 1 oidcc-config-certification-test-plan
```

2番目の引数`1`はfixtureの事前確認後の署名counter。複数のモジュールは同じ仮想認証器を使い、counterを引き継ぐ。`REVIEW`に必要な画面画像はdriverがローカルsuiteへ提出する。結果の集計と詳細ログは`local/generated/oidf-passkey-*.json`に保存する。公開issuerでの正式認証とは区別する。
