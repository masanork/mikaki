# ES256・JOSE・ローカルD1の技術検証

本番用コードではない。ES256の秘密鍵は公開RFCテストベクトル、account/client/tokenは合成値だけを使う。RustのJWTパーサーやOIDC Provider、管理CLI、ログイン画面は実装していない。

## 実行環境と固定依存

2026-09-22にmacOS arm64、Rust 1.98.1、Node 26.9.0、wasm-pack 0.15.0で実行した。

- Rust p256 0.14.0、wasm-bindgen 0.2.128。推移依存はes256/Cargo.lockへ固定。
- jose 6.2.12、Wrangler 4.136.2。推移依存はpackage-lock.jsonへ固定。
- このWranglerに含まれるworkerdは1.20260921.1、Miniflareは5.20260921.0-alpha。ローカル模擬環境の版として記録し、本番D1と同一と主張しない。

## 再実行

リポジトリルートから以下を実行する。NodeのテストrunnerとRust標準テストを使用する。

```sh
npm ci --prefix design/probes
cargo test --locked --manifest-path design/probes/es256/Cargo.toml
cargo build --locked --manifest-path design/probes/es256/Cargo.toml --bin fixture
wasm-pack build design/probes/es256 --target nodejs --release --out-dir pkg -- --locked
npm run test:crypto --prefix design/probes
npm run test:d1 --prefix design/probes
cargo clippy --locked --manifest-path design/probes/es256/Cargo.toml --all-targets -- -D warnings
cargo audit --file design/probes/es256/Cargo.lock
```

wasm-packは対応するwasm-bindgenツールを必要に応じて取得する。D1試験はWranglerのgetPlatformProxyを使い、remoteBindings=false・persist=falseで毎回独立したローカルDBを作る。localhostのプロセス間通信とWranglerのログ書込みが必要。CloudflareへのDB作成・配備・既存データ操作は行わない。

SQL試験は既存の[設計SQL](../sql/oidc-critical-schema.sql)を読み込む。named parameterをD1.bind用に変換する小さなhelperは、この固定SQL模型専用であり汎用SQLパーサーではない。WorkerのHTTP入口は常に404で、試験用署名やDB操作を公開APIにしない。

## 確認結果

| 検証 | 結果 | 確認したもの |
| --- | --- | --- |
| Rust Native | 3/3成功 | RFC 6979既知解、改変拒否、JOSE raw署名とDERの区別 |
| Wasm＋Node jose/WebCrypto | 6/6成功 | Wasmの実行、Nativeとの決定的署名一致、相互署名検証、改変・alg・期限・iss/aud拒否 |
| ローカルworkerd/D1 | 6/6成功 | 未交換sidの無効性、並行code交換の一成功、0件更新拒否、全SQL位置のrollback、changes()ガード、失効拒否 |
| cargo audit | 指摘なし | 固定された54 Rust依存を当日のRustSec DBで確認 |
| npm install時の監査 | 指摘なし | 37 packageを確認。将来の監査を代替しない |

最適化済みWasmは82,464 byte、gzipは33,952 byte（Python gzip、mtime=0）。JS glue、JOSEライブラリ、本番のWebAuthn/OIDC処理を含まない試作用モジュールのサイズであり、製品のサイズ予算ではない。

## 解釈と残る確認

ES256の秘密鍵演算をp256で行い、その署名をJOSEが利用する境界は、この試験条件では成立した。Rustのraw署名をJOSE compactへ接続する処理は試験fixtureに限り、製品JOSE層のライブラリ選定・claim検証を完了したとは扱わない。Node WebCryptoでの成功はWorkers WebCrypto・ブラウザでの実行結果ではない。WasmもNodeで実行したものであり、Rust Workerへの組込みは次の確認対象。

D1 batchによるロールバックとchanges()はローカル互換環境で成立した。withSession("first-primary")のAPI呼出しは確認したが、ローカルには本番のread replica配置がないため、遠隔D1の最新失効読取り・レプリカ整合性は未検証。

鍵生成・乱数源・実際の秘密保管、RS256互換経路、暗号処理のタイミング特性、負荷性能、実ブラウザのPasskey、OP conformanceは未検証。公開前には別途確認する。この試作から本番へ公開RFC秘密鍵やfixture用の署名関数をコピーしてはならない。

## 次の実装

一つの隔離RPを使い、[ADR 0005](../../docs/adr/0005-invitation-bootstrap-and-recovery.md)に従う登録からログアウトまでを縦に実装する。最初にauthとOIDCの登録/認証確定境界、本番schema、Workerへの署名アダプターを接続する。招待・bootstrapの競合試験は今回のcode交換模型とは別に追加する。

## 参照

- [Wrangler API](https://developers.cloudflare.com/workers/wrangler/api/)：getPlatformProxyのローカル実行境界。
- [p256](https://github.com/RustCrypto/elliptic-curves/tree/master/p256)：ES256プリミティブ。
- [RFC 6979 A.2.5](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5)：公開のP-256テストベクトル。
- [jose](https://github.com/panva/jose)：独立したJWT/JWS相互運用先。
