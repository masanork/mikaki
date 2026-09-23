# ES256・JOSE・ローカルD1の技術検証

本番用コードではない。ES256の秘密鍵は公開RFCテストベクトル、account/client/tokenは合成値だけを使う。RustのJWTパーサーやOIDC Provider、管理CLI、ログイン画面は実装していない。

## workers-rs adapter probe

[`workers-rs/`](workers-rs/) は独立したRust Worker proof of conceptで、`worker` 0.8.6を使う。本番用ではない。Wranglerのローカルworkerd上でRust async fetch、D1 batch rollback、`FirstPrimary` read、並行exchangeの一回性、Rust OIDC coreの認可code準備にWorkers WebCrypto CSPRNGを接続する経路、非同期ES256署名を確認する。追加のRS256ケースでは合成2048-bit RSA鍵をRustで検査し、非抽出JWKとしてWorkers WebCryptoへimportしてID Tokenに署名する。生成JWSを[`jose-custom`](jose-custom/)のRust/Wasm verifierで検証し、署名改ざんを拒否する。鍵はNode test processで実行時生成し、ローカルWorkerへだけ渡す。remote D1やCloudflareアカウントには接続しない。

`worker-build` 0.8.6、`wasm32-unknown-unknown` target、`design/probes` のnpm依存を用意したうえで、リポジトリルートから実行する。

```sh
cargo build --locked --manifest-path design/probes/workers-rs/Cargo.toml --target wasm32-unknown-unknown
worker-build --release design/probes/workers-rs
worker-build --release crates/worker
wasm-pack build design/probes/jose-custom --target nodejs --release --out-dir pkg -- --locked
node design/probes/workers-rs/test.mjs
cargo audit --file design/probes/workers-rs/Cargo.lock
```

2026-09-23時点で上記のD1・ES256/RS256署名・CSPRNG/code準備試験が成功し、Cargo auditは93 crateに脆弱性を報告しなかった。最適化済みprobe `index_bg.wasm`の過去サイズは321,262 bytes（gzip 104,541 bytes）。RS256追加後のサイズは未測定。これはprobe単体の参考値で、Worker全体の上限・cold startを測ったものではない。read replicaを持たないローカル環境の`FirstPrimary`はAPI経路の確認であり、本番のreplica整合性を検証しない。残りのゲート項目と結果は[ADR 0009](../../docs/adr/0009-rust-oidc-and-worker-stack.md)に記録する。

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
npm run test:crypto:workers --prefix design/probes
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

### Rust JOSE 依存スパイク（初期評価）

隔離crate [`jose`](jose/) で jsonwebtoken 11.1.0 の API と target build を確認する。Wasmでは `getrandom 0.2` の `js` feature をtarget限定で明示する必要があった。独立した `Cargo.lock` は87 crateを固定し、2026-09-23時点の `cargo audit` は指摘なし。Nodeのjose/WebCryptoがテストごとに合成鍵をメモリー上で作り、同じcompact JWSをRust Native・Wasmで検証する。秘密鍵ファイルは作らない。

```sh
cargo build --locked --manifest-path design/probes/jose/Cargo.toml --bin fixture
wasm-pack build design/probes/jose --target nodejs --release --out-dir pkg -- --locked
cargo build --locked --manifest-path design/probes/jose-custom/Cargo.toml --bin fixture
wasm-pack build design/probes/jose-custom --target nodejs --release --out-dir pkg -- --locked
npm run test:crypto --prefix design/probes
cargo build --locked --release --manifest-path design/probes/jose/Cargo.toml --bin fixture
npm run bench:crypto --prefix design/probes
cargo audit --file design/probes/jose/Cargo.lock
cargo audit --file design/probes/jose-custom/Cargo.lock
```

Native/Wasm共通で18項目が成功した。ES256・RS256の独立署名検証、非同期WebCrypto署名のJWS構造体経由での受渡し、別alg・署名改変・誤鍵拒否、鍵差替え後の旧token拒否、issuer/audience/expiry確認、必須claim欠落と重複`sub`拒否、壊れたJWK/tokenを含む。claim確認はprobe用型と固定条件であり、sakimoriのOIDC処理ではない。jsonwebtokenの時刻確認はプロセス時計に依存するため、注入時計は未確認。Rust内でのprivate-key署名は引き続き実装していない。

Wasmのrelease生成物は637,956 byte（gzip 253,443 byte）。2026-09-23のローカル10,000回測定では、組込みbackendのNative/WasmはES256が約214/690 µs、RS256が約109/461 µsだった。probe APIは各呼出しでJWKをJSON parseするため、値は鍵キャッシュなしの上限寄りであり、製品性能の予測には使わない。`rust_crypto` featureはRSA・P-384・Ed25519等をまとめて有効にし、RSA crateも依存グラフへ含む。`cargo audit` に指摘はないが、監査だけでRSA秘密鍵署名を本番採用せず、既知のRSA timing勧告と公開鍵検証/秘密鍵操作の境界を別途評価する。

別の[`jose-custom`](jose-custom/) crateは組込みbackend featureを無効にし、ES256・RS256の検証providerだけを実装した。Native/Wasmとも独立jose署名を受理し、改変・alg・失効鍵・issuer/audience/expiry不一致・重複claimを拒否した。RS256 JWKは`DecodingKey`内のn/eがcustom providerへ公開されないため、probeでn/eからPKCS#1 DERを作る前処理を置いた。Wasmは307,963 byte（gzip 120,871 byte）で、組込みRustCrypto版よりraw約52%小さい。10,000回のNative/Wasm検証はES256が約216/681 µs、RS256が約228/417 µs。RSA JWKからDERへの変換も毎回含むため、鍵をcacheする実装の予測には使わない。`cargo audit`は両lockfileとも指摘なし。

非同期署名境界も追加確認した。Node WebCryptoの`subtle.sign`でJWS signing inputへ署名し、結果を公開`jsonwebtoken::jws::Jws`構造体へ格納して、独自providerの検証をNative/Wasmで通した。さらにWrangler 4.136.2が含むworkerd 1.20260921.1上で一時ES256鍵を生成し、Workerの非同期`crypto.subtle.sign`が出したcompact JWSをNode上のRust/Wasm検証器で受理した。payload改変はいずれも拒否した。したがって同期`JwtSigner`を使わず、アプリ側でprotected header/payloadのbase64url化とJWS組立てを行えば非同期WebCrypto署名と検証APIをつなげられる。これはローカルworkerdと一時鍵の結果で、Workers KMS binding連携・永続鍵形式・運用時エラー処理は未検証。試験Workerは`async-signer-worker.mjs`、実行テストは`jose-workers.mjs`。

## 次の実装

一つの隔離RPを使い、[ADR 0005](../../docs/adr/0005-invitation-bootstrap-and-recovery.md)に従う登録からログアウトまでを縦に実装する。最初にauthとOIDCの登録/認証確定境界、本番schema、Workerへの署名アダプターを接続する。招待・bootstrapの競合試験は今回のcode交換模型とは別に追加する。

## 参照

- [Wrangler API](https://developers.cloudflare.com/workers/wrangler/api/)：getPlatformProxyのローカル実行境界。
- [p256](https://github.com/RustCrypto/elliptic-curves/tree/master/p256)：ES256プリミティブ。
- [RFC 6979 A.2.5](https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5)：公開のP-256テストベクトル。
- [jose](https://github.com/panva/jose)：独立したJWT/JWS相互運用先。
