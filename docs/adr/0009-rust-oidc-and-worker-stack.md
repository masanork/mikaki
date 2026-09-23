# ADR 0009: OIDC状態機械をRustに置き、TypeScript 7をブラウザ境界に使う

2026-09-23 / 採用方針。workers-rsのローカル実証状況は「実証ゲート」節を参照。

## 背景

認証・認可の正しさは、署名検証だけでなく「どの状態から何へ遷移できるか」「一度だけ実行できるか」「失敗時に何が確定したか」で決まる。これらはRustの型と明示的な状態遷移で一元管理する。一方、ブラウザUI、WebAuthn API、IndexedDB、Cloudflare bindingの接続は、プラットフォームのAPIに近い薄い境界として扱う。

現在のローカル縦切りでは、[`local/op.mjs`](../../local/op.mjs)が707行、`local/rp.mjs`が313行で、OIDC取引とD1操作をJavaScriptが実行する。`sakimori-oidc`は認可要求とPKCEのcoreである。従来の`sakimori-worker`はWebAuthn/PKCEのJSON/Wasm境界だったため、これを`sakimori-browser-wasm`へ改名し、Cloudflareのfetch handler/binding adapter用に`sakimori-worker`を分離した。[ローカル実装文書](../../local/README.md)はJS harnessを製品実装と区別している。

## 決定

1. **Rustをプロトコル状態遷移の正本にする。** OIDC、client assertion、一回性、認証・認可証拠、session、logout/outboxのユースケースと検証済み型を`sakimori-oidc` / `sakimori-auth`に置く。生のHTTP入力、JWT文字列、UUID文字列から、検証済み状態へ移る箇所を明示する。遷移は網羅的なenum/Resultと私有フィールド付き型で表し、HTTPやDB行をそのままドメイン型にDeserializeしない。
2. **Cloudflareの本番Worker adapterもRustを第一候補にする。** `worker` crate（workers-rs）を使い、Worker入口、設定・時計・乱数、非同期署名、D1、Service Bindingを`sakimori-worker`に閉じる。`sakimori-browser-wasm`はブラウザ/ローカルharness向けに限る。D1のconditional batchが最終的な一回性・並行性を確定する不変条件は維持し、Rust coreの型だけでDB原子性が保証されるとは扱わない。生成されたWasm/JS glueは境界の実装詳細とし、独自Wasm ABIを業務APIにしない。
3. **TypeScript 7をブラウザUIとブラウザ専用処理の標準にする。** Svelte UI、WebAuthn/IndexedDB呼出し、画面状態、ローカルdev harnessでRustが不自然な箇所に使う。UIは認証可否を決定せず、サーバー応答を表示・送信する。フロントの暗号処理は規格APIを呼び、独自プロトコルや権限判定を実装しない。
4. **ローカルJavaScript縦切りは検証fixtureとして保つ。** Rust実装への期待動作を示すための回帰・E2E harnessとして使える間は維持するが、新しい製品機能の正本にはしない。Rustへの移行中は同じ契約ケースを両方へ実行し、二つの実装が並走する期間を限定する。
5. **初期crate構成を小さく保つ。** `webauthn`、`auth`、`oidc`、`worker`をP0の境界とし、JWT、D1 repository、policy loaderのためだけのcrateや汎用plugin frameworkは追加しない。

## workers-rsの実証ゲート

Rust Workerへの全面移行前に、隔離したprobeで固定Cloudflare runtimeに対して以下を確認する。外部Cloudflareアカウント、remote D1、production secretを使わない。

- Rust async fetch handlerが型付きの入力制限、cookie/response headers、エラー写像を行える。
- D1 `batch`が全段階rollback、一回だけの並行code交換、失効競合を満たす。`with_session("first-primary")`の振舞いもlocal workerdで確認する。
- Workers WebCrypto署名と公開鍵検証、D1、scheduled/`waitUntil`がRust adapterの非同期境界から利用できる。
- Native/Wasm試験を共通化でき、Wasm size、cold start、依存監査が許容範囲にある。

**2026-09-23のローカル結果:** `worker` 0.8.6、Wrangler 4.136.2 / workerd 1.20260921.1で、async Rust fetch handler、D1 batch rollback、`FirstPrimary` read、並行する一回限りのexchange（勝者一つ）、Rust OIDC code preparationへのWorkers WebCrypto CSPRNG接続、Rustからの非同期WebCrypto ES256署名と既存Rust/Wasm verifierによる検証を確認した。製品adapter crateも作成し、health routeと404 fallbackをlocal workerdで起動した。隔離probe lockfileの93 crateは`cargo audit`で指摘なし、workspace lockfileの180 crateも2026-09-23時点で指摘なし。最適化probe Wasmは321,262 bytes（gzip 104,541 bytes）。実行手順は[probe README](../../design/probes/README.md)に記録した。これはローカルruntimeの部分実証であり、ゲート全体の完了ではない。

**2026-09-23 RS256 follow-up:** 同じlocal workerd上で、Node test processが生成した一時2048-bit RSA JWKをWorkerへ渡し、Rustによる秘密・公開JWKの検査と対応確認、WebCryptoへの非抽出秘密鍵import、RS256 ID Token signing inputの作成、RSASSA-PKCS1-v1_5/SHA-256署名を行った。返されたtokenを独立したRust/Wasm verifierが受理し、署名改ざんを拒否した。公開JWKのWebCrypto `key_ops: []` も有効なexport形態だったため、空または`verify`の用途を受け付けた上で、公開JWKSから`key_ops`は省略する。これは秘密鍵の永続secret設定やD1対応鍵行、実token exchangeを含まないローカル暗号境界の確認である。probe実行手順は[probe README](../../design/probes/README.md)を参照。

**未確認:** 本番Cloudflare上のD1 failure/session semantics、実プロジェクトのSQLとの一致、scheduled/`waitUntil`、失効とlogoutの競合、Native/Wasm共通試験、最適化済みWasmのサイズ予算とcold start、実際の設定・cookie/HTTP境界。Worker全体のcold start・配布サイズ予算とは照合していない。残りの項目を実装着手前に評価し、ゲートを満たさない場合は**TypeScript 7 Workerを薄いplatform adapterとして残し、状態遷移はRust coreが決める**方式へ切り替える。TypeScript Workerに業務状態機械を戻さない。

## TypeScript 7の適用範囲と静的検査

- TypeScript 7.0.2のnative type checkerをUIの検査に使う。TypeScriptは実行時検証・認可・Rust coreの代わりではない。
- 現在の`svelte-check`はTypeScript 7の検査に6系APIも必要とするため、`typescript@6`と`@typescript/native`の併用を維持し、6系は開発ツール限定とする。上流が不要になった版を確認してから取り除く。
- UIでは`strict`、`noUncheckedIndexedAccess`、`exactOptionalPropertyTypes`を有効化済み。Cloudflare binding型は`wrangler types`で生成し、DB row型も明示する。
- Rustは`unsafe_code = "forbid"`、Clippy warning deny、固定lockfile、依存監査、Native/Wasm試験、fuzzを保つ。domain遷移・重複JSON拒否・エラー時のrollbackは型検査だけに頼らず独立ケースで検証する。
- `local/*.mjs`を製品相当へ拡張する場合は、Rust移行までの間もTS7の`checkJs`対象へ加える。独立したJavaScript実装を恒久運用するならTypeScript化と二重ロジック解消を先に行う。

## 代替案とトレードオフ

| 案 | 評価 |
| --- | --- |
| 全体をTypeScript 7へ統一 | D1/Workersの型付きbindingを使いやすいが、OIDCの状態遷移・検証済み証拠を言語境界の外で管理することになる。ユーザーの優先順位に合わないため不採用。 |
| Rust core + TypeScript Workerを初期の既定にする | platform APIが使いやすい一方、業務操作の往復・DTO・非同期ABIを分け、D1確定をJSに残すと責務が曖昧になる。workers-rsがゲートを満たさない場合の明示的fallbackとする。 |
| OIDC状態機械とWorker adapterをRust、UIをTypeScript 7にする | 型と状態遷移の所有者が一つになり、platform bindingはcomposition rootへ閉じる。SDK/API、Wasmサイズ、デバッグ性がコストであるため、縦切りprobeを先行させる。推奨構成。 |

Rustは正しさを証明しないし、SQLの原子性・WebAuthn/JWTの規格適合を自動保証しない。型で減らせる不正状態、テストで確認する実行時契約、実環境で測る配備特性を分ける。

## 参照

- [Cloudflare Workers: Rust support](https://developers.cloudflare.com/workers/languages/rust/)・[supported crates](https://developers.cloudflare.com/workers/languages/rust/crates/)：workers-rs、非同期呼出し、Wasmの制約。
- [worker::d1::D1Database](https://docs.rs/worker/latest/worker/d1/struct.D1Database.html)：Rust bindingの`batch`・`with_session` API。
- [TypeScript 7.0 announcement](https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/)：native compilerのstable release。
- [svelte-check TypeScript 7 support](https://github.com/sveltejs/language-tools/tree/master/packages/svelte-check#typescript-7-supports)：TS6/TS7併用の現行手順。
