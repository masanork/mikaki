# ローカルの認証縦切り実装

2026-09-22。招待登録 → discoverable Passkey → OIDC Code/S256 PKCE → RPセッション → ログアウトを、二つのローカルWorkerとD1で動かす。公開用の配置ではない。

## 起動

Nodeは[.node-version](../.node-version)、Rustは[rust-toolchain.toml](../rust-toolchain.toml)を参照。Python 3.14とwasm-pack 0.15.0を使用する。

```sh
npm ci
npm run build
npm run dev
```

`http://127.0.0.1:18878`を開き、端末に表示されたbootstrap招待を登録画面へ入力する。OPは`http://localhost:18877`。cookieのhostを分離し、Secure・HttpOnly・SameSite=Laxを維持する。loopback HTTPを安全なコンテキストと扱うブラウザが必要。通常のHTTPサイトへこの構成を転用しない。

鍵・DBは起動ごとに作り直す。停止すると登録したアカウントは失われる。残ったブラウザのPasskeyでは次回起動の新しいDBへログインできない。bootstrap招待は15分・一回限りで、消費と管理者作成を同じD1 batchで確定する。公開HTTP経由のbootstrap機能はない。

## 境界と実装範囲

- Rust: WebAuthnのnone・packed self/ES256検証、JSON/CBORの境界、ceremonyの目的・ブラウザ・期限・試行数、認可要求の静的プロファイル、PKCE。
- ローカルOP harnessのJavaScript adapter: HTTP、D1の原子的操作、OIDCフロー、`jose`/WebCryptoによるJWT署名・検証。これは仕様fixtureである。Rust/Wasmのブラウザ境界は`mikaki-browser-wasm`、Cloudflare runtime adapterは`mikaki-worker`として分離し、後者は実装を開始したばかり。
- OP画面: Svelte 5、ja/enの小さな型付きカタログ。RP画面は確認用のHTML。
- SQL: [既存の原子操作模型](../design/sql/oidc-critical-schema.sql)にローカル用テーブルを追加。本番migrationとしては扱わない。
- 設定: 統合TOMLを検証して秒単位のJSONとpolicy revisionをビルド時に生成する。設定変更後は再ビルドが必要。未実装機能の設定項目はまだ利用しない。

単一RP・静的ES256鍵で検証する。通常招待の管理画面、credential追加削除、鍵ローテーション、アカウント停止・監査の外部保管、外部監視連携、本番管理者認証、全入口のレート/サイズ制限、標準OP conformance、実認証器・複数ブラウザ、PRF、tossa/tsudoi接続は未完了。本番公開条件を満たしたとは扱わない。

## ログアウト通知の配送（2026-09-23）

[配送モジュール](logout-delivery.mjs)は、SSO失効と同じD1 batchでイベントを保存し、100件ずつ通知へ展開する。既存設計模型のaccount epoch全体を対象とする`revocation_event`とは範囲が異なるため、単一SSO用の`sso_logout_event`を使う。即時配送は`waitUntil`で行い、RPの応答待ちをログアウト画面の応答から外した。即時起動が失われても、scheduled handlerから再開する。

- 実行直前の原子的lease取得、clientごとの同時実行上限、古いlease所有者の結果書込み拒否。
- 408・429・5xx・通信障害のバックオフ、jitter、Retry-After、試行上限、失効確定時点からの配送期限。3xxは追従せず、その他4xxとともに恒久失敗にする。
- 毎回新しいLogout Tokenを署名し、応答本文の読取りを設定サイズで打ち切る。本文・トークンは記録しない。
- 未展開イベント数、未配送件数、最古の滞留時間、恒久失敗・期限切れ件数を集計し、閾値超過時に構造化警告を出す。完了した通知だけを、下記の保持条件を満たした後でGCする。

初期値は[統合TOML](../config/runtime-policy.example.toml)の`logout_delivery`および`oidc.backchannel`から読み込む。ローカルrunnerは`scheduler_interval`（初期1分）で実際のWorker scheduled handlerを呼ぶ。同じrunnerの定期実行は重ねず、別の起動経路との競合はDB leaseで制御する。待機中の通知は次回走査以降に実行されるため、バックオフ値は送信時刻の下限である。本番Cron Trigger・警報通知先・本番管理者認証は未配置。runner自体の再起動時には従来どおりDBも作り直されるため、プロセス再起動を跨ぐ永続性の試験ではない。

[配送統合試験](test/logout-delivery.test.mjs)はローカルD1で、失効とイベントの一括rollback、並行fanout、lease競合・期限切れ・古い結果の拒否、通知期限、恒久失敗、即時起動を省いたscheduled復旧を検証する。

## 期限切れ記録のGC（2026-09-23）

[GCモジュール](gc.mjs)をOP/RPのscheduled handlerに接続した。ローカルrunnerは`retention.gc_interval`（初期1時間）で呼び、各DB・一回の実行で対象テーブル合計`gc_batch_size`（初期500件）まで削除する。並行起動時にも各DELETEが削除条件を原子的に確認し、削除件数のみ構造化ログへ出す。

- OP: 期限切れceremony、子ceremonyが残っていない認可取引、ログアウト取引、client assertionの再使用防止記録、古いrate window。
- RP: 期限切れログイン・ログアウト取引、親の絶対期限を過ぎたアプリセッション、保持期限を過ぎたLogout Tokenのjtiと失効sid。アプリセッションが残るsidの失効記録は削除しない。

`gc_after`は生成時に有効期限・時計ずれ・GC猶予から保存する。既存記録を現在の短い設定で再計算しない。rate windowはwindow終端＋`rate_key_ttl`、RPのjtiと失効sidは既存の`expires_at`を保持期限として使う。明示したGC期限がないclient assertion記録は保持する。RPの失効sidは現在のセッション・遅延取引・再送期限に加え、当該sidの実際の親セッション期限も覆い、重複通知では期限を単調増加させる。

GC後に長く停止していたcallbackがセッションを復活させないよう、callbackのDB確定時にも取引期限と取得済みleaseを確認する。idle更新もその場で期限を再確認する。セッションはidle期限直後には削除せず、保存済みの親絶対期限＋猶予まで保持する。

OPのSSO/client session・code/token発行履歴・単一SSOの通知履歴もGC対象に加えた。発行履歴は現行のセッション有効性判定にも使われるため、短いtoken期限だけで削除しない。

- SSO作成時に絶対期限＋時計ずれ＋猶予と監査保持の大きい方を保存する。code発行・token交換の確定時にも、監査保持の下限を同じbatchで単調増加させる。
- 通知イベントは親SSOの保持下限、再送期限、イベント作成からの監査保持を覆う。配送結果には完了時から`delivery_result_ttl`＋時計ずれ＋猶予を保存する。期限切れとして終了した配送にも同じ保持を適用する。
- 配送行はイベントが展開済みで、配送が終端状態・leaseなしであり、イベントと配送両方の保持期限・再送期限を過ぎたときだけ削除する。未展開イベントと未完了配送は期限だけで捨てない。
- 配送行→子のないイベント→token発行記録→code付随情報→code→client session→SSO付随情報→SSOの順に削除する。SSO配下の削除は親の絶対期限・保存済み保持期限を過ぎ、通知イベントが残っていないことが条件。各段階で参照を確認し、500件の上限で途中停止しても次回から再開する。

招待・アカウント・credential・同意・subject・鍵は削除対象外。account epochを対象とする`revocation_event`は、展開済み・監査保持期限経過・対象epoch以下のSSOが残っていない場合にGCする。本番の管理者認証・再配送API、アカウント停止、独立した外部監査基盤、本番migration/Cronは別途実装する。現在はSSOの絶対期限を延長しない。将来、セッション延長・再配送を追加するときは関連する保存済み保持期限を同じ原子操作で延長し、既にGC済みの対象を復元する扱いにしない。

[GC統合試験](test/gc.test.mjs)と[長期記録の試験](test/gc-lifecycle.test.mjs)で、保持期限・親子参照・実行上限・保持延長との競合・旧設定の長寿命セッション・OP/RP scheduled実行・存命セッションの発行証拠・未完了通知・削除途中からの再開を検証する。

## ローカル運用者による再配送（2026-09-23）

`npm run dev`を起動した端末の標準入力から操作する。管理HTTP endpointは設けない。プロセスの標準入力を操作できるローカル利用者を信頼し、OSユーザー名を操作主体として記録する。これは本番の管理者認証やstep-up認証の代替ではない。

```text
logout-list
logout-retry EVENT_ID REVISION DEADLINE_UTC RETAIN_UNTIL_UTC REASON
```

`logout-list`は最大100イベントのID、版番号、期限、配送件数と再配送候補数を表示する。`logout-retry`にはそこで確認したIDと版番号、`2026-10-01T00:00:00Z`形式の二つのUTC日時を指定する。理由は`network_recovered`、`configuration_fixed`、`operator_retry`のいずれか。再送期限は現在と既存イベントの期限より後、保持期限は再送期限＋`delivery_result_ttl`＋時計ずれ＋GC猶予以上が必要。既存の長い保持期限は縮めない。

展開済みで、全配送が終端状態になり、失敗・期限切れの配送が残るイベントだけを受け付ける。成功済み通知は再送しない。対象の試行回数を0へ戻し、次回scheduled実行で通常の署名・lease・バックオフ処理を再開する。期限・保持期限の延長、イベント版の更新、監査記録、対象の再投入を同一D1 batchで確定する。

監査には操作ID、イベントIDと旧版、OSユーザー、理由、操作時刻、旧・新期限、要求した保持期限、対象sidと再投入前の状態・試行回数・HTTP状態を保存する。token・cookie・応答本文は保存しない。監査表はイベントへの外部キーを持たず、イベントGC後も自身の監査保持期限まで残る。イベントが残る間は監査もGCしない。端末出力には操作ID・イベントID・新版だけを返す。

GCとの競合時は、元のclient session集合に対して配送行が完全に残っていることを同じbatch内で確認する。一部または全部がGC済みなら拒否し、通知を再生成しない。並行した同一版への再配送は一方だけが成功する。拒否時に監査や期限延長だけが残ることはない。

[再配送試験](test/logout-admin.test.mjs)では通常配送までの復帰、二重実行、未展開・処理中・部分GCの拒否、GC競合、入力検証、イベント削除後の監査保持、監査書込み後の故障による全体rollbackを検証する。ローカルDBはrunner終了時に失われるため、監査の永続運用・外部保管は未実装。

## アカウント全セッションの失効（2026-09-23）

同じローカル運用端末で次のコマンドを使う。

```text
account-list
account-revoke ACCOUNT_ID EXPECTED_EPOCH REASON
```

`account-list`は最大100アカウントのID・現在epoch・状態を表示する。理由は`session_reset`または`security_incident`。想定epochと一致する有効アカウントについて、epoch増加と`revocation_event`保存を同じbatchで確定する。イベントには操作ID、対象アカウント、旧epoch、時刻、OSユーザー、理由、再送・保持期限を残す。二重実行や古いepochの操作は拒否する。

旧epoch以下のSSOは即座にOPの有効性判定から外れる。RPには通知受信または既存leaseの満了で反映される。scheduled handlerは旧epoch以下のSSOを最大100件ずつ単一SSOイベントへ展開し、既存の配送処理でsidごとに通知する。展開遅延で再送期限を数え直さず、重なる全ログアウトも同じSSOイベントへ集約する。既存の単一SSOイベントは再投入せず、失敗済み通知の再配送には明示的な`logout-retry`を使う。

未展開のアカウントイベントがある間、対象SSO・その配送記録をGCしない。監視の未展開件数と最古滞留時間にも含める。新epochで認証したSSOは旧イベントの対象にせず、同時SSO上限の計算からも旧epochを除外する。credentialは引き続き利用可能で、新たなPasskey認証によってログインできる。アカウント停止やcredential削除は別の機能となる。

[アカウント操作試験](test/account-admin.test.mjs)で二重実行、イベント保存失敗時のrollback、分割展開、重複イベント、GC・監査保持を検証する。ブラウザ試験では通知未達時のlease満了による停止と、再認証後の新セッションが遅延した旧通知で失効しないことを確認する。既存の認証確定処理は署名検証前に取得したepochを同じDB batchで再確認する。

## SvelteとTypeScript 7

`svelte-check` 4.7.6は`--tsgo`でTypeScript 7の型検査を利用できる。Svelteソースを検査用のTypeScriptへ変換する処理では、同ツールがTypeScript 6の`createSourceFile`等のJavaScript APIを呼ぶ。変換後の型検査は7が担当する。6は旧アプリ対応や二重の型検査のためではなく、検査ツール自身の実装依存であり、ブラウザへ配布しない。7.0.2のパッケージはこれらのAPIを同じ形で公開しないため、現行の公式構成では両方が必要。Svelte側でこの依存が不要になった時点で6を削除する。

```json
{
  "@typescript/native": "npm:typescript@7.0.2",
  "typescript": "6.0.3",
  "svelte-check": "4.7.6"
}
```

`npm run check:ui`は`--tsgo --fail-on-warnings`を指定する。[公式手順](https://github.com/sveltejs/language-tools/tree/master/packages/svelte-check#typescript-7-supports)と`~/repo/tayori/tauri-app/package.json`を照合した。依存の強制解決やpeer検査の無効化は不要。

## 検証

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
npm run check:ui
npm run check:i18n
npm run format:check
npx playwright install chromium
npm run test:e2e
```

統合試験50件で、登録完了・code交換の並行実行、assertionの一回性とendpoint拘束、PKCE不一致、code期限、署名鍵停止、UserInfoの用途と期限、SSO再利用、ログアウト通知、遅延callbackの復活防止、lease切れ後のfail-closed、bootstrap再使用拒否を確認する。nativeの単体試験とcompile-fail試験も別に実行する。

[CI](../.github/workflows/ci.yml)はこれらと依存監査・native coverage・Wasm/UIサイズの計測を実行し、artifactへ保存する。GitHub上の実行は未確認。coverageはauth/oidc/webauthnのnative既定featureが対象で、別ファイルのtests.rs・Wasmアダプター・JS/Svelteを含まない。inline testコードは含まれるため、製品全体のcoverageとして表示しない。GitHub上での実行は要確認。ESLintやフロントcoverageなど、設計で挙げた品質ゲートに未実装項目がある。

```sh
mkdir -p artifacts
cargo llvm-cov --locked --workspace --exclude mikaki-browser-wasm --exclude mikaki-worker --ignore-filename-regex '/tests\.rs$' --json --summary-only --output-path artifacts/native-coverage.json
npm run health
```

規模・coverage・直接依存の履歴とグラフは[metrics](../metrics/README.md)を参照。コード規模は実装とテストを分け、mainへのpushごとに更新する。coverageはnative Rustの一部に限り、JS/SvelteやWorker Wasmアダプターのcoverageを示さない。OPアダプターは現段階で約700行あり、原子操作の前提条件を同じ場所で確認するためにまとめている。機能拡張時には登録・token・logoutの単位で責任を分ける。

WebAuthnのfit/gapは[改善バックログ](../docs/webauthn-fit-gap-todo.md)で追跡する。WG-04の対応として、登録画面は`credProps.rk===true`をクライアント互換性条件として確認する。個別拡張の保証は[対応表](../docs/webauthn-extensions.md)を参照。次の実機・ブラウザー互換性記録はWG-06を参照。

WebAuthnの[診断契約](../docs/webauthn-errors.md)に基づくWasm/JS境界・ログの正規化・attestation証跡の3試験も含め、`npm run test:e2e`は計49件。ブラウザー試験ではchallenge/origin改変の公開400応答と内部理由コードを併せて確認する。

WebAuthn端末・ブラウザーの組合せと仮想認証器／実機の未試験項目は[互換性マトリクス](../docs/webauthn-device-compatibility.md)で追跡する。CI既定のPlaywright Chromiumに加え、ローカルでは`MIKAKI_BROWSER_CHANNEL=chrome`または`chrome-canary`でブラウザーを切り替えられる。
