# フロントエンド・i18n・品質CI

> Design snapshot. Svelte 5, TypeScript checks, localization, and CI have since acquired implementation evidence. Read [project status](status.md) and the current workflows before treating recommendations below as unimplemented.

2026-09-22 / 推奨案。一部を[ローカル縦切り実装](../local/README.md)へ適用済み。以下の全項目の完了やGitHub上のCI成功を示すものではない。

ローカル画面とWorker配信のログイン・Vault画面はSvelte 5＋Viteを使い、共通のParaglide JS 2カタログから日本語・英語の型付きmessage関数を生成する。TypeScript 7のnative検査（`svelte-check --tsgo`）とnpm/package-lockを採用した。現行のsvelte-check自身がSvelteソースの解析・検査用TypeScriptへの変換にTypeScript 6のJavaScript APIを使うため、6も開発依存に必要。旧アプリへの後方互換性を目的とせず、型検査器は7に統一する。TypeScript 7は`@typescript/native`へのnpm aliasで配置する。最新の[公式README](https://github.com/sveltejs/language-tools/tree/master/packages/svelte-check#typescript-7-supports)とtayoriの設定を参照。

初期OIDCの小さな認証画面と、Rust/Workersの認証基盤を対象にする。madowiのローカルworkflowとstats実装を参考にし、mikakiの認証・失効契約に合わせて測定範囲とゲートを定める。既存の[実装基準](oidc-implementation-readiness.md)に追加する提案であり、製品の完成を意味しない。

## フロントの構成

Svelte 5＋TypeScript strict＋Viteを推奨する。初期画面はログイン、初回接続許可、アカウント選択、credential管理、セッション/接続管理に絞る。状態はSvelteのrunesと小さなモジュールで管理し、別の全域状態管理ライブラリを初期から加えない。native HTMLのbutton・form・dialog等を優先し、CSSはコンポーネント単位と共通デザイントークンから始める。UI部品集やTailwindは必要性が明らかになってから比較する。

初期はViteで生成する静的UIをRust Workerと同一originで提供する。/authorizeや/token等のプロトコル、認証の確定、cookieの設定はRust側が担当する。UIはサーバーの認可取引に結び付いた表示と操作を担当し、roleやログイン可否をブラウザだけで決めない。locale変更や再読込みでもstate/nonce/PKCE・同意の対象を作り直さない。

SvelteKitはSSRやルーティングが実際に必要になった場合の選択肢とする。採用する場合でもRustとKitの双方へ認証・セッション判定を重複実装しない。静的shellの配信を理由に全HTTP要求をSPA fallbackへ回さず、OIDC/APIパスと未知パスの扱いを分ける。秘密値や認可要求の全体をHTMLへ埋め込まない。

WebAuthn呼出しは薄いブラウザアダプターへ集約する。PRFの出力・鍵素材は通常のSvelte表示状態や永続storeへ入れず、必要なモジュール内に限定する。これは侵害されたoriginのJSから秘密を隔離する保証ではないため、第三者scriptを認証・解錠originへ入れない。通常ログインではPRFを要求しない。

Svelteによる文字列エスケープを維持し、利用者入力・アプリ名・翻訳文に{@html}を使わない。認証画面のCSPとアセット配信を実ブラウザで検証する。エラー時もフォーカス、読み上げ、キャンセル、再試行を設計し、色やアイコンだけで状態を伝えない。

## 初期からのi18n

日本語と英語の2言語で始める。画面文言をmessage keyへ切り出し、プレースホルダーの型・名前を揃える。Paraglide JS 2を採用し、Viteで型付きmessage関数を生成する。初期から翻訳SaaSや多数言語の運用は追加しない。

localeの優先順位は、認可取引で明示した対応ui_locales、利用者が保存した選択、Accept-Language、既定jaとする。ui_localesは対応言語のallowlistから最初の一致を選び、未知localeは安全にfallbackする。画面上の明示的な切替は当該取引の表示言語を更新する。localeをorigin、redirect URI、issuer、subの変更へ結び付けない。サポートするBCP 47タグと照合規則をテストする。

html langを更新し、日付・数値はIntlで表示する。比較・署名・期限計算はUTC値のまま扱う。文章を断片の連結で作らず、複数形・語順・句読点をmessageとして扱う。名前や接続先は翻訳対象にせず、安全に補間する。将来RTLを追加できるようCSS logical propertiesを基本とする。

サーバーは安定したエラーコードと型付きパラメーターを返し、UIが翻訳する。プロトコルエラー値、ID、ログの理由コードは翻訳しない。JS読込み前の期限切れ・拒否・メンテナンス画面もja/enの静的文言を持ち、サーバー例外の文字列を直接表示しない。

CIではキーの欠落/余剰、パラメーター不一致、空翻訳、ユーザー向け文字列の直書きを確認する。日本語文字のgrepだけでは英語の直書きを検出できないため、Svelte/TSの文脈を扱えるlintを使い、ブランド名等の例外は理由付きで管理する。実行時fallbackがあっても、ja/enの未翻訳をCI合格にしない。長文化した疑似翻訳と両言語の主要画面で、折返し・ボタン幅・フォーカス順を試験する。

## 規模の測定

毎PRでbase/headの同じルールによる差分を表示する。手書きRust、TS/Svelte、SQL、テスト、文書、生成物を分ける。生成物・vendored依存・翻訳生成関数は手書き行数から除外するが、配信バンドルの総サイズからは除外しない。

測るのは行数に加え、crate/モジュール別の公開API数、最大ファイル、直接/推移依存、runtime/dev/target別依存、Rust/Wasmのraw/gzipサイズ、初回画面JS/CSSの圧縮サイズ、ビルド時間・テスト時間とする。TODO、allow、unsafe、lint抑制、coverage除外の増加もレビューへ出す。単純な文字列カウントや括弧数によるtest行判定は参考値と明示し、正確なAPI監査の代わりにしない。

初期案では手書き製品ファイル500行を注意、800行超の新規作成/増大を理由付きレビュー対象とする。機械的分割で通すことを目的にしない。総行数が増えたこと自体ではCIを落とさない。バンドル絶対上限は最初の動く縦切り実装で実測して基準を決め、以後の変更に差分と根拠を要求する。

計測JSON・HTML・LCOV・グラフはCI artifactとJob Summaryを正本とし、commit SHA、toolchain、対象feature、除外一覧、測定方式の版を記録する。初期はbotのmainへの自動commitや外部coverage SaaSを必須にしない。履歴保持が必要なら、trustedなmain用jobから専用の履歴保存先へ出す。PR測定jobに書込みtokenを与えない。

## カバレッジの使い方

Rustはcargo-llvm-covでline・region・functionを、フロントはVitestのV8 providerでline・branch・function・statementを測る。Rustのregionはbranchと同義ではない。参照したcargo-llvm-covではbranch測定はnightlyの不安定機能なので、stableの必須ゲートとは分けて試験する。

初期目標案は、認証・OIDC coreのline 90%以上、region 85%以上、フロントの手書きロジックはline 85%以上・branch 80%以上。初回実装の測定と対応付けを確認して閾値を有効化する。以後、閾値引下げ・除外追加・対象featureの削減には理由を要する。閾値を満たすためだけのassertionなしテストや実装をなぞるテストは作らない。

変更箇所の未被覆行と重要な拒否条件をPRへ出す。全体平均で暗号/認可の穴を隠さず、crate/領域別の結果を併記する。生成物以外の未実行sourceも分母に含める。計測失敗や空reportを0%/100%の成功へ変換しない。UI生成コード、FFI境界などの除外は根拠と代替試験を明記する。

失効、期限境界、一回性、署名・alg・issuer・audienceの取り違え、原子的更新の途中失敗は、率に関係なく必須シナリオとする。選んだ境界にはproptestと小規模なmutation testingを追加する。NativeでのカバレッジはWasmでの実行確認を代替せず、仮想認証器は実認証器の互換性を代替しない。

## CIの配置

| 頻度 | チェック |
| --- | --- |
| 毎PR・必須 | 設計設定/リンク/SQL試験、rustfmt・clippy、Rust unit/integration/doc test、core coverage、Native/WasmビルドとWasm smoke、svelte-check・TS strict・ESLint・format、Vitest/coverage、build、i18n、規模差分、依存境界、lock変更時の依存監査 |
| 毎PR・主要経路 | 実Workerローカルruntimeを使うPlaywright、Chromium仮想WebAuthnによるログイン/キャンセル/ログアウト/別origin拒否、ja/en、keyboardとaxe、DB migration/原子性の契約試験 |
| 毎晩・必要なPR・手動 | 長時間fuzz、固定corpus回帰、Rust branch coverage実験、mutation、負荷/通知再送/soak、Chromium/Firefox/WebKit、スクリーンショット比較、最新脆弱性監査 |
| 公開前・隔離環境 | 実D1 batch/read consistency、旧schemaからのmigration、鍵更新/停止、conformance、tossa/tsudoi相互運用、実認証器/PRF、DB復旧訓練、a11y手動確認 |

PlaywrightのWebAuthn仮想認証器はChromium/CDPの経路として扱う。他ブラウザのUI・cookie試験が通ったことをPasskey/PRF実機対応と同一視しない。テスト失敗時のtrace、HAR、スクリーンショットには認証情報が入り得るため、合成account/鍵だけを使い、artifactの権限と保持を制限する。

core coverageは初期から毎PRで測る。重くなった場合は結果を再利用するjob構成や対象の分離を検討し、認証変更のゲートを夜間だけへ退避させない。madowiのように重い全体検証を分ける構成は採用できるが、初期mikakiにmobile build・Tauri・Docker等の無関係なmatrixは持ち込まない。

スクリーンショット比較jobで--update-snapshotsを実行しない。基準画像の更新は別操作として差分をレビューする。再試行で通ったテストはflakyとして記録し、再試行成功を安定性の証拠にしない。例外は担当・理由・期限を記録する。

## 予め固定する開発契約

- Rust toolchain/MSRV・Node・pnpm・Python・Wrangler・Playwrightを管理ファイルへ固定し、Cargo.lock/pnpm-lock.yamlを追跡。CIはcargo --lockedとpnpm --frozen-lockfileを使う。stable/latestが毎回変わる測定にしない。Workers compatibility date/flagsも固定する。
- Rust→ブラウザのHTTP DTOはschemaを正本にTS型と実行時validatorを生成する。TS型だけでは受信JSONの安全性を保証しない。秘密フィールドを公開DTOの生成対象にしない。生成後の差分が残る場合はCI失敗とする。
- DB migrationは順序付きSQLで管理し、空DBと直前リリースのfixtureの両方へ適用して試験する。取り消せないmigration後にアプリだけrollbackする手順は互換性試験なしに認めない。
- cargo-deny等でlicense/sourceと依存境界を、cargo-audit/pnpm auditで既知勧告を確認する。dev依存にもCI実行時の攻撃面がある。既知脆弱性の例外は影響範囲・理由・担当・期限を持たせ、madowiのRSA例外をそのまま継承しない。
- 自作Rustのunsafe禁止、認証coreのWorkers/HTTP依存禁止、server側のPRF/Vault端末処理混入禁止を静的な依存グラフとlintで検証する。featureの無意味な全組合せではなく出荷する構成を試験する。
- GitHub ActionsのusesはSHA固定、permissionsは原則contents:read。untrusted PRにsecretを渡さず、pull_request_targetでPRコードを実行しない。workflow静的検査、secret scan、依存更新botを導入し、公開jobとPR検証を分離する。
- required checkはbranch protection/rulesetで設定する。workflowを置くだけでmerge保護済みとはしない。対象workflowのpath filterで必要checkが永久pending/未実行にならないよう、集約gateが必要jobの成功を確認する。

設計・SQL模型に加え、現在はRust/Svelteのローカル実装と対応するCI定義がある。実行済みの範囲は[ローカル実装の記録](../local/README.md)を参照する。未導入の品質ゲートや存在しないテストをskipして「検証済み」と表示しない。

## 確認した参照

madowiのローカル.github/workflows/ci.yml、ci-full.yml、security.yml、growth-chart.ymlとscripts/stats.mjsを確認した。規模のratchet、軽量/重いCI、Rust/JS別coverage、i18nゲートを参考にした。madowi全体の監査や実行結果の検証ではない。

- [Svelte概要](https://svelte.dev/docs/svelte/overview)・[testing](https://svelte.dev/docs/svelte/testing)：コンポーネントとVitest/ブラウザ試験。
- [Paraglide JS](https://inlang.com/m/gerre34r/library-inlang-paraglideJs)：型付きmessage生成とVite統合。
- [Vitest coverage](https://vitest.dev/guide/coverage.html)：V8/Istanbul、対象runtime。
- [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)：line/regionと不安定なbranch計測。
- [Playwright accessibility](https://playwright.dev/docs/accessibility-testing)：axeと手動評価の役割。
