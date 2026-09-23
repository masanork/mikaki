# WebAuthn fit/gapと品質改善TODO

2026-09-23 / 比較レビューに基づく改善バックログ。優先順位は本書内の順序であり、製品全体のP0や公開条件を追加するものではない。機能追加の採用判断と実装完了は区別する。

## 比較の前提

[ADR 0006](adr/0006-compact-portable-webauthn.md)のコンパクトさ、native/Wasm共通コア、HTTP・DB・時計・ネットワークとの分離を維持する。[ADR 0008](adr/0008-webauthn-conformance.md)の製品既定（ES256・UV required・discoverable・attestation要求none）も維持する。webauthn-rsの全機能を追うことを目標にしない。

比較対象は手元のsakimoriと、webauthn-rsの[commit be696b79](https://github.com/kanidm/webauthn-rs/tree/be696b79800bd1953df78e87d0215571733cc26f)（Cargo上のversion 0.5.5）。以下の評価は実装と公開資料のレビューであり、同条件の性能比較やセキュリティ監査ではない。

sakimoriの`crates/webauthn/src`は1,811行（うちtests.rsが520行）。比較先のcore・公開API・proto・attestation-ca・base64補助・fido-mdsのsrcは計17,144行。いずれもRustの物理行数で、コメント・空行・埋め込みテストを含み、外部依存・fixture・exampleを除く。sakimoriのauth/storeや比較先の認証器クライアントは含めない。対応範囲・文書量が異なるため、同等機能を約1/10で実装したとは解釈しない。

## Fit: 維持したい設計と確認済みの範囲

| 項目       | 現在の適合・利点                                                                      | 維持する境界                                                                                      |
| ---------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| 移植性     | 同じRust検証器をnative/Wasmで使用                                                     | コアへOS・HTTP・DB依存を持ち込まない                                                              |
| 検証の入力 | challenge・origin・RP ID・時刻・信頼情報を明示的に渡す                                | 信頼されたサーバー状態から構築し、credential応答から採用しない                                    |
| 検証結果   | 外部から構築・Deserializeできない型                                                   | 署名検証成功とログイン確定を混同せず、challenge消費とcredential更新はauth/storeで原子的に確定する |
| 入力境界   | サイズ・深さ・重複・末尾データなどを検査                                              | 機能追加時も制限と拒否経路を維持する                                                              |
| 適合試験   | 記録上、Tools 1.9.1の必須155件をnative/Wasmで通過。1.9.2 ARM64でもnativeの155件を通過 | OPTIONAL 14件、正式認証、監査、実機網羅とは区別する                                               |

試験の根拠は[1.9.1結果](../local/conformance/results-2026-09-22.md)と[1.9.2追試](../local/conformance/performance-arm64-2026-09-23.md)。今回の比較時にはnativeの17テストとcompile-fail 2件を再実行して成功した。公式Suiteは比較のために再実行していない。

## Gap: 学ぶべき点と対応順

| ID    | 差分・現在の制約                                                  | 学ぶ点／対応方針                                                          | 優先度                      |
| ----- | ----------------------------------------------------------------- | ------------------------------------------------------------------------- | --------------------------- |
| WG-01 | コアとauthの失敗がほぼ`Invalid`へ集約される                       | 内部の拒否理由を型で区別し、外部応答との対応を分離する                    | A（完了）: 次の品質改善             |
| WG-02 | `Context`等の公開フィールドを呼び出し側が組み立てる               | 用途別APIや状態型による誤用防止を参考に、最小の設定・ceremony契約を整える | A（契約レビュー完了）                           |
| WG-03 | 信頼情報と必須ポリシーを分離し、検証済み証跡を返す | 通常passkeyと認証器の出自保証を区別する | A（完了） |
| WG-04 | 拡張CBORの構造検査はあるが、個別拡張の意味を扱うAPIではない       | 拡張ごとの要求・応答・保証を明文化する                                    | A: 対応範囲の明示（完了）   |
| WG-05 | JSON/CBOR/COSE、証明書・TPM・MDSの独立seedと限定時間のfuzz結果を蓄積 | 変異入力を通常の回帰試験へ戻し、範囲と限界を記録する | A（初回実行完了） |
| WG-06 | Chrome系列の仮想認証器試験を記録。platform authenticator・他OS・外付けkeyは未試験 | 機種・OS・browser・認証器と同期挙動を区別して記録する | B（ブラウザー自動試験済み、実機継続） |
| WG-07 | MDSの暗号検証と製品向け運用統合の間に差がある                     | metadataの意味、更新、失効後の扱いを含めて設計する                        | B: 製品でMDSを使う前        |
| WG-08 | 小ささ・速度の比較条件が未統一                                    | 同じ責務と安全要件で測定する                                              | A（比較範囲を明記して完了） |
| WG-09 | 第三者レビューと脆弱性受付経路が未整備                          | レビュー対象、依存更新、脆弱性対応を整える                                | B                           |
| WG-10 | Apple/Android Key attestation等は未対応                           | 実需要と保守費用で追加を判断する                                          | C: 用途が生じた時           |

## TODOと完了条件

### A: 次の品質改善

- [x] **WG-01: エラーを詳細化する。** 入力形式・上限、challenge/origin/RP不一致、UV/UP、credential/userHandle/allow-list、backup/counter、署名、証明書パス・期限、metadata/CRL等を、診断に必要な粒度へ分類する。列挙型の候補であり、この分類全てを公開APIへ露出することは前提にしない。
  - 完了条件: native/Wasm共通の安定したエラーコードと、HTTP/JS境界での外部エラーへの対応表がある。代表的な異常入力の分類と既存の拒否動作を試験する。
  - 内部ログには段階・理由・相関IDを残せるようにし、生のcredential応答、challenge、userHandle等を既定で記録しない。未登録credentialと署名不正など、利用者の存在推測につながる詳細は外部応答へそのまま返さない。コア自身にログ基盤を必須化しない。
  - 2026-09-23: payloadを持たない共通エラー型と[診断・公開応答契約](webauthn-errors.md)を実装。native/Wasm各21試験とcompile-fail各2件、workspace試験、Clippy、JS/ブラウザーを含む48試験が通過。Wasm境界とログの文字列除去、challenge/origin改変の公開応答同一性を確認。公式Suiteは今回再実行していない。
- [x] **WG-02: 信頼された入力とceremonyの契約をレビューする。** 設定検証、登録／認証の状態、保存済みポリシー、challengeの生成・期限・消費、credentialの所有者照合を誰が保証するか整理する。最小のconstructor/builderや用途別状態型で改善できるか評価する。
  - 完了条件: コア単体とauth/store経由の保証が文書化され、不正設定や用途の取り違えを拒否する試験がある。型を増やす場合は解消する具体的な誤用を説明する。検証結果の外部構築禁止と、再送・同時実行時の原子性を維持する。
  - 2026-09-23: [信頼入力・ceremony契約](webauthn-ceremony-contract.md)を整理し、両検証入口の設定検査と空browser bindingの拒否を追加。native/Wasm各22試験、型境界各2件、workspace・Clippy、JS/統合48試験が通過。型の追加は見送り、永続環境での発行時設定snapshotは後続課題として明示。公式Suiteは今回未実行。
- [x] **WG-03: attestation必須の意味と結果型を整理する。** 現在は`Context.attestation`に信頼情報を渡しても`none`を受理する。`VerifiedRegistration`にも方式・AAGUID・信頼元を残さない。「検証に使える信頼情報」と「信頼されたattestationを必須にするポリシー」は別の契約として定義する。
  - 完了条件: 通常passkeyとattestation必須の適用範囲を明記する。必須モードを採用する場合はnone/selfによる条件のすり抜けを拒否し、必要な検証済み証跡を外部から偽造できない型で返す。製品のnone既定は維持する。未検証の`attestation_hint`を証跡として利用しない。
  - 2026-09-23: [attestation契約](webauthn-attestation.md)と`required_trusted`を実装。none/selfの拒否、方式・保証区分・metadata識別子・検証時刻・実際の信頼anchor指紋を返す偽造不能な結果型を追加。製品はoptionalと要求noneを維持。native/Wasm各24試験・型境界各4件、workspace・Clippy、JS/統合49試験が通過。公式Suiteは今回未実行。
- [x] **WG-04: 拡張対応表を作る。** 構造検査、署名対象への包含、拡張固有の意味の検証、クライアント出力を区別する。現在の`extensions()`はCBOR mapと末尾等の検査であり、`credProtect`等の意味を検証する実装とは扱わない。
  - 完了条件: 利用する拡張について要求・結果・保存項目・未知拡張の扱いが決まり、必要な意味を確認できない時に保証済みとしない。個別実装は採用した拡張だけに限定する。
  - 2026-09-23: [拡張契約と対応表](webauthn-extensions.md)を追加。文字列でない拡張識別子の拒否、未知拡張の署名改変の回帰試験、製品画面での`credProps.rk`確認を実装。native/Wasm共通試験とブラウザー試験で検証する。PRF等の個別機能は未実装のまま。
- [x] **WG-05: パーサーと信頼検証を重点的に検証する。** JSON/CBOR/COSE、DER・証明書チェーン、TPM、MDS/JWT/CRLを対象に、入力制限、panic、過大な時間・メモリー使用、検証漏れを探す。
  - 2026-09-23: [独立fixtureを使う3 fuzz target](webauthn-fuzzing.md)とseed再生チェックを追加。macOS arm64、nightly 1.100.0、cargo-fuzz 0.13.2/libfuzzer-sys 0.4.13で各25秒実行し、registration 268,184回/42 seed、assertion 363,762回/4 seed、metadata 259,561回/43 seed、panic/timeoutなしを記録。MDS全体のfixture期待値をseed時に照合。各targetは独立生成の署名付き・不正証明書fixtureを使用し、native/Wasmの共有回帰試験は24件と型境界試験4件を実行済み。長期間の探索・署名維持のstructured mutation・差分実装比較・第三者レビューは未実施。公式FIDO Suiteは今回未実行。

### B: 検証・運用・評価

- [ ] **WG-06: 実機互換性のマトリクスを作る。** Apple、Android、Windows Hello、外付けセキュリティキーについて、端末・OS・ブラウザー・認証器・同期有無・実行日を記録する。
  - 完了条件: 製品が対象とする組合せで登録、再認証、discoverable、UV、backup/counterの挙動を確認し、成功・未試験・既知の制約を分ける。ブラウザーの仮想認証器による試験と実機試験を混同しない。
  - 2026-09-23: [互換性マトリクス](webauthn-device-compatibility.md)を作成。Playwright Chromium 153、Chrome 154、Chrome Canary 156のheadless自動試験は各49件pass。すべてCDP仮想CTAP2.1 authenticatorを使い、実機での認証を証明しない。headed ChromeでのTouch ID操作はUIが出ず未完了で、自動試験対象から除外。MacBook Air M3/macOS 27のTouch ID、iOS/Android/Windows Hello、外付けSecurity Keyは未試験。Mac上のSafari 27も未試験。
- [ ] **WG-07: MDSの対応範囲と更新運用を設計する。** `verify_mds`はAAGUIDなしのU2F entryを扱い、検証結果にBLOB番号・期限・status reportを保持する。firmware別status評価、永続キャッシュ・更新処理は未実装。
  - 完了条件: 必要なmetadataを欠落・誤解せず扱えることをfixtureで確認する。永続キャッシュ、BLOB番号の巻き戻し防止、期限切れ・取得失敗・失効時の扱い、更新の原子性を運用仕様と試験で示す。BLOB番号等を検証結果として返す必要も評価する。HTTP取得・取得先制限はコア外に保つ。
  - 2026-09-23: [MDS運用境界](webauthn-mds-operation.md)を追加。FIDO MDS 3.1.1 PSに合わせ、コアは必須`iat`・BLOB番号・任意`nextUpdate`・U2F key identifier・statusのfirmware/date/certificate情報を保持する。`nextUpdate`は廃止予定のため鮮度条件に使わない。検証済みU2F entryを実attestationへ接続するfixtureを追加。永続snapshotと番号高水位、原子的更新は製品アダプターの将来作業。
  - 2026-09-23検証: native workspaceとWasm各24件、MDS応答JSON境界を含むNode E2E 50件、Rust/JS書式・設計整合チェックが通過。永続snapshot、番号高水位、原子的更新は未実装のため完了扱いにしない。
- [x] **WG-08: 比較可能な範囲で規模・性能を測定する。** 検証器単体と製品全体、nativeとWasm、通常認証とattestation/MDSを分けて記録。
  - 完了条件: 同じ入力・方式・信頼条件・ビルド設定・測定境界のfixture比較を行い、製品全体など責務の異なる数値は別物として明示する。Suite所要時間を検証器の速度順位に使わない。
  - 2026-09-23: [native性能・サイズ記録](../local/conformance/performance-2026-09-23.md)と[MDS変更後のfixture再測定](../local/conformance/performance-core-2026-09-23.json)を更新。native core、Wasm/JSON境界、認証/attestation方式を分け、製品Worker Wasm 644,011 bytesと試験server 2,604,224 bytesを記録したが、どちらもコア単体サイズではない。さらに[同じFIDO Tools 1.9.2 Suiteによるiwato/sakimori比較](../local/conformance/performance-cross-impl-2026-09-23.md)を各2回実施し、両方155/155成功、Suite時間の中央値は5.385秒／3.285秒だった。Suite時間は検証器単体の速度順位ではない。同一fixture native core比較を各2回・18サンプルで行い、none登録 1.366/2.440 µs、ES256 assertion 158.333/96.853 µs（iwato/sakimori中央値）を記録した。さらに同fixture Wasm assertionはiwato 805.156 µs、sakimori 411.036 µs（各3回のrun中央値の中央値）、test shimは363,714/373,840 bytesだった。製品workerのraw Wasmは同release設定でiwato 2,303,854 bytes、sakimori 738,618 bytesだが機能・依存グラフが異なるためWebAuthn単体のサイズ比較にしない。native検証呼出し中のpeak live heapはnone登録1,159/2,094 bytes、assertion 1,119/1,366 bytes（iwato/sakimori）で2回一致した。これは事前保持データ・stack・process RSSを含まない。suite server process peak RSSは各2回の中央値で45,867,008/18,251,776 bytes、macOS peak footprintは32,236,156/16,146,876 bytes（iwato/sakimori）。Suiteは各2回とも155件成功したが、process memoryは稼働時間とMDS初期化が揃わない参考値として明示した。iwato Wasm registrationはNodeのwasm32-unknown-unknown実行で`SystemTime::now()`の未対応trapとなり比較対象外。責務が異なる製品artifactの差を無理に順位付けせず、fixture・core・Suiteの比較範囲と限界を記録したため本項目を完了とする。追加の性能調査は、利用者向け遅延、回帰、または具体的なhot spotが観測された場合に限る。
  - チューニング判断: [ARM64のnative測定](../local/conformance/performance-arm64-2026-09-23.md)では、FIDO Suite 2回目の3,085.945msに対しhandler合計42.374ms（約1.4%）、Rust検証14.773ms（約0.5%）。Suite経過時間の大半はサーバー処理外であり、暗号・DBを省略する最適化は行わない。具体的なhandler hot spotや利用者向け遅延を確認した場合に計測して判断する。
- [ ] **WG-09: 第三者レビューと保守手順を整える。** 独自証明書パス、TPM/MDS、ceremonyとstoreの境界を重点レビュー対象にする。暗号依存の安定版・保守状況と更新方針も確認する。
  - 完了条件: レビュー対象commit、実施範囲、指摘と対応状況を記録する。脆弱性連絡先・更新手順を用意する。RSAのRC採用とRUSTSEC-2023-0071の用途限定除外は[ADR 0008](adr/0008-webauthn-conformance.md)に従って再評価し、無指摘の監査と表現しない。
  - 2026-09-23: CIは各push/PRで`cargo audit`と`npm audit --audit-level=low`を実行する。今回のRust auditは129 crate dependenciesを走査し、`.cargo/audit.toml`に明記したRUSTSEC-2023-0071だけを用途限定で除外。RustSecの2026-09-14更新でも`rsa 0.10.0-rc.18`を含め修正版なし。秘密鍵処理を追加しない判断をADRに更新し、Cargo・npm・GitHub Actionsの週次Dependabot更新を設定した。第三者レビュー、公開時の脆弱性連絡先は未確定のため完了扱いにしない。
  - [第三者レビュー用ブリーフ](webauthn-security-review.md)に境界・確認事項・既知の非対応・証拠リンクを整理。2026-09-23の再scanでは最新RustSec advisory database上129依存、既知の用途限定除外以外に指摘なし。npm auditは0 vulnerabilities。CIと週次Dependabotも稼働設定済み。外部reviewerと対象commitを固定できず、受付可能な脆弱性報告経路も未設定のためWG-09は継続。

### C: 用途に応じた機能追加

- [ ] **WG-10: 追加方式を実需要で選ぶ。** Apple/Android Key attestation、追加アルゴリズム、クロスオリジンiframe等は、対象製品・端末に必要になった時点で評価する。
  - 完了条件: 利用シナリオ、保証、非対応時の挙動、native/Wasm両方の検証手段、依存・サイズ・保守費用を示して採否を記録する。採用しない場合も対応範囲に明記する。対応方式数を品質指標にしない。

## 比較の参照先

- [sakimori WebAuthnコアの現状](../crates/webauthn/README.md)、[公開型と検証処理](../crates/webauthn/src/lib.rs)、[attestation](../crates/webauthn/src/attestation.rs)、[metadata](../crates/webauthn/src/metadata.rs)
- webauthn-rsの[用途別APIと状態の扱い](https://github.com/kanidm/webauthn-rs/blob/be696b79800bd1953df78e87d0215571733cc26f/webauthn-rs/src/lib.rs)、[エラー型](https://github.com/kanidm/webauthn-rs/blob/be696b79800bd1953df78e87d0215571733cc26f/webauthn-rs-core/src/error.rs)、[metadata処理](https://github.com/kanidm/webauthn-rs/tree/be696b79800bd1953df78e87d0215571733cc26f/fido-mds/src)
- webauthn-rsの[README](https://github.com/kanidm/webauthn-rs/blob/be696b79800bd1953df78e87d0215571733cc26f/README.md)は実機試験とSUSE Product Securityによる監査通過を記載する。監査が現行コード全体を保証するとの意味には取らない。[Security Policy](https://github.com/kanidm/webauthn-rs/blob/be696b79800bd1953df78e87d0215571733cc26f/SECURITY.md)も継続保守の参考とする。
