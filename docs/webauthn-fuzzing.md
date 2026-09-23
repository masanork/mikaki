# WebAuthn parser fuzzing

2026-09-23 / WG-05のfuzz target、独立fixtureのcorpus、実行記録。

## 対象と入力の組み立て

[fuzz package](../fuzz/Cargo.toml)は通常のCargo workspaceから除外し、製品依存に`libfuzzer-sys`を足さない。独立した[Python cryptography/OpenSSL生成fixture](../crates/webauthn/testdata/README.md)を各実行時にcorpusへ再生成する。seed生成時には登録fixtureの受理/拒否、MDS fixtureの検証結果を期待値と照合し、認証用fixtureは有効な署名を作って完了まで確認する。corpusファイルは無視対象で、変異による大量のcoverage入力をソース管理へ入れない。

| target | 入力変異 | 通過させる処理 |
| --- | --- | --- |
| `registration` | 独立登録fixtureのattestationObject、clientDataJSON | JSON/Base64URL、CBOR、authenticatorData、COSE鍵、packed/U2F/TPM、証明書・metadata参照、署名 |
| `assertion` | clientDataJSON、authenticatorData/拡張、COSE公開鍵、DER署名 | 保存credentialとの照合、key parse、flags/counter、署名検査 |
| `metadata` | MDS JWT文字列/header、CRL bytes、署名済みMDS全体JSON | JWT/X.509、署名、CRL、期限、metadata JSON/entries |

rawフィールド変更後の署名失敗は想定した検証結果であり、fuzzerはpanic・ハング・libFuzzer timeoutを探索する。署名検証を無効化するcfgやtest専用の受理経路はない。有効署名付き全体MDS seedでは後段payload/entry parserへ到達しやすくする。暗号署名を保ったまま意味を変えるstructured mutationや、ローカルで認証器と比較する差分試験は対象外であり、Conformanceと既存の独立mutation fixtureで補う。

## 再実行

nightly toolchainとcargo-fuzzを固定する。ローカルでは一度seedを生成し、targetごとに時間を区切る。

```sh
cargo run --manifest-path fuzz/Cargo.toml --locked --bin seed
cargo +nightly-2026-09-21 fuzz run registration -- -max_total_time=120 -max_len=65538 -timeout=10
cargo +nightly-2026-09-21 fuzz run assertion -- -max_total_time=120 -max_len=65538 -timeout=10
cargo +nightly-2026-09-21 fuzz run metadata -- -max_total_time=120 -max_len=131074 -timeout=10
```

`.github/workflows/webauthn-fuzz.yml`は日次ではなく毎週と手動で実行し、各targetを90秒実行する。所要時間、実行回数、peak RSS、対象targetとseed件数を記録する。結果はそのcommitの探索範囲でpanic/timeoutが見つからなかったことだけを示し、未到達コード、網羅性、暗号実装の正しさ、安全性を証明しない。

crashを見つけたらartifact入力を保持し、`cargo +nightly-2026-09-21 fuzz tmin <target> <input>`で最小化する。原因と期待される受理/拒否を確認し、最小入力を通常のnative/Wasm共通回帰試験へ戻してからartifactを閉じる。署名付きfixtureが壊れて拒否されただけの入力は不具合としない。

## 2026-09-23のローカル実行

| target | 固定時間 | 実行回数 | seed数 | 結果 |
| --- | ---: | ---: | ---: | --- |
| registration | 25秒 | 268,184 | 42 | crash/timeoutなし |
| assertion | 25秒 | 363,762 | 4 | crash/timeoutなし |
| metadata | 25秒 | 259,561 | 43 | crash/timeoutなし |

実測はmacOS arm64のnightly Rust 1.100.0、cargo-fuzz 0.13.2、libfuzzer-sys 0.4.13。並列3 targetが示すpeak RSSは各最大560 MiB。シンボライザー起動警告が出たためpanic stack traceのsymbolicationはできないが、終了状態・fuzzer統計は正常だった。初回はAddressSanitizer有効で各targetをビルド・実行しており、UBSanの実行は主張しない。

続けてAddressSanitizerの既定設定（同nightly/cargo-fuzz）でも3 targetを各10秒実行した。registration 88,391回/seed 42/peak RSS 476 MiB、assertion 111,850回/seed 4/511 MiB、metadata 89,231回/seed 43/440 MiBで、crash・timeout・Sanitizer報告なし。2回の測定は同じmachineryでも実行時間・メモリーを独立に記録した。

このfixture群はattestation/MDSの受理・拒否ベクトルであり、暗号署名された信頼連鎖に対する網羅的なmutation corpusではない。第三者レビュー・長期fuzz継続・実認証器互換性はWG-06/09等の別課題として残る。
