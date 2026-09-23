# mikaki-webauthn

native/Wasmで共有するWebAuthn検証コア。[ADR 0006](../../docs/adr/0006-compact-portable-webauthn.md)のコンパクトな実装方針と、[ADR 0008](../../docs/adr/0008-webauthn-conformance.md)の公式Conformance完成条件に従う。

## 境界と対応範囲

`register` / `authenticate`は、信頼された呼び出し側から渡されたchallenge・origin・RP IDとceremony policyを検証し、外部から構築できない検証結果を返す。HTTP、DB、時計、乱数、OIDC、Vaultには依存しない。`Context`は保存済み取引とサーバー設定から組み立て、credential応答から設定を採用しない。

- credential署名: ES256、Ed25519、RS256、互換用途のRS1。既定のallow-listはES256のみ。保存公開鍵はbase64url COSE。
- attestation: none、packed self/full、FIDO U2F、TPM 2.0。証明書付き方式は明示的に与えられた信頼情報がなければ拒否する。
- UP必須、UV required/preferred/discouraged、identified/discoverable認証、account・allow-list・userHandleの照合、backup/counter、拡張CBORの構造検査と認証署名への包含、厳密なJSON/CBOR/COSE境界。
- 証明書: 署名・アルゴリズムと鍵の対応、時刻、issuer/subject、CA/key usage/path length、重複、critical extension、packed/TPM固有属性を検証する。TPMの公開鍵・extraData・certified nameは構造を解析して照合する。
- MDS: ES256 BLOBの署名、設定されたroot SPKIまでのチェーン、署名付きCRLの期限・失効、`iat`、BLOB番号、任意の`nextUpdate`、AAGUID/U2F key identifier、status reportを検証・保持する。HTTP取得とstatefulな更新はコア外（[運用境界](../../docs/webauthn-mds-operation.md)）。

`Context.attestation`には検証時刻と、認証済みのmetadataを渡す。`attestation_hint`は検索用の未検証ヒントであり、認証の証拠ではない。コアが改めてAAGUIDまたはU2F certificate key identifierを照合する。試験用rootは製品コアに含めない。

呼び出し側は、取引の目的・ブラウザーとの結び付き・期限・未消費、credentialの所有者を確認し、検証後のチャレンジ消費とcredential保存・更新を原子的に確定する。製品の既定はES256・UV required・discoverable・attestation要求noneのまま。

## 検証済みの範囲

2026-09-22、公式FIDO2 Server Conformance Tools 1.9.1の**必須155件をnative/Wasm両方で全通過**。before-all失敗による未到達はない。追加OPTIONAL項目14件は未選択。正式認証の申請・提出は行っていない。[実行条件と結果](../../local/conformance/results-2026-09-22.md)。

```sh
cargo test --locked -p mikaki-webauthn
wasm-pack test --node crates/webauthn --locked
```

同じ24テストと型境界のcompile-fail 4件を両ターゲットで実行する。独立したPython cryptography/OpenSSL fixtureでpacked/U2F/TPM、証明書の信頼・改変、MDS署名・CRL・失効・期限を確認する。fixtureに秘密鍵や公式Suiteのコードを保存しない。既存CIがこの回帰試験を実行する。公式GUI Suiteは[ローカル専用アダプター](../../local/conformance/README.md)で別途実行する。

## 限界と次の品質改善

汎用Web PKI validatorではない。name constraints、policy mappings/constraints/inhibitAnyPolicyや未処理critical extensionは拒否する。MDS検証は状態を持たず、永続snapshot、BLOB番号の高水位、定期更新、障害時の運用通知、statusのfirmware別適用は実装していない。製品はMDSを有効にしていない。クロスオリジンiframe、追加optionalアルゴリズム・platform attestationは未対応。legacy tokenBindingは構造を検査するがTLS Token Binding機能を提供しない。

次はパーサーのfuzzing、実認証器・複数ブラウザーでの相互運用、コア単体のサイズ・性能測定とAPIレビューを行う。Conformance成功をセキュリティ監査やwebauthn-rsに対する優位性の証明とは扱わない。

拡張ごとの要求・結果・保存と保証範囲は[拡張対応表](../../docs/webauthn-extensions.md)を参照する。構造検査と拡張固有の意味の検証は区別する。

内部エラーの理由コードと公開応答の境界は[診断契約](../../docs/webauthn-errors.md)を参照。`Invalid`は入力値を含まない列挙型で、native/Wasm共通の`code()`・`stage()`を提供する。

登録・認証入口では`Context::validate()`を必ず実行する。設定検証と呼び出し側の責務は[ceremony契約](../../docs/webauthn-ceremony-contract.md)を参照。

`Context.attestation_policy`の`required_trusted`はnone/selfを拒否する。既定は`optional`。登録結果は方式・保証区分・metadata識別子・検証時刻・信頼anchor指紋を返す。[attestation契約](../../docs/webauthn-attestation.md)を参照。

独立fixtureでseedする入力変異試験と実行範囲は[fuzzing記録](../../docs/webauthn-fuzzing.md)を参照。
