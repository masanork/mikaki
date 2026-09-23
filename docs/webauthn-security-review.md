# WebAuthn第三者レビュー用ブリーフ

この文書は第三者レビューを依頼するときの範囲と確認事項を揃えるためのブリーフであり、レビューや監査の実施記録ではない。対象revisionと外部レビュー担当者が確定した時点で、結果を末尾の記録欄へ追加する。

## 対象範囲

優先度順に次の境界を確認する。

1. **Ceremony・credential検証:** [`crates/webauthn/src/lib.rs`](../crates/webauthn/src/lib.rs)、`key.rs`。challenge、origin、RP ID、UP/UV、credential/user handle、allow-list、counterの結合と、再利用・取り違え拒否。
2. **Attestationと証明書信頼:** `attestation.rs`、`attestation/tpm.rs`、`certificate.rs`。packed/U2F/TPM 2.0の署名対象、証明書パス、trust anchor、期限・critical extension・TPM構造の検証。一般Web PKI全体を実装したものと誤認させない失敗動作。
3. **MDS:** `metadata.rs`。BLOB署名、root pin、CRL署名・期限・失効、entry選択、BLOB番号の意味と、未実装の永続snapshot・rollback防止との境界。
4. **Store・ceremony lifecycle:** 製品アダプターのtransaction、challenge一回性・期限、失敗時のrollback、複数instance／永続環境での整合性。現在のMDS運用TODOや製品store契約を含め、in-memory test adapterと本番保証を区別する。
5. **Native/Wasm境界:** Worker/Wasm入口のJSON上限・深さ制限、結果/error変換、秘密情報・attestation情報のログや診断への流出。

## レビューで答えてほしいこと

- 攻撃者制御のCBOR、DER/X.509、TPM値が、上限・長さ・深さを迂回したpanic、過剰計算、曖昧な受理を起こさないか。
- クライアント入力から認証ポリシー、信頼アンカー、credential所有者を上書きできないか。challenge再利用、期限切れ、counter rollbackが抜け道にならないか。
- 証明書パスとMDS/CRLの不完全・期限切れ・失効・不一致状態を、trustedとして誤認しないか。
- native/Wasmと製品storeの間で、同じ入力が違う信頼判断や副作用を起こさないか。
- 明示された非対応仕様、RSA advisoryの除外判断、製品化前のMDS運用TODOに、追加の重大リスクがないか。

## 既知の設計境界

- 製品既定はES256、UV required、discoverable credential、attestation要求none。attestationの受け入れ能力は既定ポリシーと分離する。
- WebAuthn coreにHTTP、時計取得、DB、MDS取得を持ち込まず、それらは呼び出し側から明示的に渡す。
- MDSは検証coreがBLOB/CRLを検証する。製品の永続snapshot、番号高水位、原子的更新は未実装であり、製品でMDSを使う前に別途完了させる。
- `RUSTSEC-2023-0071`はRSA公開鍵検証のみで秘密鍵演算を行わない用途限定判断として除外中。RSA秘密鍵機能を導入する場合は除外を再審査する。判断根拠は[ADR 0008](adr/0008-webauthn-conformance.md)。
- 必須FIDO Server Suite 155件の通過記録、OPTIONAL項目、正式認証、実機網羅、第三者レビューは別の証拠である。

## 既存の内部証拠

- [ADR 0008とRSA advisoryの適用範囲](adr/0008-webauthn-conformance.md)
- [FIDO適合・fit-gap一覧](webauthn-fit-gap-todo.md)
- [fuzz手順と実行範囲](webauthn-fuzzing.md)
- [ceremony契約](webauthn-ceremony-contract.md)、[attestation契約](webauthn-attestation.md)、[MDS運用境界](webauthn-mds-operation.md)
- CIはpush/PRごとに`cargo audit --file Cargo.lock`と`npm audit --audit-level=low`を実行し、DependabotはCargo、npm、GitHub Actionsを週次確認する。
- 2026-09-23に新しいRustSec advisory databaseで129 Rust依存をscan。`.cargo/audit.toml`に記載した`RUSTSEC-2023-0071`以外の指摘なし。npm auditは0 vulnerabilities。これは依存advisory scanであってコードレビューではない。

## 脆弱性報告の受付

公開先のGitHub Security Advisoriesによるprivate vulnerability reportingが有効か、または専用security連絡先を設けるかは未確定。実際に受付可能な経路を公開前に設定し、ここへURLまたは連絡先と確認日を記録する。未設定の連絡先を推測して案内しない。

## 外部レビュー記録

外部レビューは未実施。依頼・受領後、以下を記録する。

| 項目 | 記録 |
| --- | --- |
| 対象revision（commit） | 未設定。このworkspace checkoutにはGit metadataがないため、review対象を固定できていない |
| reviewer / 実施日 | 未実施 |
| 範囲・方法・除外範囲 | 未実施 |
| 指摘と重大度 | 未実施 |
| 対応commit・残余リスク | 未実施 |
| 脆弱性報告経路と確認日 | 未設定 |

内部テスト・advisory scan・FIDO Conformance通過を、外部監査済みまたは無指摘という表現へ置き換えない。
