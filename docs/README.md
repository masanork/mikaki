# 設計文書の案内・決定状態

2026-09-23 / 文書案内。機能や新しい設計の採用を意味しない。

## 文書の役割

ADRは「何を、なぜ選んだか」という長期的な決定を記録する。分野別仕様は「現在どのように動くべきか」を記述する。実装基準は仕様への入口と実装順を示す。設定ファイルは運用値の正本、試験は特定条件での成立の証拠であり、ADRや仕様を自動的に変更するものではない。

新しい文書という理由だけで過去の合意を上書きしない。ユーザーの明示的な決定が最優先であり、会話合意が未ADR化の場合はその記録を補う。ADRがないことだけを理由に決定を取り消したり、再承認を繰り返し要求したりしない。

文書の状態は「採用済みの決定」「実装案」「推奨案」「将来構想」と、別軸の「未実装／ローカル検証／実環境検証」を分けて読む。Draftは文書全体の成熟度であり、そこに引用された採用済みADRまで未決に戻す意味ではない。

## ADRの現状

| ADR                                                   | 採用済みの決定                                                | 主な具体化先                                              |
| ----------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------- |
| [0001](adr/0001-common-account.md)                    | 共通アカウント、アプリ主体の分離、Vaultとの境界               | implementation-spec、oidc-identity-and-keys               |
| [0002](adr/0002-oidc-from-first-release.md)           | 初期からOIDC Code＋PKCE、UXを複雑にしない                     | oidc-login、oidc-login-flow                               |
| [0003](adr/0003-session-lifecycle.md)                 | 保持期限、失効反映の上限、ログアウト範囲                      | session-lifecycle、oidc-store-contract                    |
| [0004](adr/0004-runtime-policy-configuration.md)      | 運用値の外部化、既存状態への適用規則                          | runtime-configuration、config/runtime-policy.example.toml |
| [0005](adr/0005-invitation-bootstrap-and-recovery.md) | 招待制、初回管理者bootstrap、初期の紛失復旧なし               | 登録実装・統合設定                                        |
| [0006](adr/0006-compact-portable-webauthn.md)         | mikaki継続、コンパクトさ最優先、native/Wasm共通WebAuthnコア | crates/webauthn/README                                    |
| [0007](adr/0007-packed-self-attestation.md)           | none既定を維持しES256 packed selfの検証を追加                 | crates/webauthn、local/conformance                        |
| [0008](adr/0008-webauthn-conformance.md)              | Conformance全通過を完成条件とし、製品既定と検証能力を分離     | crates/webauthn、local/conformance                        |
| [0009](adr/0009-rust-oidc-and-worker-stack.md)        | OIDC状態機械・Worker adapterはRust、ブラウザ境界はTypeScript 7 | implementation-spec、oidc-implementation-readiness       |
| [0011](adr/0011-d1-runtime-policy.md)                 | 運用設定の有効版をD1で管理し、検証後に原子的に切り替える      | runtime-configuration、Worker設定loader                   |

0004は0003の数値を変更可能な既定値として補足する。0002は0001当時に保留していたOIDC採用を確定する。旧ADRの理由は残し、後続決定への参照で関係を示す。

通常署名をRSA既定にしないこと、互換RSA/SHA-1の実装を許容すること、crypto agilityは会話で明示された方針だが、独立ADRはまだない。UUID/pairwise sub、private_key_jwt、不透明Access Token等は後続の実装基準に整理されているが、決定理由・代替案のADR記録は追いついていない。Svelte/i18n/CI文書は推奨案を含む。一部を適用した[ローカル実装](../local/README.md)と、未実装の推奨事項を区別する。

ADRは仕様書ごとに一つ作る必要はない。次に追加すべき対象は、識別子の安定性、署名/互換/PQC移行、初期OPプロファイル、フロント/i18n/CIの選択など、変更時に構造や利用者との契約へ影響する決定。timeoutの微調整ごとにADRを増やさない。新しい決定では状態・背景・代替案・理由・不利益・関連仕様を残す。

## 各文書の担当範囲

RP実装者が最初に読む文書は[RP向け接続手順](rp-integration.md)です。RPの登録操作は[RP client operations](rp-client-operations.md)、セッション照会の詳細は[RP session check](rp-session-check.md)に分けています。

| 文書                                                                               | 役割・現在の状態                                                                                |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| [implementation-spec](implementation-spec.md)                                      | 全体の段階・信頼境界・認証core・後続機能の実装案。全分野を無条件に上書きする文書ではない        |
| [oidc-implementation-readiness](oidc-implementation-readiness.md)                  | 初期OIDCの実装基準・依存評価・公開条件の索引。ADRの代用ではない                                 |
| [oidc-login](oidc-login.md)                                                        | ADR 0002に基づくログインUXと初期プロファイル                                                    |
| [session-lifecycle](session-lifecycle.md)                                          | ADR 0003の採用済みセッション契約。運用値は0004で可変                                            |
| [runtime-configuration](runtime-configuration.md)                                  | 設定の型・検証・適用・履歴。数値の正本は統合TOML                                                |
| [identifier-policy](identifier-policy.md)                                          | ID選択の比較・表現。OIDC初期選択は実装基準で絞込み済み                                          |
| [oidc-identity-and-keys](oidc-identity-and-keys.md)                                | subject対応・鍵運用。旧候補の記述を含む                                                         |
| [crypto-agility](crypto-agility.md)                                                | 合意した暗号移行の条件、通常方式と互換方式の分離                                                |
| [webauthn-fit-gap-todo](webauthn-fit-gap-todo.md)                                  | webauthn-rs比較に基づく品質改善TODO。優先順位・完了条件を記録し、機能追加の採用決定とは区別する |
| [webauthn-ceremony-contract](webauthn-ceremony-contract.md) | 信頼入力、設定検証、auth/storeの責務と保存ポリシーの制約（WG-02） |
| [webauthn-device-compatibility](webauthn-device-compatibility.md) | 実機と仮想認証器を区別した端末・ブラウザー試験の記録（WG-06） |
| [webauthn-fuzzing](webauthn-fuzzing.md) | seed、fuzz target、実行条件と結果（WG-05） |
| [webauthn-security-review](webauthn-security-review.md) | 第三者レビューの対象境界・問い・既存証拠。外部レビュー実施記録ではない（WG-09） |
| [webauthn-attestation](webauthn-attestation.md) | attestation受理ポリシー、検証済み証跡と保証の範囲（WG-03） |
| [webauthn-mds-operation](webauthn-mds-operation.md) | MDS検証結果と将来の更新アダプターの責務（WG-07） |
| [webauthn-errors](webauthn-errors.md) | native/Wasm共通の診断コード、JS/HTTP境界、ログの情報制限（WG-01） |
| [webauthn-extensions](webauthn-extensions.md) | 拡張の要求・結果・保存、構造検査と署名・意味の保証範囲（WG-04） |
| [oidc-login-flow](oidc-login-flow.md)                                              | HTTPとログイン取引の実装案                                                                      |
| [oidc-access-token-and-userinfo](oidc-access-token-and-userinfo.md)                | token用途・形式・UserInfoの実装案                                                               |
| [oidc-store-contract](oidc-store-contract.md)                                      | 業務原子操作の実装案。SQL模型は一部だけローカル検証済み                                         |
| [oidc-operations](oidc-operations.md)                                              | 制限・再送・障害復旧の実装案。運用実績ではない                                                  |
| [frontend-and-ci](frontend-and-ci.md)                                              | Svelte/i18n/品質計測の推奨案                                                                    |
| [personal-vault](personal-vault.md)、[federated-messaging](federated-messaging.md) | 合意した将来方向と候補。G2以降の詳細をP0へ持ち込まない                                          |
| [storage-api](storage-api.md)、[vault-claim-sharing](vault-claim-sharing.md)          | 共通blob基盤とFileNodeの設計案、Vault属性の限定的なシステム共有案。API・AuthZEN profileは未決 |

運用設定の実行時の正本は[設定契約](runtime-configuration.md)で定めるD1有効版とし、[runtime-policy.example.toml](../config/runtime-policy.example.toml)は初期投入・編集の見本とする。旧3断片は説明用であり、mergeして使わない。SQLとPythonは設計検証用で、本番のmigration/設定loaderではない。

Cloudflareへの公開手順は[デプロイ文書](cloudflare-deployment.md)、SBOM・CBOM・ビルド証跡の対象と検証手順は[供給網証跡](supply-chain.md)に記録する。

## 矛盾の扱い

明示的な合意と採用済みADRの契約を維持し、個別仕様は上記の担当範囲で具体化する。同じ内容を索引へ転載した場合は個別仕様への参照を添える。初期OIDCの旧候補を実装基準で選択済みの場合も、合意済みの保証を黙って変更しない。

数値は統合TOMLを参照し、意味・不変条件は分野別仕様で定める。文書と設定が異なっていた場合は、単に最新ファイルを勝たせず、変更理由を確認して修正する。今回、理由なく増えていたWebAuthn body上限128 KiB・credential上限16を先行仕様の64 KiB・10へ戻し、WebAuthnの深さ8を一般JSONの深さ16と分けた。

## 実装開始前レビューで残ったもの

| 論点                        | 必要な時点           | 現在の整理                                                                               |
| --------------------------- | -------------------- | ---------------------------------------------------------------------------------------- |
| 最初の縦切り実装            | 直ちに               | 一つのRPで登録→Passkey認証→code交換→アプリsession→logout。Vault/連合/MCPは含めない       |
| crypto/JOSEとD1の実現性     | 本番schema固定前     | 小さなNative/Wasm・原子性spikeを先に行う。文書だけでライブラリ適合を確定しない           |
| 登録招待・管理者bootstrap   | 登録実装前           | ADR 0005で方針確定。CLI・登録確定と権限付与の原子操作を実装する                          |
| 全credential紛失            | 公開前               | ADR 0005で初期復旧なしを確定。UIへ説明し、別accountへの再登録と復旧を混同しない          |
| issuer/RP ID/本番origin     | 本番credential発行前 | 長期的に維持する実値が必要。仮ドメインでの隔離spikeは先行可能                            |
| 停止・退会・保存/監査保持   | 公開前               | 最小のaccount停止と、永久削除・再登録の扱いを分ける。全削除UIは最初のspikeの前提ではない |
| 初期OP適合範囲・Svelte/i18n | 対象実装の着手前     | 採用する範囲を短いADRへ記録。全面認証取得を初期要件へ追加しない                          |

80項目の外部設定は運用の柔軟性のために保持するが、全項目を日常調整するUIは不要。基本設定・高度設定・固定の安全性条件を説明上分け、Rust型からschema/検証を揃える。Pythonとの二重保守は移行期の照合に限定する。

簡素化候補は、初期の通知dispatcherを単一系統にすること、履歴グラフ・長時間mutation等を後続CIへ回すこと、不要なAPI型生成基盤を先行導入しないこと。5分以内の失効反映とoutbox永続性は採用済みなので、この整理だけで削らない。規模と負荷を見ずに多重dispatcher・汎用鍵provider・自動復旧システムを一度に実装する必要はない。
