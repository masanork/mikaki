# MDS検証結果と更新境界

sakimoriのMDS検証は署名済みBLOBをオフラインで検査するコア機能であり、製品の定期取得・保存・認証ポリシー適用とは分離する。現行の規範文書は[FIDO MDS 3.1.1 Proposed Standard](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html)。MDSは authenticator metadata と状態報告を含む署名付き一覧を配布する。entryはAAGUIDまたはattestation certificate key identifierで識別され、状態報告には有効日やfirmware version、対象証明書が付くことがある。

`verify_mds`は署名、signer証明書チェーン、渡されたCRLを検証し、必須のJWT header `iat`、BLOB番号、任意の`nextUpdate`、関連する認証器entryを返す。U2F entryは小文字hexの40桁 key identifierで保持する。各status reportは`status`とその他の署名対象フィールドをまとめて保持するため、`effectiveDate`, `authenticatorVersion`, `batchCertificate`, `certificate`, `url`や今後追加される項目を失わない。metadata statementのfirmware versionと`timeOfLastStatusChange`も返す。未知のstatus値はFIDO仕様に従いエラーにせず、その文字列を結果へ残す。現行MDSでは`nextUpdate`は廃止予定であり、存在しない場合も受理する。存在していても鮮度の判定には使わない。`x5u`形式のsigner証明書取得はコアの入力契約に含めていないため、現状は拒否し、x5c形式だけを処理する。

`allowed`は現在の簡易ポリシーである。`USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`, `USER_KEY_REMOTE_COMPROMISE`, `USER_KEY_PHYSICAL_COMPROMISE`, `REVOKED`のどれかが含まれるentry全体をfalseにする。statusが特定versionや証明書だけを対象にする場合も、コアはattestation certificateのfirmware extensionをまだ評価しないため、安全側に全entryを拒否する。詳細statusを保持しても、これをfirmware別の状態評価まで対応済みとはみなさない。FIDO仕様ではstatusごとに関連するfirmware versionや証明書を示せる一方、statusの受入れ方針はRPが定める。[StatusReportと処理規則](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#statusreport-dictionary)

## 将来の取得アダプターが守る更新手順

1. 配布元と全ダウンロード先をアダプターの許可リストで制限する。BLOB内の`x5u`やCRL URLは未検証の入力として扱い、WebAuthnコアにHTTP取得を追加しない。
2. 候補全体を検証し、保存済み番号より大きいBLOB番号を確認する。FIDOの処理規則は、保存済みBLOBと同じか古い番号を拒否する。`iat`と取得時刻を記録し、更新の鮮度・再試行間隔は運用ポリシーで決める。`nextUpdate`を必須の鮮度条件にしない。
3. 全entryの検証が終わってから、番号・期限・entry群を一つのsnapshotとして原子的に置き換える。検証途中のentryを公開せず、番号だけ先に更新しない。
4. 取得や検証に失敗した場合、最後の検証済みsnapshotは変更せず、更新失敗とsnapshotの経過時間を記録する。どの程度古いsnapshotまで新規登録に使うかは製品の明示的な鮮度ポリシーで決める。MDSを必須としないPasskey認証の継続可否は、MDS取得状態から独立した製品ポリシーとする。
5. 更新後のstatusを既存credentialへどう適用するかは別の製品方針とする。MDS更新を理由にcredentialやsessionを自動削除せず、将来、再評価を行う場合は登録時のattestation証跡と当時のmetadata snapshotを保存できる設計が必要になる。

FIDOは2026-08-31から署名BLOBのx5cにGlobalSign R3→R46 cross-certificateを追加し、R46への移行期間に入った。現在のchain長上限6件はこれを収容するが、運用側はR46をtrust storeに追加し、旧R3系の証明書期限より前にanchorを切り替える必要がある。[MDS changelog](https://fidoalliance.org/mds-changelog/)は旧R3系の期限を2029-03-18としている。

現状のコアは永続snapshot、番号の高水位、原子的な入替え、定期取得、障害時通知、既存credential再評価を実装していない。製品はMDSを有効にしておらず、`required_trusted`を使う運用前にこれらを行うアダプターと運用試験が必要。
