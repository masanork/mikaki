# WebAuthnの診断エラーと公開応答

2026-09-23 / WG-01。native/Wasm共通コアとローカルOPへの実装契約。

## 共通コア

`Invalid`はデータを持たない列挙型で、`code()`と`stage()`が安定した診断文字列を返す。`Display`も理由コードだけを返し、生の入力、識別子、鍵、署名、証明書を保持しない。コアにロガー・HTTP・時計・相関ID生成を持ち込まない。コードの正本は[error.rs](../crates/webauthn/src/error.rs)。新しい分類を追加しても既存コードの意味を変更しない。

| stage | code | 検査対象 |
| --- | --- | --- |
| configuration | `configuration` | 信頼設定の形・上限・方式一覧・identified認証の指定 |
| input | `input`, `limit` | 入力形式、サイズ・深さ等の上限 |
| client_data | `client_data_type`, `challenge`, `origin` | ceremony種別、challenge、origin/crossOrigin/topOrigin |
| authenticator_data | `rp_id`, `user_presence`, `user_verification`, `backup`, `counter` | RP ID hash、UP/UV、backup状態、counter |
| credential | `credential`, `user_handle`, `allow_list` | credentialの照合、userHandle、許可リスト |
| key | `public_key`, `algorithm` | 公開鍵の構造・方式、許可アルゴリズム |
| signature | `signature` | 暗号署名の検証 |
| extensions | `extensions` | 拡張CBORの構造・識別子・末尾。個別拡張の意味の保証ではない |
| attestation | `attestation`, `attestation_policy`, `trust`, `tpm` | attestation構造、信頼情報・方式、TPM構造とbinding |
| certificate | `certificate`, `certificate_time`, `certificate_path` | 証明書プロファイル、時刻、チェーン・信頼anchor |
| metadata | `metadata`, `crl`, `crl_expired`, `revoked` | MDS構造・署名入力、CRLの存在・対応範囲・時刻、失効・利用拒否 |
| ceremony | `ceremony_purpose`, `browser`, `ceremony_expired`, `ceremony_consumed`, `ceremony_attempts` | 用途、browser binding、期限、消費済み、試行回数 |

コードは最初に失敗した検査を表す。例えば証明書とCRLがともに期限切れなら、証明書の検査が先である。`crl_expired`は期限切れに加え、thisUpdateより前・nextUpdate欠落も含む。`revoked`には信頼entryの`allowed=false`も含む。MDS検証が返すentryの利用可否と、attestation検証がそのentryを拒否する段階は別である。

汎用JSON/base64/CBORの失敗は、呼び出し元の詳細理由に達する前に`input`となる場合がある。拡張CBORの深さ超過等は`extensions`にまとめる。鍵や証明書の検証から返る下位の署名エラーは保持するが、複数anchor探索の最終失敗は`certificate_path`にまとめる。すべてのパーサー内部事情や候補anchorの失敗一覧を提供するAPIではない。WG-01は検証の受理・拒否条件を変えない分類変更。後続のWG-02では[信頼設定の検査](webauthn-ceremony-contract.md)を追加した。

## JS・HTTP・ログの境界

| 境界 | 扱い |
| --- | --- |
| native Rust | `Result<_, Invalid>`。呼び出し元が公開応答とログを選ぶ |
| 内部Wasm/JS | `register`/`authenticate`/attestation・MDS関数は失敗時にJSON文字列`{"code":"challenge","stage":"client_data"}`等をthrowする。HTTP応答として転送しない |
| ローカルOPのcredential検証 | 詳細理由・credential検索失敗を400 `{"error":"invalid_credential"}`へまとめる |
| OPの外側の入力・CSRF・ceremony状態検査 | 既存の固定エラー対応を維持。全endpointの全失敗を一種類へ統一する変更ではない |
| Conformanceアダプター | 既存の汎用エラー応答を維持。内部例外をHTTPへ直送しない |
| ローカルOPの内部ログ | `event`, `correlation`, `code`, `stage`のみ。`event`は`webauthn_rejected`、相関IDは新規UUID |

[JS側の正規化](../local/webauthn-errors.mjs)は短い文字列だけを受け、Rustの`diagnostic_stage`でコード・段階の組を検査する。任意の例外文、未知コード、不一致の段階は固定の`credential`へ縮退し、余分なフィールドは捨てる。応答本文、challenge、userHandle、credential ID、browser bindingは記録しない。相関IDもそれらから導出しない。内部ログの理由は未検証入力による診断であり、認証成功の証跡ではない。

これによって未登録credentialと署名不正等の詳細を応答本文から推測できないようにする。処理時間まで同一にする保証は追加していない。ログの保管・閲覧権限はアダプター側の運用責務である。

## 検証

native/Wasm共通試験でchallenge/origin/RP ID、flags、counter、署名、入力上限と独立生成の証明書・TPM・MDS fixtureの理由を照合する。auth crateでceremonyの分類を確認する。JS試験は実際のWasm例外と任意文字列の除去を確認し、ブラウザー試験はchallenge/origin改変が同じ公開400応答となり、ログに異なる固定理由だけが残ることを確認する。

この変更では公式FIDO GUI Suiteを再実行していない。既存の155項目通過記録は[Conformance README](../local/conformance/README.md)を参照する。今回の回帰試験と公式Suiteの結果を区別する。
