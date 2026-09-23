# Attestationの受理ポリシーと検証結果

2026-09-23 / WG-03。共通コアの明示的な必須モードと証跡を実装。製品の通常登録でattestationを必須にする変更ではない。

## 要求・信頼情報・受理条件を分ける

ブラウザーへ渡す`attestation`はconveyanceの希望であり、サーバーが結果を受理する条件とは別である。none/selfには認証器の出自を判断するための証拠がなく、RPは登録時に受理可否を判断する。[WebAuthn Level 3 §5.4.7](https://www.w3.org/TR/webauthn-3/#enum-attestation-convey)、[§6.5](https://www.w3.org/TR/webauthn-3/#sctn-attestation)、[§7.1](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)を参照（2026-09-23確認、2026-08-25 Recommendation）。

`Context.attestation`は検証用の信頼情報と時刻であり、それを渡すだけではnone/selfを拒否しない。受理条件は別の`Context.attestation_policy`で選ぶ。

| ポリシー | none / packed self | 証明書付きpacked / FIDO U2F / TPM |
| --- | --- | --- |
| `optional`（省略時の既定） | 方式ごとの検証に成功すれば受理 | 認証済みmetadataとの照合、証明書パス、署名等の全検証に成功した場合だけ受理 |
| `required_trusted` | 拒否。正しいself署名でも要件を満たさない | 同じ全検証に成功した場合だけ受理 |

不正な証明書付きattestationをselfやnoneへ格下げして受理しない。信頼情報の欠落・失効扱い・anchor不一致でも失敗する。未対応方式も両モードで拒否する。必須要件を満たさないnone/selfは内部理由`attestation_policy`となる。既存の署名・証明書等の不正は、その検証段階の理由を返す。

このポリシーは登録専用であり、認証assertionから過去のattestationを再検証するものではない。通常のローカルOPはES256、UV required、discoverable、ブラウザーへのattestation要求none、サーバーポリシーoptionalを維持する。認証器の出自を制限する製品用途では、発行時にrequired_trustedを保存し、適切なconveyance要求・信頼情報・保存と再評価の運用を組み合わせる。

## 登録結果

`VerifiedRegistration.attestation()`は`AttestationEvidence`への参照を返す。Rustでこれらの証跡は外部から構築・Deserializeできず、全検証と受理ポリシーを通過した登録だけが返す。JSでは登録結果の`attestation`フィールドへserializeされる。HTTPから受け取った同形のJSONを検証結果として扱ってはならない。

| フィールド | 内容と保証 |
| --- | --- |
| `format` | 実際に検証した`none` / `packed` / `fido-u2f` / `tpm` |
| `kind` | `none` / `self` / `trusted`。本実装の保証区分であり、Basic/AttCA/AnonCAを厳密に分類した値ではない |
| `aaguid` | authenticatorDataの16 byteをcanonical base64urlで表現。none/selfでは認証器の出自の証拠にしない。U2Fではゼロ値 |
| `trust` | none/selfはnull。証明書付き方式の全検証成功時だけ下記を持つ |
| `trust.metadata_key` | 実際に照合したmetadata識別子。packed/TPMはbase64url AAGUID、U2Fは既存のSHA-1 certificate key identifierを小文字hexで表現 |
| `trust.anchor_sha256` | パス検証が成功した信頼anchorのDER証明書全体のSHA-256、canonical base64url。直接信頼するbatch証明書ならその証明書の指紋 |
| `trust.verified_at` | 検証に使用したサーバー指定のUnix秒。コアが取得した時計や有効性の将来保証ではない |

anchorの指紋は実際に成功したパスから取得し、設定リストの先頭や未検証の`attestation_hint`から推測しない。metadata識別子とanchorは、与えられた信頼情報に対する照合結果である。公式MDSから取得したこと、特定のMDS BLOB番号、端末個体、現在の継続的な安全性を証明する値ではない。

証明書列・生の応答は結果へコピーしない。登録結果全体を既定の診断ログへ出さない。現行ローカルOPは出自制限を利用せず、追加証跡をDBに永続保存しない。将来の失効・firmware等の再評価に必要な保存項目とMDS更新運用はWG-07の対象であり、この最小証跡だけで対応済みとは扱わない。

## 試験と範囲

native/Wasm共通試験で、信頼情報を渡したoptionalのnone/self受理とrequired_trustedの拒否を確認する。独立生成のpacked/U2F/TPMの全fixtureを必須モードでも評価し、既存の不正・失効・binding変更の拒否を維持する。成功時はformat・metadata識別子・時刻・anchor指紋を照合し、直接信頼するbatch証明書の指紋も確認する。

compile-fail試験で証跡の構築とDeserializeを禁止し、JS試験でWasm境界の証跡・信頼情報欠落・未知ポリシー拒否を確認する。通常登録・ログイン等のブラウザー試験は既定ポリシーで実行する。公式FIDO GUI Suiteは今回再実行していない。
