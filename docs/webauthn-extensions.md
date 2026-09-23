# WebAuthn拡張の対応範囲

2026-09-23 / WG-04。拡張の構造検査、署名による完全性、個別の意味の検証、ブラウザー出力を区別する。追加の拡張型や永続化項目は、利用する機能を採用した時点で定める。

## 共通コアの契約

`authenticatorData`のEDフラグが立つ場合、末尾に拡張識別子を文字列キーとするCBOR mapを要求する。重複キー、サイズ・深さ制限違反、末尾の余剰データを拒否する。EDが立たない場合は拡張用の余剰データを受け付けない。未知の文字列キーと構造的に有効な値は受け入れるが、意味を解釈せず、検証結果や保存用証跡には含めない。

認証では拡張を含むauthenticatorData全体をcredentialの署名で検証する。署名が正しいことは、未知拡張の意味やポリシーを検証したことを意味しない。登録時の完全性はattestation方式に依存する。特に製品既定の`none`はattestation署名を持たず、拡張の構造を受理したことを認証器の出自保証としない。

型の根拠は[WebAuthn Level 3 §5.7.4](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsauthenticatoroutputs)、署名対象とクライアント出力の区別は[§9.5](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-extension-processing)を参照する。

## 要求・結果・保存の対応表

| 拡張・機能 | 現在の要求 | 結果の扱い | 保存・保証 |
| --- | --- | --- | --- |
| `credProps` | 製品の登録画面が`true`を要求 | ブラウザーの`getClientExtensionResults()`で`rk===true`を確認。false・欠落時は登録完了要求を送らない | 結果はサーバーへ送らず保存しない。クライアント互換性条件であり、署名された本人確認・出自の証跡ではない |
| discoverable認証 | `residentKey=required`で登録、認証時のallow-listを省略 | コアは保存済みcredentialとuserHandleの一致を確認 | `credProps`の自己申告をアカウント照合に使わない。credentialの発見可能性の実績は実際の再認証で確認する |
| `credProtect` | 要求しない | 拡張領域にあれば共通の構造検査のみ | 値や保護レベルを検証・保存しない。UV requiredの独立した確認からcredProtect設定を推測しない |
| `prf` / `hmac-secret` | 要求しない | PRF値の取得・鍵導出・比較は未実装 | Vault解除・鍵復旧・PRF対応認証器との表示には利用しない。採用時にクライアント内の秘密保持と失敗時挙動を設計する |
| `largeBlob` / `credBlob` | 要求しない | 読み書き・意味の検証なし | 保存保証なし |
| `appid` / `appidExclude` | 要求しない | AppIDによるRP ID hash検証の切替なし | U2F attestation形式の検証対応とは別。旧U2F credentialのAppID移行に対応したとは扱わない |
| 未知の認証器拡張 | 個別には要求しない | CBOR構造・文字列キーを検査。認証では拡張バイト列も署名検証対象 | 個別の意味を保証しない。値の永続化・外部への返却なし |
| その他のクライアント拡張出力 | 要求しない | コアのRegistration/Assertionへ取り込まない | `getClientExtensionResults()`全体を署名済みデータとみなさない |

`credProps`は[クライアント拡張](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension)である。ブラウザー側の確認は改変可能なクライアント入力の確認に留まる。サーバーがcredentialの所有者・challenge・origin・署名等を検証する責任は変わらない。PRFは[規格の独立した拡張](https://www.w3.org/TR/webauthn-3/#prf-extension)であり、CBOR mapを受け入れるだけでは実装したことにならない。

## 検証と残課題

Rustの登録・認証の共通試験で、非文字列キー・重複キーの拒否、未知拡張の構造的受理、署名後に拡張値だけを変更した認証応答の拒否、検証結果へ拡張の保証を追加しないことを確認する。同じ試験をnative/Wasmで実行する。ブラウザー試験では`rk`欠落・falseでアカウントや招待消費が確定しないこと、その後の正常登録とdiscoverable再認証を確認する。

WG-03のattestation必須ポリシー、WG-05のfuzz、WG-06の実機試験は別の未完了項目。この変更について公式GUI Conformanceは再実行しておらず、既存の155件通過記録を新しい検証結果として更新しない。
