# ADR 0007: ES256 packed self-attestationの検証を追加する

2026-09-22 / 採用。公式Suite接続後の最小限の対応拡張。

## 背景と決定

ADR 0006のコンパクトさを維持しながら、初期のnone限定検証へES256 packed self-attestationを追加する。ブラウザーへ送る製品のattestation既定値はnone、署名方式はES256、UP/UV必須を維持する。none以外をすべて拒否する従来の受入範囲は、この決定でselfに限って拡張する。

[WebAuthnのpacked検証手順](https://www.w3.org/TR/webauthn/#sctn-packed-attestation)に従い、credentialのCOSE algとattStmt.algがES256で一致すること、credential公開鍵でauthenticatorDataとclientDataHashの連結に対するDER署名を検証できることを要求する。既存p256を利用し、新規依存を追加しない。

証明書/MDSの信頼検証は追加しない。x5cが存在する場合は、空配列やnullでもselfへフォールバックしない。初期のpacked attStmtはalg/sigのみを受け付け、ECDAAや未知フィールドも拒否する。selfの成功はcredential秘密鍵の所持を示すもので、認証器の出自・機種・信頼性の証明ではない。

## 代替案と影響

none限定を維持すると、selfに必要な暗号処理が既にあっても入力を扱えない。packed fullとMDSまで一度に追加すると、証明書・信頼ストア・ネットワーク処理へ範囲が広がる。まずselfのみを独立して検証する。

試験点数だけを目的にattestationをnoneへ変換したり、UVを解除したりしない。全Suite適合は未達であり、この追加だけで認証試験の全前処理を通過できるとは仮定しない。

受入試験はnative/Wasmの同じテストで正常署名、方式不一致、DER形式、署名改変、必須フィールド欠落、x5c/ECDAA/重複キー、raw clientDataとauthDataへの結び付きを確認する。公式Suiteでの結果はlocal/conformance以下へ別途記録する。
