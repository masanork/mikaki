# ADR 0008: WebAuthnの完成条件を公式Conformance全通過とする

2026-09-22 / 採用。ユーザーの明示的な全通過方針に基づく。

## 決定

FIDO2 Server Conformanceを一部プロファイルの参考測定に留めず、必要項目を除外しない全通過をWebAuthn実装の完成条件とする。正式認証の申請・結果提出は別途判断する。2026-09-22にTools 1.9.1の必須155件をnative/Wasm双方で全通過した。追加OPTIONAL 14件は対象外。結果・条件は[測定記録](../../local/conformance/results-2026-09-22.md)に残す。

製品の既定値と検証器の能力を分ける。製品はES256・UV required・discoverable・attestation要求noneを維持する。検証器は保存済みceremonyの信頼された設定としてUVのrequired/preferred/discouraged、許可方式、アカウント指定とdiscoverableの区別を受け取る。credential応答の自己申告で設定を変えない。

アカウント指定の場合、取引に保存されたuser handleとallow-listの両方にcredentialを結び付ける。userHandle省略を許すのはこの場合のみで、存在すれば一致必須。discoverableでは引き続き省略を拒否する。UPは全ポリシーで必須とし、結果には実際のUVフラグを返す。

ES256に加えEd25519、RS256、互換用途のRS1検証をnative/Wasm共通で追加する。署名・公開鍵の形式と方式を対応付け、サーバー設定のallow-listから外れた方式を拒否する。RSAを既定にしない。RS1の許可を一般のトークン署名や鍵生成へ波及させない。

格納公開鍵は方式を含むCOSEへ統一する。未運用のローカルDBは再作成し、以前のSEC1保存形式の互換パーサーを追加しない。

## 実装順

1. ポリシーと鍵形式、追加署名方式を共通コアで実装する。
2. 証明書付きpacked/U2F、TPM、必要なplatform attestationを追加する。証明書・TPMの構造を正しく解析し、単なるバイト列検索を検証の代わりにしない。
3. MDSの署名・信頼パス・失効情報・有効期限を検証する。HTTP取得とキャッシュはアダプターに置き、コアには時刻と検証に必要なデータを明示的に渡す。テスト用ルートを製品の信頼アンカーに混ぜない。
4. 全Suiteの成功をnative/Wasmで確認し、不具合を独立した回帰試験へ戻す。前処理失敗による未到達や任意項目を結果に残す。

iwatoの検証と試験資産を参考にするが、native限定RSAやコア内部の時計・ネットワーク依存は引き継がない。既存実装を移植しただけで正しいと判断しない。

## 依存と検証

2026-09-22にregistryで確認したed25519-dalek 3.0.0、sha1 0.11.0、rsa 0.10.0-rc.18を固定する。RSAは正式版ではなくRCであり、現在のRustCrypto digest/signature/crypto-bigint世代と組み合わせて評価する。公開前の安定版・保守状況確認は残る。乱数・秘密鍵演算をWebAuthnの検証経路へ導入しない。

OpenSSL（Node crypto）で独立生成した公開鍵・署名ベクトルを保存し、正常署名と改変拒否をnative/Wasmで確認する。秘密鍵はfixtureに保存しない。

### RSA監査指摘の適用範囲

`cargo audit`はRUSTSEC-2023-0071（Marvin、秘密鍵演算からのタイミング漏洩）を報告する。2026-09-23に確認したRustSecの記録では、現行の`rsa 0.10.0-rc.18`を含め修正版なし。今回のコードは`RsaPublicKey`と`pkcs1v15::VerifyingKey`だけを使い、RSA秘密鍵を生成・読込・保存・使用しないため、漏洩対象の秘密鍵操作はない。この用途限定の判断を`.cargo/audit.toml`に記録する。監査が無指摘だったとは扱わない。RustSecの記録とRustCryptoの対応状況を定期的に再確認する。

RSAの署名・復号・鍵生成を導入する場合は、この除外判断を必ず再評価し、原則としてadvisory解消まで秘密鍵操作を採用しない。他のadvisoryは除外しない。参照: [RustSec RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)、[RustCrypto RSA issue #626](https://github.com/RustCrypto/RSA/issues/626)

## 完了した実装と範囲

none、packed self/full、U2F、TPM 2.0を同じRust検証経路に実装した。証明書チェーン、時刻、Basic Constraints、key usage、critical extension、AAGUID、TPMの公開鍵・extraData・certified nameを検証する。TPMのBMPString通知文もDERとして解析する。信頼アンカーは中間CAと区別し、明示的に信頼したX.509 v1 rootにも対応する。

MDS 3.1.1はES256 BLOBと設定されたroot SPKI、署名付きCRL、必須`iat`、BLOB番号、任意`nextUpdate`、statusReportsを検証・保持する。HTTPと試験データの保存はlocal/conformanceに置く。コアはネットワークや永続状態を持たず、test rootも含まない。製品向けの定期更新・永続キャッシュ・BLOB番号のロールバック防止は今後の運用統合で実装する。

証明書処理はx509-cert 0.3.0、der 0.8.2、P-384署名検証はp384 0.14.0を用いる。フルWeb PKIの汎用化はせず、未対応の名前・ポリシー制約を拒否する。Python cryptography/OpenSSLによる独立した公開fixtureで、登録とMDSの正常・異常系をnative/Wasm共通CIへ追加した。追加OPTIONAL方式や正式認証を達成済みとはしない。

仕様の基準は[WebAuthn Level 3 Recommendation (2026-08-25)](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/)と[FIDO MDS 3.1.1 Proposed Standard](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html)。
