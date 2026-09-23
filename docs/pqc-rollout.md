# ML-KEM・ML-DSAの段階導入

2026-09-23時点。PQCの製品機能はまだ有効化していません。[独立probe](../design/probes/pqc/README.md)でML-KEM-768とML-DSA-65のNative/Node Wasm往復、NIST ACVP sample既知解、nobleとの相互運用、Vault data keyのHPKE鍵包みと版取り違え拒否を確認しました。実機到着時のFIDO登録・assertion採取画面と署名検証CLIも用意しました。現在のVault形式・Passkey登録・OIDC署名は変更していません。

| 対象 | 現在 | 次の実装単位 | 有効化の条件 |
| --- | --- | --- | --- |
| Vault | 本人専用のPRF→HKDF→AES-GCM鍵包み。system recipientなし | 鍵directory・秘密鍵保管・Grantを設計し、現行HPKE草案との互換性とブラウザー/Workerでの実行を確認する | 公開鍵の真正性・継続性、標準の鍵配送/AEAD構成、復旧・再包み、独立ベクトル、ブラウザーWasm性能、失敗時の旧版維持 |
| FIDOドングル | 製品登録/検証はES256（COSE `-7`） | 対象ドングルとブラウザーの対応を実測し、ML-DSA-65（COSE `-49`）のCOSE鍵・登録・assertion検証を隔離試験へ追加 | 対応機器で登録と再認証が成功し、改変/取り違えを拒否。既存ES256 credentialとの併存と新旧の登録方針を確認 |
| OIDC/JOSE | 本番client認証はES256。ID TokenはES256/RS256 | RFC 9964のML-DSA JWK/JWS相互運用を独立probeで検討 | RPライブラリ、JWKS/key rotation、HTTP上限、conformance profile、署名鍵保管を確認後にclient単位で明示有効化 |

ML-KEMは共有秘密を成立させる鍵配送であり、Passkey署名方式ではありません。ML-DSAは署名方式であり、Vaultの長期機密性を単独では改善しません。現在のVault本文は既にAES-256-GCMで暗号化され、本人用data keyはPasskey PRF由来の鍵で包まれています。ML-KEMが直接役立つのは、将来の別端末またはsystem recipientへdata keyを配送する境界です。[Vault共有設計](vault-claim-sharing.md)のGrantと公開鍵真正性が先に必要です。独自の「ML-KEM共有秘密をそのままAES鍵にする」形式は採用しません。

## VaultをFIDO実機より先に進める順序

1. UserInfo専用recipientの鍵管理を確定する。公開鍵・鍵ID・suite・発行/停止状態をD1のdirectoryで管理し、秘密鍵はD1/R2の平文にも一般のOIDC署名鍵にも置かない。登録時に秘密鍵と公開鍵の対応を証明し、鍵切替時は旧鍵で包まれた属性の扱いを定める。
2. 本人が属性を解錠したときだけ、そのrevisionのdata keyに追加のrecipient envelopeを作る。origin・属性・revision・service・鍵IDをHPKEのinfo/AADに結び付け、現行owner envelopeは残す。envelopeとGrantを同じ版で公開し、鍵配送に失敗した更新ではsystem共有を停止する。
3. 失効、鍵切替、属性更新、誤った鍵ID・revision・属性への差し替え、鍵管理障害を含むWorker/ブラウザー試験を通してからUserInfoに接続する。本人専用Vaultを利用するだけならPQC鍵やFIDOのML-DSA対応を要求しない。

隔離HPKE probeはこの2番の暗号境界を確かめるものです。鍵directory、秘密鍵保管、Grant、ブラウザー実行はまだ製品に実装していません。

FIDOではML-DSAのCOSE番号が割り当てられていても、手元のドングル・ブラウザー・OSで利用できるとは限りません。現在の認証器をサーバー側でPQC credentialへ変換することもできません。対象機器で新規credentialを作り、既存credentialと並行運用してから移行します。ML-DSAで検証できるようになるまで`pubKeyCredParams`へ`-49`を出さず、未対応時の暗黙のダウングレードを「PQC対応」と表示しません。

Cloudflare WorkersのWebCrypto対応表には、確認時点でML-KEM/ML-DSAの行がありません。このためWorkersの組込みWebCryptoで使えると仮定せず、Rust/Wasmの隔離検証から始めます。採用候補のRustCrypto `ml-kem` 0.3.2と`ml-dsa` 0.1.1、比較に使うnobleは独立監査未実施と明記されています。NIST sampleと独立実装の照合は通ったものの、製品への組込み前に全パラメータの既知解、鍵・署名のサイズ境界、依存監査、実際のWorker/ブラウザーでの資源計測を追加します。VaultのHPKE probeはdraft-04実装で、現行のHPKE PQ draft-05に対する互換性を確認していません。key directory、秘密鍵保管、Grant、再包み、旧版との併存が完成するまで製品に接続しません。導入後も実装済み・受理可能・新規発行を用途ごとに分け、D1の運用ポリシーで切替可能にします。

## 根拠

- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) と [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)：ML-KEMとML-DSAの規格。
- [RFC 9964](https://www.rfc-editor.org/info/rfc9964/)：ML-DSAのJOSE/COSE識別子と鍵形式。
- [FIDO Server Requirements 2.3 Review Draft](https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20260226.html)：COSE `-49`をML-DSA-65として記載。ただしReview Draftであり、実機対応の証拠ではない。
- [WebAuthn Level 3](https://www.w3.org/TR/webauthn/)：RPが候補アルゴリズムを提示し、client/認証器が作成可能な方式を選ぶ。
- [Cloudflare Workers WebCrypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/) と [RustCrypto ML-KEM](https://docs.rs/ml-kem/0.3.2/ml_kem/)・[ML-DSA](https://docs.rs/ml-dsa/0.1.1/ml_dsa/)：実行環境と候補実装の制約。
- [NIST ACVP sample](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files) と [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum)：既知解と独立実装との照合。
- [draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05)：ML-KEMをHPKEに使う現行の作業草案。製品形式は未確定。
