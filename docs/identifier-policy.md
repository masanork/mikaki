# 識別子の統一方針とUUIDv4/v7の比較

2026-09-22 / Draft 1（推奨案）

識別子であることだけを理由にDIDを採用しない。規格が形式・生成方法を定める箇所はそれに従い、mikakiが発行する通常のエンティティIDはUUIDへ寄せる。DIDは連合で鍵・制御主体・配送先との関係を扱う用途に絞る。本書は比較と用途別推奨であり、既存データの移行や実装完了を意味しない。

## UUIDv4とUUIDv7

| 観点 | UUIDv4 | UUIDv7 |
| --- | --- | --- |
| 大きさ | 128 bit、標準文字列表記36文字 | 同じ |
| 構成 | version/variantを除く122 bitがランダム | 先頭48 bitにUnix時刻のミリ秒。残り74 bitに乱数、または規格が許す単調性用の値を配置 |
| 時刻の露出 | UUID自体に生成時刻を埋め込まない | 生成器が用いた時刻を読み取れる |
| 生成 | CSPRNG。時計や生成順序の管理が不要 | 時計と乱数が必要。同一ミリ秒・時計逆行の扱いは採用生成器を確認 |
| 並び順 | 作成順には並ばない | 時刻に沿った配置。ただし全プロセスの厳密な生成順・確定順は保証しない |
| 索引の局所性 | 挿入先が分散する | 時刻に沿うため局所性を得やすい。実DBでの効果は測定が必要 |
| mikakiの候補用途 | 公開される主体・オブジェクト・操作のID | 大量に追記する、外部非公開の監査・outboxレコードID |

形式と索引特性の根拠は[RFC 9562 §5.4・§5.7・§6.11](https://www.rfc-editor.org/rfc/rfc9562.html)。用途の割当てはmikakiの設計判断である。どちらも生成数・乱数品質を考慮し、一意制約と衝突時の扱いを必要とする。UUIDv7の74 bitを常に独立した乱数と仮定せず、生成器の方式を確認する。

## 推奨する初期方針

UUIDv4を通常IDの既定とする。初期の認証・Vaultは、作成日時をIDに埋め込まず、生成・検証の種類を少なくする利点を優先する。内部専用で追記量の多いレコードにはUUIDv7を候補とし、その保存経路を実装するときに採用と測定を行う。v7を使うためだけに監査表や追加の主キーを作らない。

すべてのエンティティへ「内部用v7＋外部用v4」の二重IDを追加しない。内部IDと公開IDを分けるのは、AccountIdとOIDC subのように独立した意味・開示範囲がある場合に限る。

## 用途別の割当て案

| 対象 | 推奨形式 | 理由・条件 |
| --- | --- | --- |
| AccountId | UUIDv4 | 共通アカウントの内部参照。OIDC subとして流用しない |
| アプリ内SubjectId | UUIDv4 | 各アプリが独立発行。表示名等から導出しない |
| OIDC sub | sectorごとに独立したUUIDv4 | 公開される恒久ID。生成時刻を含めず、接続解除・再接続で維持 |
| OIDC client_id | mikakiの初期登録ではUUIDv4 | アプリ表示名・ドメインから独立。OIDC自体がUUIDを要求するわけではない |
| OIDC sid、Logout Token jti | UUIDv4 | セッション/通知の公開参照。cookieの秘密値とは別 |
| VaultId、CollectionId、ObjectId、GrantId | UUIDv4 | API・AAD等に現れ得る。ownerや用途を別フィールドで結び付ける |
| Messaging DeviceId、独自会話ID・メッセージID | UUIDv4 | 公開され得る識別子。鍵やMLSの規定形式とは分離 |
| operation_id、delivery_id | UUIDv4 | 再試行で同じ値を保持。所有者/送信元と組み合わせて重複排除 |
| ceremonyのレコード参照ID | UUIDv4 | 同じブラウザとの結び付けを別に確認。IDだけで完了を許可しない |
| 自前の署名鍵kid | UUIDv4 | 鍵ごとに一意。外部規格で鍵参照形式が決まっている場合はそちらに従う |
| 内部監査イベント・outboxレコードの独立ID | UUIDv7を候補 | 外部に公開しない追記データ。必要性と保存効率を測定して採用 |

UUIDv7を内部outboxの主キーに使う場合でも、配送プロトコルのdelivery_idと同じ値にしない。ただしoutboxが既存のdelivery_id等で十分識別できるなら、独立したv7主キーを追加しない。

## UUIDへ変えない値

- **秘密・本人確認用の乱数**：セッションcookieのbearer値、認可code、access token、client_secret、CSRF state、OIDC nonce、PKCE verifier、WebAuthn challenge。必要なエントロピーと規格上の形式を個別に満たすCSPRNGの値を使う。既存の32 byte challengeをUUIDに縮めない。
- **外部で発行された値**：WebAuthn credential ID、外部アプリのsource message ID等をUUIDとして解釈し直さない。userHandleもWebAuthn上のバイト列と所有関係を明示し、UUID必須とはしない。
- **URL・ドメイン**：OIDC issuer、redirect URI、RP ID、originは規格の形式を維持する。
- **暗号プロトコルの値**：鍵本体・指紋・ハッシュ・AEAD nonce・MLS KeyPackage参照等はプロトコルの形式を維持する。独自会話IDとMLS内部IDの対応は別に定める。
- **順序・版**：revision、epoch、grant版、同期cursor、設定内容ハッシュはUUIDで代用しない。確定順が必要なら原子的に割り当てるシーケンス等を別に持つ。
- **DID**：連合で採用する利用者/インスタンスDIDはメソッドに従う。UUID表記をdidで装飾してDIDと称しない。

UUIDは参照値であり、認証・認可・鍵所有の証明にはしない。内部IDにv7を使っても、時間由来の値を管理操作許可やセッショントークンとして使わない。

## 表記・型・保存

自前のUUIDは小文字・ハイフン付きの36文字を標準の外部表記とする案を推奨する。OIDC subにも同じ表記を使い、通常は`urn:uuid:`を付けない。URNはURIが必要な文脈で使用できるが、同じsubを場面により36文字とURNへ切り替えない。受信したOIDCの(issuer, sub)は大文字小文字を含めてそのまま扱い、他issuerのsubをUUIDと決め付けない。

自前UUIDのAPIでは許可版とvariant、標準表記を検証する。別表記を無条件に正規化して署名/AADの入力を書き換えない。暗号形式のバイト表現はG2/G3で別途固定する。生成器はNative/Wasmで同じ形式契約を満たす保守された実装を使う。

RustではAccountId・VaultId等を取り違えやすい境界だけ薄い型で分け、内部は同じUUID型を再利用する。UUIDの共通化を型の同一化と解釈しない。生成済みIDは文字列から型へ変換できても、それだけで所有者・認証済み主体にはならない。

DBでは16 byte表現と36文字表現の容量・索引・運用性を比較し、アダプターで保存方式を統一する。UUIDv7の採用だけでDB全体が高速になると結論付けない。既存の複合キーだけで十分な表に、UUIDを追加しない。

## 一意性・時刻・再送

新しいエンティティのID衝突は一意制約で拒否し、既存行を上書きしない。自分がまだ公開・確定していない新規生成値の衝突なら再生成できるが、公開済みIDや再試行IDを都合よく差し替えない。同じoperation_id/delivery_id・異なる要求内容は競合として拒否する。

UUIDv7から読める時刻はクライアントの申告や時計補正を含み得るため、認証時刻・失効期限・監査上の確定時刻の根拠にしない。created_at、auth_time、expires_at、必要な確定シーケンスを別に保持する。v7をWHERE id > cursorの同期保証に使い、時計逆行や並行挿入を取りこぼす設計は禁止する。

## 検証項目

- 自前UUIDの版・variant・文字列表記と、Native/Wasm双方のCSPRNG利用。
- 独立したsectorのsub、同時初回生成の一意制約、再接続でのID維持。
- v7採用時の同一ミリ秒大量生成、時計逆行、並行プロセス、再起動。ID順を認証/同期の正しさに使っていないこと。
- 重複IDを意図的に注入した拒否試験、同ID異内容の再送拒否、応答喪失後の同一ID再利用。
- 外部由来の非UUID識別子を受け取れること、公開APIへ内部v7を不用意に露出しないこと。

## 参照

- [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562.html)：UUIDv4/v7、表記、時刻・並び順・セキュリティ上の注意。
- [OIDC Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)：subの形式と識別範囲。
- [OIDC Core §8.1](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg)：sector単位の識別子。
