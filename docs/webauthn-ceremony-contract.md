# WebAuthnの信頼入力とceremony契約

2026-09-23 / WG-02。現在の保証、呼び出し側の責務、ローカル実装の制約を分ける。

## コアへ渡す入力

`Context`、`StoredCredential`、`Ceremony`は信頼されたサーバー状態である。ブラウザーが送るcredential応答をこれらへmergeしない。Deserialize可能という性質は信頼性を保証しない。HTTPが受け取るのはcredential応答と取引参照であり、設定、保存鍵、所有者、時刻、消費状態はサーバー側から構成する。

`Context::validate()`はchallengeの非空・canonical base64url、origin/RP IDの非空と前後空白、正のサイズ・深さ、非空で重複のない対応アルゴリズム一覧を検査する。identified認証のuserHandleとallow-listは非空・canonical base64urlで、長さの上限も確認する。`register`と`authenticate`は必ずこの検査を呼び、失敗は`configuration`となる。発行側でも同じメソッドを呼べる。public fieldを後から変更しても検証入口を迂回できない。

この検査はURLパーサーや設定ファイルのschema検証の代用ではない。HTTPS/local開発originの選定、originとRP IDの関係・所有権、運用上限の妥当性は配備設定側が保証する。コアはtrusted originとの完全一致とRP ID hashを照合する。challengeの乱数品質、再利用の有無、attestation信頼情報の取得元・鮮度を設定の形だけから証明することもできない。

## 責務の分担

| 項目 | 共通コア / auth | 呼び出し側・store |
| --- | --- | --- |
| challenge | 保存値とclientDataの一致 | CSPRNGで生成し、ceremonyに保存。ローカルOPは32 byteを生成 |
| 用途 | `register`はcreate、`authenticate`はgetを要求。authは保存purposeとも照合 | 発行した操作のpurposeを保存し、応答から採用しない |
| browser・期限・試行 | authが空でないbrowser binding、一致、未消費、期限、試行上限を検査 | browser取引を認証し、信頼した現在時刻を渡す。失敗回数を永続化 |
| UV・方式・認証種別 | 保存ポリシーに従って検証 | 発行時と完了時のポリシーを一貫させる |
| discoverable認証 | 応答userHandleが保存credentialのuserHandleと一致することを要求 | credential IDで取得する鍵・所有者・有効状態の整合性を保証 |
| identified認証 | 保存userHandle、credential IDのallow-list所属、応答に存在するuserHandleを照合 | ログイン対象アカウントからuserHandle・allow-listを構成 |
| 登録所有者 | 登録公開鍵等を検証。登録応答からaccountを証明するものではない | 招待と発行済みceremonyのaccountへ登録を結び付ける |
| 検証結果 | 外部構築・Deserialize不能の結果型 | JS境界ではJSONになるため、HTTPから結果を受け取らない |
| 一回性・並行実行 | メモリー上の検証成功は消費を意味しない | challenge消費とcredential保存/更新・session発行を同一原子操作で確定 |

コアを直接呼ぶ場合、authのbrowser・期限・試行検査も自動では付かない。authを呼んでも永続的な一回性は付かない。検証成功後に保存が競合・失敗した場合、ログインを成功扱いにしない。

ローカルOPの完了処理はceremonyの未消費・browser・期限・試行回数をSQLで再確認し、更新件数を検査する。認証では保存credentialのrevision、有効状態、account epochも確定時に再確認する。登録では招待消費、bootstrap、credentialの一意性を同じbatch内で処理する。native ConformanceアダプターにもSQLite transactionの競合・rollback試験がある。これらは結果型だけでは代替できない保証である。

## 保存ポリシーと現行の制約

[設定契約](runtime-configuration.md)に従い、永続環境では発行時の設定版・期限・上限を保存し、途中の設定変更で既存ceremonyの条件を暗黙に変えない。緊急停止等の即時適用は同文書の別契約に従う。

現行ローカルOPはchallenge、purpose、browser、account、期限を保存する一方、origin/RP ID、UV/アルゴリズム、入力上限、試行上限は固定の実行環境から再構成する。設定変更のhot reloadはなく、開発環境のDBは起動ごとに作り直す。**永続DBと新旧配備をまたぐceremonyの設定snapshotは未実装**であり、ローカルでの成功をその保証として扱わない。永続環境への移行時は設定版と検証条件を保存し、発行後の設定変更・rollbackを試験する。

## APIの選択と試験

今回は用途別状態型やbuilderを増やさず、両入口の設定検査と既存のpurpose照合を採用した。constructorだけで検査してもpublic fieldやDeserialize後の変更は防げない。privateな状態型を導入するなら、永続化形式と発行APIを含めた具体的な誤用を解消する段階で行う。信頼された呼び出し側が虚偽の状態を渡す問題は型だけでは解決しない。

native/Wasm共通試験は不正設定を登録・認証の両入口から拒否すること、所有者・allow-list・UVの照合を確認する。auth試験は用途違い、空/不一致のbrowser、期限、消費、試行境界を確認する。既存のnative store試験とブラウザー統合試験は同時完了・再送・rollbackを確認し、JS試験は設定エラーのWasm境界を確認する。公式FIDO GUI Suiteはこの変更では再実行していない。
