# WebAuthn実機・ブラウザー互換性記録

2026-09-23 / WG-06。仮想認証器による自動試験と、認証器を実際に操作した結果を分けて記録する。FIDO Server Conformanceはブラウザー／端末互換性の代替ではない。

## このMacで確認した環境

| 端末・OS | ブラウザー | 認証器 | 登録・再認証 | resident/discoverable | UV | backup/counter | 状態 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MacBook Air M3 (Mac15,13), macOS 27.0 (26A428), 2026-09-23 | Playwright管理 Chromium 153.0.8010.12 headless | Chromium CDP仮想CTAP2.1 internal。resident key・UV・user presenceをシミュレート | 統合49試験がpass | 登録後にresident credential属性を確認、discoverableログインを含む | UV flagを常時trueに設定 | backupの実機挙動は未試験。counterはcore単体fixtureで別途検証 | 自動試験済み。実機互換の結果には数えない |
| 同上 | Google Chrome 154.0.8037.58 headless | 同上のCDP仮想認証器 | 2026-09-23、統合49試験pass | 同上 | 同上 | 実機挙動は未試験 | 自動試験済み |
| 同上 | Google Chrome Canary 156.0.8068.0 headless | 同上のCDP仮想認証器 | 2026-09-23、統合49試験pass | 同上 | 同上 | 実機挙動は未試験 | 自動試験済み |
| 同上 | Safari 27.0 (22625.1.29.11.27) | macOS platform authenticator / Touch ID | 未試験 | 未試験 | 未試験 | 未試験 | GUI・生体認証を使う試験が必要 |

SPUSB/SPBluetoothのこの実行環境の一覧から、外付けFIDO認証器の製品名を確認できなかった。接続済みキーが存在しないと断定する調査ではない。アプリ一覧ではChrome、Chrome Canary、Safariを確認。Android端末、iPhone/iPad、Windows Hello端末、外付けSecurity Keyの結果はまだない。

## 再現した自動ブラウザー試験

`slice.test.mjs`は既定でPlaywright管理Chromiumを使い、`WebAuthn.addVirtualAuthenticator`でresident-keyとuser-verificationに対応する仮想CTAP2.1 authenticatorを追加する。Chrome stable／Canaryへ切り替える場合は`SAKIMORI_BROWSER_CHANNEL=chrome`または`chrome-canary`を設定して`npm run test:e2e`を実行する。いずれもDB、issuer、RPはテスト用の一時loopback環境を使用する。

統合試験は招待による登録、resident credential属性、discoverable Passkeyログイン、再ログイン、UV必須、認証後のcode交換までを確認する。WebAuthn応答の検証、OIDC、session/lifecycle試験も同じ49件に含む。PlaywrightがCDP経由で認証器を制御するため繰り返し実行でき、生体操作やcredential同期を必要としない。一方、実機の生体操作、OS permission UI、credential同期、Bluetooth/NFC/USB transport、hardware firmwareは再現しない。

2026-09-23にPlaywright headed ChromeからTouch IDを試したが、試験用ウィンドウと認証プロンプトを利用者の画面で確認できず完了しなかった。実機互換の結果とは扱わず、この操作モードは自動試験の対象から外した。実機マトリクスを追加する場合は、対象端末で別途記録する。


## 未実施の組合せ

| platform／認証器 | Browser | 状態 |
| --- | --- | --- |
| macOS built-in Touch ID / iCloud Keychain同期 | Safari、Chrome | 未試験 |
| iPhone/iPad built-in authenticator /同期 | Safari | 端末がなく未試験 |
| Android platform authenticator /同期 | Chrome | 端末がなく未試験 |
| Windows Hello | Edge、Chrome | 端末がなく未試験 |
| 外付けFIDO2 security key（USB/NFC） | Chrome、Safari、Firefox | 認証器未確認、未試験 |

現時点ではChrome系列の仮想認証器を用いる自動試験だけが実行済み。製品が対象とする実機互換性を結論付けたり、ブラウザー差を一般化したりしない。
