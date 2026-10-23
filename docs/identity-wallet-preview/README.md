# Identity Wallet preview

Synthetic test identities rendered by the actual native UI with fixture IPC.
The current-main preview retains in-app Web navigation and adds Wallet-only login
for account-scoped encrypted read summaries.

- [390px Wallet](wallet-390.png)
- [320px Wallet](wallet-320.png)
- [Desktop](wallet-1080.png)
- [Add a document](wallet-add.png)
- [Dark appearance](wallet-dark.png)
- [Read document details and next actions](wallet-document-detail.png)
- [Credential details and presentation preparation](wallet-credential-detail.png)
- [Passport access form](wallet-passport-access.png)
- [Three documents and masked passport details](wallet-passport.png)
- [Explicit passport number and MRZ display](wallet-passport-revealed.png)
- [DG1/SOD consistency with issuer trust still unconfirmed](wallet-passport-signature.png)
- [Multipaz host SDK results](multipaz-host-results.json)
- [Native passport presentation SDK results](multipaz-passport-host-results.json)

Regenerate with `node --test local/conformance/identity-wallet-ui.test.ts`.
Physical reading, encrypted storage/restart and Multipaz interoperability require
separate device and verifier checks; screenshots do not establish those results.

- [Passport evidence-transfer review](passport-issuance-review.png): synthetic MRZ attributes and explicit raw-evidence transfer consent. This is mocked native IPC, not a successful real-passport issuance.

- [HAIP browser consent](passport-haip-consent.png): the actual workerd-generated authorization page with synthetic projected attributes and Wallet identity. Privileged test-database seeds isolate this UI/protocol check; this is not a successful real-passport intake.
