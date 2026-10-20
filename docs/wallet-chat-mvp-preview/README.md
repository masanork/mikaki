# Wallet and Chat MVP screenshots

These are captures of the actual product UI under disposable local test fixtures.
Names, credentials, issuers and conversations are synthetic. The native UI tests
simulate the native IPC; the Chat product-entry test uses real Owner custody,
OpenMLS/Wasm, encrypted IndexedDB and authenticated workerd/D1 mailboxes with a
synthetic Passkey PRF. They do not establish physical-device or real-issuer qualification.

- [Wallet, mobile](wallet-390.png)
- [Wallet, narrow mobile](wallet-320.png)
- [Wallet, desktop](wallet-1080.png)
- [Chat, mobile](chat-390.png)

Regenerate with `MIKAKI_WALLET_CHAT_PREVIEW=1 npm run test:wallet-chat`.
Ordinary test runs write captures under ignored `local/generated/` and keep
reviewed source files unchanged.
The [MVP scope](../wallet-chat-mvp.md) describes implemented behavior and release gates.
