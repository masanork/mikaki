# Fictional Vault interaction preview

This preview accompanies the proposed [Vault product model](../vault-product-model.md). It uses fictional Japanese human/human and human/AI threads, application authorization/history, and simulated opening, saving, proposal acceptance, sharing and stopping. It does not call WebAuthn, a Worker, production, a messaging endpoint or any agent; it has no storage or encryption. Reloading resets the demo. The existing woven renderer supplies the decorative header.

Run from the repository root after installing the existing dependencies:

```sh
node docs/vault-usage-preview/serve.mjs
```

Open [the local preview](http://127.0.0.1:4178/). The server binds loopback only and serves a fixed set of preview routes. `MIKAKI_PREVIEW_PORT` can select another nonprivileged port. Stop with Ctrl-C.

Try this sequence:

1. Open once and inspect Conversations: the human conversation has a linked comparison; the AI conversation names its processing service and links a draft/application history.
2. Review the exact sample draft/version/destination and authorize it. History records the owner's authorization; dispatch/receipt remain unconfirmed. It does not claim a submission or an official decision.
3. Edit the display name in My information and save. No separate item unlock is shown.
4. Open Records and review the AI's proposed task recap. Accepting creates a simulated retained record; it does not grant AI access.
5. Open that record and choose to pass it to another AI. Review the one selected record, consumer/provider, read-only operation, one-hour duration and snapshot mode.
6. In Connections, stop future retrieval. The copy cannot be recalled.
7. Lock. Content is removed from the displayed workspace; opening again starts another simulated ceremony.

The real owner-key lifetime, E2EE protocol/participant authentication, AI decryption boundary, server authorization, application dispatch/receipt verification, conflict/retry behavior, imports, grants, recovery and crypto formats still require the implementation slices in the model. A click counter in this demo is not evidence of an actual single WebAuthn ceremony.

Capture and exercise the prototype:

```sh
node docs/vault-usage-preview/capture.mjs
```

The capture checks keyboard focus, the fictional action flow, absence of additional simulated opening during ordinary use, removal of displayed content on lock, accessible names/landmarks/references, no page errors and overflow at 320/390/1440 pixels. It captures reduced-motion desktop/mobile screens. These are prototype checks, not product regression or assistive-technology qualification.

| State | Desktop | Mobile |
| --- | --- | --- |
| Locked | [Preview](locked-desktop.png) | [Preview](locked-mobile.png) |
| Conversations | [Preview](threads-desktop.png) | [Preview](threads-mobile.png) |
| Human conversation | [Preview](human-thread-desktop.png) | [Preview](human-thread-mobile.png) |
| AI conversation | [Preview](ai-thread-desktop.png) | [Preview](ai-thread-mobile.png) |
| Owner authorization, receipt pending | [Preview](application-history-desktop.png) | [Preview](application-history-mobile.png) |
| My information | [Preview](profile-desktop.png) | [Preview](profile-mobile.png) |
| Records | [Preview](records-desktop.png) | [Preview](records-mobile.png) |
| Agent proposal review | [Preview](review-desktop.png) | [Preview](review-mobile.png) |
| Selected disclosure | [Preview](sharing-desktop.png) | [Preview](sharing-mobile.png) |
