# UserInfo claim-service timeout boundary

The default-disabled `openid profile` path asks a dedicated claim Worker to decrypt an owner-approved Vault `name` and conditionally write a disclosure audit before returning the value. OP UserInfo already fails closed with 503 on a rejected or failed claim response. A slow service binding has a separate concern: how long the RP waits and whether a timeout can leave an audit for a value the RP never received.

Run `node design/probes/userinfo-service-timeout.mjs` from the repository root. With Miniflare from the pinned Wrangler 4.144.0 installation, the caller's `AbortSignal.timeout(100)` rejected the service-binding fetch while its downstream callback continued for 500 ms. The callback still observed `request.signal.aborted === false`. The probe uses no Vault data, token, production binding, or account. It establishes local runtime behavior only; it does not measure Cloudflare production cancellation.

The Rust `worker 0.8.6` `Fetcher` exposes `fetch` and `fetch_request` without a signal parameter. Even if a request signal is attached through a lower-level API, the local probe shows that caller cancellation alone cannot be treated as proof that claim processing or its audit stopped. A `Promise.race` around the service call would bound the OP response but could let the claim Worker record a disclosure after the RP receives 503. Do not add that timeout to the release path under the current audit meaning.

Before setting a hard UserInfo deadline, define and test one of these contracts against the actual service:

1. A cancellation protocol in which the claim Worker acknowledges it stopped before the conditional audit, including a D1 write already in progress; or
2. Audit semantics that distinguish an attempted release from a response delivered to the RP, with a bounded handoff that can record the final outcome.

Test slow R2, D1, Secrets Store, and service-binding phases separately, including a delay just before the conditional audit. Check the RP-visible status, elapsed time, audit result, and recovery. Keep the sharing and RP-release policies disabled until a named RP and intended device are qualified as described in [the Vault fit-gap](vault-fit-gap.md#vg-06--complete-ordinary-rp-profile-release).
