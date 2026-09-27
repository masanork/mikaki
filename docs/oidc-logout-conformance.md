# RP-Initiated Logout conformance run

On 2026-09-27 JST, the local Mikaki OP fixture was tested with OIDF Conformance Suite 5.3.1 using the `oidcc-rp-initiated-logout-certification-test-plan` plan. The static client used Authorization Code flow and a Chromium virtual passkey. The final complete run was plan `PXI54vyEHYG0z`.

| Result | Modules |
| --- | --- |
| `PASSED` (3) | Discovery endpoint verification; standard RP-initiated logout; logout without `state` |
| `REVIEW` (8) | Invalid redirect URI, modified ID Token hint, missing ID Token hint with redirect URI, no parameters, no redirect URI, only `state`, added redirect URI query, invalid ID Token hint |

All 11 modules finished. The eight `REVIEW` cases ask a human to inspect an error or successful logout page; this is not an automated pass or formal certification. The run `Qm9prAtPxjTPc` repeated those eight cases and uploaded screenshots after the logout request, including the completion page for successful cases. Their detailed records remain in ignored `local/generated/oidf-passkey-*.json` files, which may contain test credentials.

The suite exposed three implementation gaps: `end_session_endpoint` was absent from Discovery, `state` and `post_logout_redirect_uri` were incorrectly required, and the confirmation page's browser policies blocked its own POST or redirect. Those were corrected. A local Worker/D1 integration probe also verifies unregistered redirect and invalid hint rejection, no-parameter confirmation, same-origin POST, atomic rollback on injected D1 failure, concurrent duplicate POST, SSO/client-session revocation, and logout outbox snapshot.

The OP now accepts RP logout requests via HTTP POST, converting validated form parameters to a same-site GET confirmation so the browser can send its Lax SSO cookie. The Back-Channel delivery worker signs `logout+jwt` tokens and retries leased outbox items every minute. The local signing test verifies the JWS signature and required claims; the Worker/D1 probe verifies that a failed outbound attempt remains pending with an incremented attempt count.

After these changes, the standard RP-Initiated Logout module passed again in plan `3qVI0ntufGbl0` (module `VNdetLbJdh9sG1G`).

The Back-Channel Logout conformance plan was also attempted locally. Discovery passed (plan `FAaW9v4CThyp0`), but the RP-initiated notification case did not complete: the local Worker harness returned HTTP 500 for its outbound call to the suite, and no request appeared in the suite's receiver log (run `Z4B1eBKULxPs6TW`). This is an incomplete test result, not a conformance pass. Run the profile again with a reachable HTTPS receiver before merging the logout implementation. The eight RP-Initiated Logout `REVIEW` results also still require manual inspection.

The test profile and manual-review requirements are described by the [OpenID Foundation OP logout testing instructions](https://openid.net/certification/connect_op_logout_testing/); optional request parameters and GET/POST methods are defined in [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
