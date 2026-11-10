# Local Access bridge experiment

The readiness bridge was merged in #350 and the integrated code and 0011/0012 migrations followed in #351. See the [production rollout record](owner-email-bridge-rollout.md) for the observed state and open activation and recovery boundaries. The rest of this document records the original local experiment and its limits.

This prototype starts from #349 and accepts only the complete verified-email ledger and two candidate subsequent names: `0011_access_email_bindings.sql` and `0012_access_email_scope.sql`. It adds neither Access functionality nor migrations. The names are experimental, not a reviewed production migration chain.

The Rust owner-schema tests include missing, duplicated, reordered and unknown entries. A local workerd/D1 experiment used the #346 SQL bytes under the candidate names, the original 0010 Worker, this bridge and the actual Claim Worker. The original 0010 Worker became unready after 0011; the bridge remained ready and a seeded existing-account OIDC code exchange passed on 0010, 0011 and 0012. This does not exercise the combined Access feature, a real Passkey ceremony, Cloudflare deployment or rollback, production data, or Work/Messaging data.

The #336 and #346 feature branches independently change scope canonicalization, email authorization, token issuance and client-secret handling. Their code and tests must be integrated before adopting these filenames or considering promotion. This experiment does not authorize production migration or deployment.
