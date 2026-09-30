# Supply-chain evidence

The reusable [Worker build workflow](../.github/workflows/supply-chain-build.yml) runs only after the main CI verification job succeeds on `main`. It builds the Rust Worker in GitHub-hosted Actions without deployment credentials and publishes an archive containing the Worker entrypoint, JavaScript glue, and Wasm. The archive is the subject of a GitHub build-provenance attestation and a CycloneDX SBOM attestation. The workflow also uploads the inventories alongside the archive.

| Evidence | Scope | Generator |
| --- | --- | --- |
| `release-manifest.json` | Clean source commit, both archive/member digests and ordered migration digests | [`release-inventory.ts`](../scripts/release-inventory.ts); separately attested |
| `promotion-*/upload-manifest.json` | Verified archive/configuration digests and exact local Wrangler upload-bundle digests for both Workers | [`prepare-release-upload.ts`](../scripts/prepare-release-upload.ts); separately attested |
| `worker-rust.cdx.json` | Rust packages selected for `wasm32-unknown-unknown` | `cargo-cyclonedx` 0.5.9, CycloneDX 1.5 |
| `npm-build.cdx.json` | npm dependencies used by the local build | `npm sbom`, CycloneDX 1.5 |
| `worker-crypto.cdx.json` | Reviewed cryptographic algorithms and key-storage classes in the Worker source | [`build_cbom.ts`](../scripts/build_cbom.ts), CycloneDX 1.7 |

The CBOM does not contain key values, client secrets, passkeys, or tokens. It records six source-backed cryptographic assets. Cloudflare's TLS termination and the cryptography inside third-party dependencies are outside that initial source inventory. A CBOM entry for a key binding describes the storage class, not a particular live key or proof of HSM protection.

The workflow validates all three BOMs with a SHA-256-pinned CycloneDX CLI binary. The Rust SBOM and CBOM are each attached to the Worker archive as CycloneDX attestations. The npm inventory describes build tooling and is distributed separately; it is not presented as a runtime dependency list.

[GitHub documents](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/increase-security-rating) a reusable workflow with artifact attestations as a route to **SLSA v1.0 Build Level 3**. This repository's CI archive follows that pattern. The currently deployed `mikaki.tossa.app` Worker was built and uploaded from a developer machine, so the CI archive's attestation does **not** prove the bytes running at that domain. Promotion of the attested archive to Cloudflare, followed by verification of the deployed version, is a separate gate before making a SLSA claim about production.

After downloading an `attested-worker-<commit>` workflow artifact into `artifacts/`, verify its build provenance and the Rust SBOM and CBOM attestations:

```sh
gh attestation verify artifacts/mikaki-worker.tar.gz -R masanork/mikaki \
  --signer-workflow masanork/mikaki/.github/workflows/supply-chain-build.yml
gh attestation verify artifacts/mikaki-worker.tar.gz -R masanork/mikaki \
  --signer-workflow masanork/mikaki/.github/workflows/supply-chain-build.yml \
  --predicate-type https://cyclonedx.org/bom
```

The expected builder identity and source revision must also match the intended release. A successful cryptographic verification alone does not authorize deployment.

Before promotion, verify the inventory provenance and both archives against the independently selected commit, then run `npm run release:verify` in its clean checkout. The verifier compares bytes without filesystem extraction and does not authenticate a manifest by itself. See [the release and recovery runbook](release-and-recovery.md). This workflow change has local verifier/rehearsal evidence; no new remote attestation or runtime-byte mapping is claimed.

The OP now has a `/version` response backed by Cloudflare Worker version metadata and an embedded clean-checkout source commit. The version-aware [production smoke workflow](../.github/workflows/production-smoke.yml) can compare those with an independently reviewed activation record and retain a result. This source/version comparison is only one part of promotion: an operator still must establish which verified archive bytes produced that Cloudflare version. It has not been exercised on the production issuer.

The attested build now runs the offline [upload preparer](../scripts/prepare-release-upload.ts) and verifier after the archive inventory. It closes the local archive-to-Wrangler-input segment: it extracts verified members, dry-run bundles both Workers with their production configs, records bundle digests and rechecks all files before upload. `--no-bundle` can consume those outputs without a second build. The prepared inventory is attested and distributed with the archives. Its local dirty-mode rehearsal is not a production promotion or remote byte attestation. The version IDs and bindings returned by a future Cloudflare upload must be added to the activation record.
