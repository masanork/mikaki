# Supply-chain evidence

The reusable [Worker build workflow](../.github/workflows/supply-chain-build.yml) runs only after the main CI verification job succeeds on `main`. It builds the Rust Worker in GitHub-hosted Actions without deployment credentials and publishes an archive containing the Worker entrypoint, JavaScript glue, and Wasm. The archive is the subject of a GitHub build-provenance attestation and a CycloneDX SBOM attestation. The workflow also uploads the inventories alongside the archive.

| Evidence | Scope | Generator |
| --- | --- | --- |
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
