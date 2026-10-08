# Artifacts development copy

**Status:** Historical bootstrap evidence from 2026-10-06, retained during main integration on 2026-10-08. GitHub remains authoritative. This increment has not refreshed the development copy to current main.

Stage 0 of [ADR 0016](adr/0016-personal-context-and-workload-delegation.md) copied committed source `d441ce0a4583ebcf1ae54627e2ca3df29e2f20a9`, tree `93196f9d7093346d12009d9c3f61699dc47300a2`. Only its reachable ancestry and selected `HEAD` ref were included; uncommitted work and unrelated refs were excluded.

Retained receipts identify 649 committed files, 232 reachable commits and bundle SHA-256 `e855f35832940f8696e3fe3fcc0797c5a4af46d3867872222219c27490fc2bd1`. Standalone and remote clones matched the selected commit/tree. The destination is namespace `mikaki-dev`, repository `mikaki`, default branch `baseline`:

```text
https://4b749427a0c80c547e726a42aff4b6fc.artifacts.cloudflare.net/git/mikaki-dev/mikaki.git
```

Issued Git credentials were revoked, retained plaintext removed and the disposable bootstrap probe deleted. Protected receipts remain under ignored `local/generated/artifacts-bootstrap/`. This is earlier evidence, not current remote inspection or a propagation guarantee.

Later work-effect probes are separate: six retained empty repositories and uncertain allocations remain accounted for by existing journals. Bootstrap cleanup authorizes no deletion of these resources; see the [integration plan](work-delegation-implementation.md#preserved-work-and-main-baseline).

Before refreshing, qualify a selected committed main-based source, prepare its exact commit/tree/bundle digest, refresh in one controlled direction, independently clone/verify and record credential cleanup. Keep experimental adoption and task repositories separate. Canonical migration, production deployment and CI/recovery parity retain their own gates.
