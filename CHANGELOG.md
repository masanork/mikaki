# Changelog

This file records user-visible project changes from 2026-09-23 onward. Mikaki has no supported release yet; earlier experiments and probes remain in the Git history and their dated test records. Entries under **Unreleased** describe work in this repository, not a production launch.

## [Unreleased]

### Added

- A short project README and a documentation map that distinguish deployed behavior, local verification, accepted decisions, and proposals.
- English project-status, architecture, local-development, roadmap, and contribution guides.
- English versions of the existing architecture decision records and the RP integration guide.
- English documentation across the root, topic guides, crate and local harness READMEs, probes, and dated conformance reports.
- Restored the codebase growth and coverage links in the project README.

### Documentation

- Recorded the current production deployment limits: no registered production account or RP, and no verified production Vault write or PRF unlock.
- Kept conformance results separate from formal FIDO or OIDF certification claims.
- Marked implemented behavior separately from design proposals and historical acceptance gates throughout the topic guides.

Future entries should describe shipped behavior and migrations with a dated version or release tag. Do not move an item from **Unreleased** merely because a local probe passes.
