# Prototype-safe configuration merge

This is a scoped local fork of the published MIT-licensed deepmerge 4.3.1 distribution, used only through the npm override for build tooling. It is not an upstream deepmerge release.

- Source: https://github.com/TehShrike/deepmerge/tree/v4.3.1
- Upstream artifact: https://registry.npmjs.org/deepmerge/-/deepmerge-4.3.1.tgz
- Original dist/cjs.js SHA-256: `2e5160f84a1141bd927264afe4d15766f1e6cf07daef182b37ff53fea121de7d` (retained at `local/conformance/fixtures/deepmerge-4.3.1.cjs` for differential tests).
- The bundled is-mergeable-object implementation is unchanged. Upstream copyright and MIT licence are retained in LICENSE.
- Advisory: https://github.com/advisories/GHSA-gcqx-w48m-w2h4
- Upstream report and proposed repair: https://github.com/TehShrike/deepmerge/issues/273

The patch rejects __proto__, constructor and prototype at both target/source loops and defines own data properties rather than invoking inherited setters. All other merge behaviour is preserved. Regression tests compare ordinary configuration merging with the retained distribution and demonstrate the reported attack against that distribution. Remove this fork when a reviewed compatible upstream release fixes the issue.
