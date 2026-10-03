# Public website

The public site at https://mikaki.org uses Sorane 0.5 for Japanese and English Markdown content, canonical and alternate-language metadata, structured data, a sitemap, Markdown alternates and llms.txt. Edit `content/` and `sorane.yaml` to update content. `pages.json` lists the routes and navigation labels; the build rejects missing translations or content omitted from that manifest.

`build.mjs` keeps the existing shared woven renderer, stylesheet, hero and sign-in links, then `sorane.mjs` combines Sorane metadata and rendered Markdown with that visual shell. JSON-LD scripts use CSP hashes. Generated output is ignored by Git.

Articles with at least three level-two headings get a localized table of contents before their first section. It uses Sorane's rendered heading IDs, works without JavaScript and highlights the selected heading. The landing pages keep their existing hero layout.

```sh
npm ci
npm run build:website
npm run check:website
npm run test:website
```

The same build also emits the existing app-domain assets; app callback handling and the authentication Worker are separate. Deploy only the public site with `node_modules/.bin/wrangler deploy --config website/wrangler.jsonc`. The main-branch CI deployment continues to deploy both public domains.

Sorane's optional Mermaid dependency versions are overridden to audited releases. Diagram rendering is not used by this site.

ZenUML’s optional Playwright peer is aligned with the project’s Playwright 1.63.0 via a scoped override. Without it, npm accepts the optional peer mismatch at install time but fails `npm sbom`. The dependency CI job also generates an SBOM to catch this before merging.

Social previews use committed 1200×630 PNG captures of the existing woven hero, with a Japanese or English image selected by page language. After changing the hero or renderer, regenerate them with `npm run build:website`, `node website/export-social-preview.mjs`, then `npm run build:website` again. The capture needs an installed Playwright Chromium browser; normal builds only copy the committed images.

`audit-public.ts` checks all sitemap pages, reciprocal locale URLs, canonical URLs, JSON-LD CSP hashes, internal page/fragment links, reachability from the homepage, Markdown alternates, catalog, robots and social PNGs. The existing website test runs it against real local static-assets responses, plus negative cases. Production smoke runs the same audit against https://mikaki.org and retains its report. It checks crawlability and discovery signals, not search-engine indexing or rankings.

## Onboarding screenshots

The localized images in `screenshots/onboarding/` are maintained manually, separately from CI. Public enrollment/sign-in captures only make GET requests. Vault captures use a disposable local Worker, synthetic account/note and mocked PRF; they do not qualify production saving, recovery or physical devices.

To refresh, build an isolated checkout at the commit returned by the public OP `/version` (policy and Worker build), then run from the website checkout:

```sh
MIKAKI_SCREENSHOT_SOURCE_ROOT=/path/to/isolated-active-op node website/capture-onboarding.mjs
```

The script verifies the active source commit, pins downloaded deployed UI assets into the local fixture, checks saved/reopened sample text, and refuses a changed public version during capture. `screenshots/onboarding/provenance.json` records deployment/source identifiers, public and local asset hashes, image hashes and capture scope. Review both languages before publishing and update the visible capture dates.

`build:website` copies tracked PNGs and adds intrinsic dimensions and lazy loading. `test:website` checks image responses, dimensions, alt text, decoding and mobile overflow, including a missing-image regression. Invitation/integration links use the four public forms in `.github/ISSUE_TEMPLATE/`; never test these by submitting secrets or creating an unsolicited issue.
