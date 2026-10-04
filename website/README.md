# Public website

The public site at https://mikaki.org uses Sorane 0.5 for Japanese and English Markdown content, canonical and alternate-language metadata, structured data, a sitemap, Markdown alternates and llms.txt. Edit `content/` and `sorane.yaml` to update content. `pages.json` lists routes and labels. `navigation.json` assigns every guide to one of three audience groups; the build rejects omissions, duplicate assignments and missing translations. `layout.mjs` generates the shared header, four primary destinations, section navigation, breadcrumbs and grouped footer.

`build.mjs` emits the shared styles and application information pages in Japanese and English. `sorane.mjs` combines Sorane metadata and rendered Markdown with the public layout. The woven renderer is confined to the homepage hero; article content uses a quiet reading surface. Existing public URLs and authentication/app callbacks are preserved. JSON-LD scripts use CSP hashes. Generated output is ignored by Git.

The broad `/*` CSP includes only the Japanese root page's hashes. Other canonical pages detach it and set a policy containing only their own hashes; the exact `/` route never overrides CSP. This avoids the [Workers Assets deployment-only root-detachment defect](https://github.com/cloudflare/workers-sdk/issues/11351), which local `wrangler dev` does not reproduce. Non-script restrictions are identical for every route, and the build enforces Cloudflare's 2,000-character line and 100-rule limits. Deterministic tests inspect the generated policies and model the retained-default defect; the audit checks the intersection of repeated CSP fields, not just the presence of a hash anywhere. Local and CI browser checks do not prove deployed header behavior; the production response audit remains the deployment check.

Articles with at least three level-two headings get a native, collapsed contents disclosure before their first section. It uses Sorane's rendered heading IDs, works without JavaScript and highlights the selected heading. The homepage body has three audience guides followed by one contact section; its editor-facing structure is checked during the build.

```sh
npm ci
npm run build:website
npm run check:website
npm run test:website
```

The same build also emits the existing app-domain assets; app callback handling and the authentication Worker are separate. Deploy only the public site with `node_modules/.bin/wrangler deploy --config website/wrangler.jsonc`. The main-branch CI deployment continues to deploy both public domains.

Sorane's optional Mermaid dependency versions are overridden to audited releases. Diagram rendering is not used by this site.

ZenUML’s optional Playwright peer is aligned with the project’s Playwright 1.63.0 via a scoped override. Without it, npm accepts the optional peer mismatch at install time but fails `npm sbom`. The dependency CI job also generates an SBOM to catch this before merging.

Social previews use committed 1200×630 PNG captures of the public woven hero, with a Japanese or English image selected by page language. After changing the hero or renderer, regenerate them with `npm run build:website`, `node website/export-social-preview.mjs`, then `npm run build:website` again. The capture needs an installed Playwright Chromium browser; normal builds only copy the committed images.

`audit-public.ts` checks all sitemap pages, reciprocal locale URLs, canonical URLs, JSON-LD CSP hashes, internal page/fragment links, reachability from the homepage, Markdown alternates, catalog, robots and social PNGs. The existing website test runs it against real local static-assets responses, plus negative cases. Production smoke runs the same audit against https://mikaki.org and retains its report. It checks crawlability and discovery signals, not search-engine indexing or rankings.

## Onboarding screenshots

The localized images in `screenshots/onboarding/` are maintained manually, separately from CI. Public enrollment/sign-in captures only make GET requests. Vault captures use a disposable local Worker, synthetic account/note and mocked PRF; they do not qualify production saving, recovery or physical devices.

To refresh, prepare an isolated clean checkout at the commit returned by the public OP `/version`, with dependencies and `worker-build` installed, then run from the website checkout:

```sh
MIKAKI_SCREENSHOT_SOURCE_ROOT=/path/to/isolated-active-op node website/capture-onboarding.mjs
```

The script rejects tracked/untracked source changes, rebuilds ignored policy/Worker artifacts from the active source commit, pins downloaded deployed UI assets into the local fixture, checks saved/reopened sample text, and refuses a changed public version during capture. `screenshots/onboarding/provenance.json` records deployment/source identifiers, public and local asset hashes, image hashes and capture scope. Review both languages before publishing and update the visible capture dates.

`build:website` copies tracked PNGs and adds intrinsic dimensions and lazy loading. `test:website` checks image responses, dimensions, alt text, decoding and mobile overflow, including a missing-image regression. Invitation/integration links use the four public forms in `.github/ISSUE_TEMPLATE/`; never test these by submitting secrets or creating an unsolicited issue.

## Accessibility and layout checks

The design targets WCAG 2.2 AA without claiming full conformance. Shared pages include a skip-to-content link, semantic/named navigation, visible keyboard focus, meaningful language links, readable contrast, underlined prose links and responsive layouts. Tables use scoped column headers and named keyboard-focusable scrolling regions; code blocks can also be focused for scrolling. Current guide selection is shown with a border and text weight as well as color. Native contents disclosures and all navigation remain usable without JavaScript.

The homepage pause toggle stops the decorative renderer and retains the choice in sessionStorage for the same tab. Device reduced-motion settings force a paused state. Article and app-information pages have no moving background. Forced-colors and print styles keep content and controls available. Do not reintroduce full-page animation or hide content behind animation initialization.

`test:website` runs axe's WCAG A/AA tags on every public and app-information page, checks keyboard skipping/contents/table scrolling, pause persistence/reduced motion, 320 CSS px reflow (the 400% zoom equivalent at 1280px) and text-spacing overrides. It also captures desktop/mobile layouts. `local/test/demo-rp.test.ts` checks the demo's signed-out/signed-in accessibility and preserves the existing login, CSRF and logout tests. Automation is not a substitute for physical-device VoiceOver/NVDA qualification; the [public statement](content/accessibility.md) records that remaining scope.
