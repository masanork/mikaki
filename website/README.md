# Public website

The public site at https://mikaki.org uses Sorane 0.5 for Japanese and English Markdown content, canonical and alternate-language metadata, structured data, a sitemap, Markdown alternates and llms.txt. Edit `content/` and `sorane.yaml` to update content.

`build.mjs` keeps the existing shared woven renderer, stylesheet, hero and sign-in links, then `sorane.mjs` combines Sorane metadata and rendered Markdown with that visual shell. JSON-LD scripts use CSP hashes. Generated output is ignored by Git.

```sh
npm ci
npm run build:website
npm run check:website
npm run test:website
```

The same build also emits the existing app-domain assets; app callback handling and the authentication Worker are separate. Deploy only the public site with `node_modules/.bin/wrangler deploy --config website/wrangler.jsonc`. The main-branch CI deployment continues to deploy both public domains.

Sorane's optional Mermaid dependency versions are overridden to audited releases. Diagram rendering is not used by this site.

ZenUML’s optional Playwright peer is aligned with the project’s Playwright 1.63.0 via a scoped override. Without it, npm accepts the optional peer mismatch at install time but fails `npm sbom`. The dependency CI job also generates an SBOM to catch this before merging.
