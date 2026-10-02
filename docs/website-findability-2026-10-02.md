# Public website findability and guide audit — 2026-10-02

## Scope and evidence

The production site at https://mikaki.org was inspected in Chrome. All six existing Japanese/English overview, integration and status pages rendered with one H1, distinct titles, canonical extensionless URLs, reciprocal locale alternates and the appropriate social image. English sign-in links retained `lang=en`.

The English status page's DOM exposed a broken Markdown alternate: `https://mikaki.org/en/en/security.md`. Sorane emits that alternate relative to the site root, while the custom visual adapter resolved it relative to the English page directory. Local real static-assets responses reproduced the doubled prefix and 404. Resolve the adapter's discovery URLs from the site root; the audit now follows every Markdown alternate rather than checking only that its tag exists.

The browser integration blocked navigation to robots.txt, so no production robots/sitemap/catalog response result is claimed from that browser session. The post-deployment audit below checks these endpoints directly from the GitHub runner. A deployment success alone is not recorded as a search-engine indexing result.

## Content gaps and changes

| Gap                                                                        | Change                                                                                                                         |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| New users had no invitation-to-sign-in walkthrough                         | Japanese and English getting-started guides; direct hero link                                                                  |
| Sign-in, Vault unlocking and native app availability were easy to conflate | Separate explanations with PRF, invitation and distribution limitations                                                        |
| Saving, plaintext export and passkey transfer had no public usage guide    | Vault guides covering saved vs unsaved content, independent name/note transfer, lock and recovery limits                       |
| Common troubleshooting required reading repository design documents        | Japanese and English FAQ with links to the relevant guides                                                                     |
| Integration guide stopped at three high-level steps                        | Registration inputs, backend responsibilities, state/nonce/PKCE, token validation, managed session checks and production scope |
| Status page only described application-initiated login                     | Include Web sign-in and distinguish authentication from decryption                                                             |
| Routes were repeated in several adapter expressions                        | One page manifest for navigation and route normalization; build rejects missing translations or omitted source pages           |
| Mobile page navigation would grow into a long vertical list                | Wrap guide navigation into compact rows and identify the current page                                                          |

The source contracts used for the guides are [RP integration](rp-integration.md), [client operations](rp-client-operations.md), [Vault design](personal-vault.md), [typed notes](vault-typed-attributes.md), [passkey transfer](vault-passkey-transfer.md) and [session lifecycle](session-lifecycle.md), together with the current Worker UI. Historical local evidence is not presented as a guarantee of real-device compatibility, recovery, production RP qualification or formal certification.

## Repeatable checks

`npm run build:website`, `npm run check:website` and `npm run test:website` cover the new twelve-page site. The website browser test invokes `website/audit-public.ts` against real local static-assets responses and checks:

- Sitemap coverage, unique canonical URLs and one H1 per page.
- Reciprocal `ja`, `en`, `x-default` alternates and English authentication destinations.
- Nonempty descriptions, social images and accessible Markdown alternates.
- Valid JSON-LD with matching CSP hashes.
- Every internal page link and heading fragment, plus reachability from the homepage.
- Robots, catalog and llms.txt discovery links.
- PNG response types and 1200×630 image dimensions.
- Mobile and desktop layout, no-script guide navigation, woven rendering and reduced motion.

Negative cases reject a wrong canonical URL, wrong translation URL, missing fragment, unpublished destination, missing JSON-LD, noindex header and blocked JSON-LD. Production smoke runs the same public audit after deployment and retains `website-findability.json` as a GitHub Actions artifact.

## Measuring discovery after release

Crawlable HTML and links provide a discoverable foundation; they do not establish that a search engine has indexed the site or improved its ranking. [Google's developer guide](https://developers.google.com/search/docs/fundamentals/get-started-developers) recommends crawlable links, sitemap discovery and URL inspection.

Once Search Console property access is available, record URL Inspection results for the homepage and each guide, the selected canonical, sitemap processing and indexed-page count. Then compare impressions, clicks and queries over a meaningful period after release, distinguishing Japanese and English pages. No Search Console access or ranking measurement was available during this audit. The [sitemap guide](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap) documents submission; do not infer submission from the existence of sitemap.xml.
