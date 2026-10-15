# Font review

Run `npm run preview:fonts` to refresh the desktop and narrow-screen comparisons
in Chromium (`comparison*.png`) and WebKit (`comparison*webkit.png`). The fixture
includes small Japanese text, IVS, supplementary-plane characters, administrative
PUA glyphs, synthetic bold and Inter. `npm run preview:fonts -- --serve` exposes
the same fixture on localhost for native Safari review.

`npm run test:fonts` checks both engines, including dynamic editor text and every
shipped WOFF2 chunk. It compares glyph rendering against the expected family
within the same engine and checks that IVS variants remain distinct. Chromium
also reports actual platform font use through CDP. Screenshots, traces and
request measurements are saved under `artifacts/font-rendering/` and uploaded
by CI. The narrow viewport covers responsive layout; it does not emulate an
actual iPhone or replace testing the Safari application.

The latest local Bunsen PUP inputs contain 6,705 of the reference font's 9,420
administrative private-use characters. The remaining 2,715 are intentionally
unsupported. `assets/fonts/coverage.json` records their codepoints. Text is kept
unchanged, including unsupported characters and variation selectors.

On 2026-10-15, the same fixture was also visually checked in the native
Safari 27.0.1 application on macOS: both Japanese styles, distinct IVS forms,
PUP glyphs, Inter and synthetic bold rendered correctly. All-chunk decoding
is covered by the automated Chromium/WebKit tests.

## Reproduce the font assets

Normal builds consume committed assets. Regeneration requires the external gjs
checkout and its six generated Bunsen TTFs, with exact input hashes and tool
versions in `scripts/fonts.lock.json`:

```sh
python3.12 -m venv local/generated/font-venv
local/generated/font-venv/bin/python -m pip install -r scripts/fonts-requirements.txt
npm run build:fonts
npm run check:fonts-reproducible
npx playwright install chromium webkit
npm run test:fonts
```

`MIKAKI_GJS_DIR` changes the checkout location; `MIKAKI_FONT_PYTHON` changes the
interpreter. Rust 1.98.1 and wasm-pack 0.15.0 are required. gjs performs IVS-aware
subsetting. fontTools merges corresponding Base/Ext/PUP chunks, verifies glyph
outlines and metrics, and applies lossless WOFF2 compression. Japanese uses one
physical font per style and range so WebKit can find Ext IVS correctly. Japanese precedes Latin in the stack for WebKit IVS selection; their CSS
ranges and physical cmaps assign Inter-supported characters exclusively to
Inter. DOM text advances are compared with explicit-family references as well as
Canvas pixels, because WebKit can select different fonts in these paths.
The Mikaki Bunsen CSS family prefix avoids fallback to locally installed
Bunsen fonts outside the webfont ranges. Merged-font timestamps use the source-date epoch recorded in the lock file.

The official additional Mincho is a build-time coverage reference only. Bundled
licenses and attribution are in `assets/fonts/NOTICE.txt`.
