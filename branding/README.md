# Mikaki branding

`mikaki-mark.svg` is the shared source for the woven fence (御垣) logo.
It uses three uprights and two alternating rails, an eight-degree tilt, and
the established blue palette. The accepted mark is 18% larger than the first
fence concept. Compound paths preserve the weave without document-wide IDs
or masks, so multiple inline marks can coexist.

Worker/Svelte and local screens embed the checked-in mark. App icons and
favicons use a navy background. Android adaptive icons scale the foreground
to retain launcher mask clearance; monochrome icons retain the weave.

Regenerate all derived SVGs, desktop/mobile icons and favicons from
`apps/mikaki-client` with `npm run generate:icons`. This requires that app's
pinned Tauri CLI and Python Pillow. The generator also writes the native UI
and local UI copies. Commit source and derived assets together.

The ICO contains 16/32/48/64px variants. Modern pages explicitly select
`/favicon.svg`; the production issuer also serves `/favicon.ico` and
`/favicon-32x32.png`. Native callback-host isolation is unchanged.
