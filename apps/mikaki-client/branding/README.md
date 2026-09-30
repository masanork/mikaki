# Native app icon

The source SVGs retain the four tiles, -12 degree rotation and blue palette of
`crates/worker/ui/auth.css`. A navy background provides contrast at launcher sizes.
Android has separate adaptive background, foreground and monochrome layers.
iOS icons are flattened onto navy; the OS applies its icon mask. Desktop assets
include PNG, ICNS and ICO variants.

Regenerate from `apps/mikaki-client` with the pinned Tauri CLI and Python Pillow
(install Pillow into your development Python environment first):

```sh
npm ci
npm run generate:icons
```

The manifest paths are relative to `icons.json`. The CLI updates desktop files
in `src-tauri/icons` and the initialized Android/iOS projects under `src-tauri/gen`.
Commit the source SVGs and generated assets together. See the
[Tauri icon command](https://v2.tauri.app/reference/cli/#icon).

The final Python step removes the CLI's residual alpha from the iOS PNGs and
writes RGB images. This is an asset-generation dependency, not an app dependency.
