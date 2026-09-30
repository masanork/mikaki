# Native app icon

The shared source is [`branding/mikaki-mark.svg`](../../../branding/mikaki-mark.svg).
The woven fence motif refers to 御垣. Navy-backed icons use the established blue
palette; Android has separate adaptive background, foreground and monochrome
layers. iOS icons are flattened onto navy. Desktop assets include PNG, ICNS and ICO.

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
