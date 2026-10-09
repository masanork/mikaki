import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { fileURLToPath } from 'node:url';

const entry = process.env['MIKAKI_UI_ENTRY'] ?? 'login';
const outDir = process.env['MIKAKI_UI_OUTDIR'] ?? '../../../target/worker-ui-check';
if (!['login', 'vault', 'admin', 'complete', 'logout', 'waitlist'].includes(entry))
  throw new Error('Unknown Worker UI entry');

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  plugins: [
    svelte(),
    paraglideVitePlugin({
      project: '../../../project.inlang',
      outdir: './paraglide',
      emitTsDeclarations: true,
      strategy: ['cookie', 'preferredLanguage', 'baseLocale'],
    }),
  ],
  build: {
    outDir,
    emptyOutDir: false,
    sourcemap: process.env['MIKAKI_UI_COVERAGE'] === '1' ? 'hidden' : false,
    lib: {
      entry: fileURLToPath(new URL(`./${entry}.ts`, import.meta.url)),
      formats: ['es'],
      fileName: () => `${entry}.js`,
      cssFileName: entry,
    },
    // Vite's ES library output normally preserves whitespace. The Vault entry
    // uses the supported final output minifier without splitting or adding assets.
    rolldownOptions: {
      output: { inlineDynamicImports: true, ...(entry === 'vault' ? { minify: true } : {}) },
    },
  },
});
