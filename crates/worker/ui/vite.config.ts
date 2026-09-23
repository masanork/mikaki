import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { fileURLToPath } from 'node:url';

const entry = process.env['MIKAKI_UI_ENTRY'] ?? 'login';
const outDir = process.env['MIKAKI_UI_OUTDIR'] ?? '../../../target/worker-ui-check';
if (!['login', 'vault'].includes(entry)) throw new Error('Unknown Worker UI entry');

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
    lib: {
      entry: fileURLToPath(new URL(`./${entry}.ts`, import.meta.url)),
      formats: ['es'],
      fileName: () => `${entry}.js`,
    },
    rolldownOptions: { output: { inlineDynamicImports: true } },
  },
});
