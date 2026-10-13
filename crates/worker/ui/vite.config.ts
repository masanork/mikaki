import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { fileURLToPath } from 'node:url';
import { minifySync } from 'rolldown/utils';

const entry = process.env['MIKAKI_UI_ENTRY'] ?? 'login';
const outDir = process.env['MIKAKI_UI_OUTDIR'] ?? '../../../target/worker-ui-check';
if (
  ![
    'login',
    'vault',
    'admin',
    'complete',
    'logout',
    'waitlist',
    'work-sources',
    'work-preparations',
    'work-copy',
  ].includes(entry)
)
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
    {
      name: 'work-es-module-minification',
      renderChunk(code, chunk) {
        if (!entry.startsWith('work-')) return null;
        const result = minifySync(chunk.fileName, code, { module: true, sourcemap: true });
        if (result.errors.length) throw new Error('Work UI module minification failed');
        return { code: result.code, map: result.map ?? null };
      },
    },
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
    // Vite's ES library output normally preserves whitespace. Work entries
    // use module-aware minification in renderChunk and retain composed source maps.
    rolldownOptions: {
      external: ['/work/browser-assistant.js'],
      output: {
        inlineDynamicImports: true,
        ...(['vault', 'work-sources', 'work-preparations', 'work-copy'].includes(entry)
          ? { minify: entry === 'vault' }
          : {}),
      },
    },
  },
});
