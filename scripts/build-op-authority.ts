/** Package the named storage authorities beside the verified Rust shim. */
import { build } from 'esbuild';

await build({
  entryPoints: ['crates/worker/service/entrypoint.ts'],
  outfile: 'crates/worker/build/worker/service.mjs',
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  external: ['cloudflare:workers'],
  loader: { '.sql': 'text' },
  plugins: [
    {
      name: 'verified-rust-shim',
      setup(builder) {
        builder.onResolve({ filter: /build\/worker\/shim\.mjs$/ }, () => ({
          path: './shim.mjs',
          external: true,
        }));
      },
    },
  ],
});
