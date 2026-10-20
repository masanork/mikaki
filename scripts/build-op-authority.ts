/** Package the named storage authorities beside the verified Rust shim. */
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export async function buildOpAuthority(profile: 'default' | 'messaging-beta' = 'default') {
  const directory = profile === 'default' ? 'build' : 'build-messaging-beta';
  await build({
    entryPoints: ['crates/worker/service/entrypoint.ts'],
    outfile: `crates/worker/${directory}/worker/service.mjs`,
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
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error('Usage: node scripts/build-op-authority.ts');
  await buildOpAuthority();
}
