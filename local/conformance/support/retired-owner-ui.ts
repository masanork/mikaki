/** Test-only host for retired editors. There is no legacy product URL or export. */
import { build } from 'vite';
import type { DispatchFetch } from 'miniflare';
type Worker = { fetch: DispatchFetch };
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

let script: Promise<Buffer> | undefined;
async function compiled() {
  const out = new URL('../../generated/retired-owner-ui/', import.meta.url);
  await build({
    configFile: fileURLToPath(new URL('../../../crates/worker/ui/vite.config.ts', import.meta.url)),
    logLevel: 'error',
    build: {
      outDir: fileURLToPath(out),
      lib: {
        entry: fileURLToPath(new URL('./retired-owner-entry.ts', import.meta.url)),
        formats: ['es'],
        fileName: () => 'vault.js',
      },
    },
  });
  return readFile(new URL('vault.js', out));
}
export async function withRetiredOwnerUi<T extends Worker>(worker: T): Promise<T> {
  const body = await (script ??= compiled());
  return new Proxy(worker, {
    get(target, property) {
      if (property === 'fetch')
        return async (...args: Parameters<Worker['fetch']>) => {
          const response = await target.fetch(...args);
          const input = args[0];
          const url = new URL(
            typeof input === 'string' ? input : 'url' in input ? input.url : input.href,
          );
          if (url.pathname === '/vault' && response.status === 200) {
            const headers = new Headers(Object.fromEntries(response.headers));
            const csp = headers.get('Content-Security-Policy');
            if (csp) headers.set('Content-Security-Policy', csp.replace(" 'wasm-unsafe-eval'", ''));
            return new Response(await response.text(), { status: 200, headers });
          }
          if (url.pathname !== '/vault/vault.js' || response.status !== 200) return response;
          await response.arrayBuffer();
          const headers = new Headers(Object.fromEntries(response.headers));
          headers.delete('Content-Length');
          headers.delete('Content-Encoding');
          return new Response(body.toString('utf8'), { status: 200, headers });
        };
      const value: unknown = Reflect.get(target, property);
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });
}
