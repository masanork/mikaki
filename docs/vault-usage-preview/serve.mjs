import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { transform } from 'esbuild';

export async function startPreview(port = 0) {
  const woven = await readFile(
    new URL('../../crates/worker/ui/woven-gate.ts', import.meta.url),
    'utf8',
  );
  const { code } = await transform(woven, { loader: 'ts', target: 'es2022', format: 'esm' });
  const routes = new Map([
    ['/', ['index.html', 'text/html; charset=utf-8']],
    ['/index.html', ['index.html', 'text/html; charset=utf-8']],
    ['/prototype.css', ['prototype.css', 'text/css; charset=utf-8']],
    ['/prototype.js', ['prototype.js', 'text/javascript; charset=utf-8']],
  ]);
  const server = createServer(async (request, response) => {
    const path = new URL(request.url ?? '/', 'http://localhost').pathname;
    if (request.method !== 'GET') {
      response.writeHead(405).end();
      return;
    }
    try {
      if (path === '/woven-gate.js') {
        response
          .writeHead(200, {
            'Content-Type': 'text/javascript; charset=utf-8',
            'Cache-Control': 'no-store',
          })
          .end(code);
        return;
      }
      const route = routes.get(path);
      if (!route) {
        response.writeHead(404).end();
        return;
      }
      const bytes = await readFile(new URL(route[0], import.meta.url));
      response.writeHead(200, { 'Content-Type': route[1], 'Cache-Control': 'no-store' }).end(bytes);
    } catch {
      response.writeHead(500).end();
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  const address = server.address();
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.MIKAKI_PREVIEW_PORT ?? 4178);
  if (!Number.isInteger(port) || port < 1025 || port > 65535)
    throw new Error('Invalid preview port');
  const server = await startPreview(port);
  console.log(`Fictional Vault preview: ${server.url}`);
  for (const signal of ['SIGINT', 'SIGTERM'])
    process.once(signal, () => {
      void server.close();
    });
}
