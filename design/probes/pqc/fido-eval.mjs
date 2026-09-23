import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

const page = await readFile(new URL('./fido-eval.html', import.meta.url));
const server = createServer((request, response) => {
  if (request.url !== '/' || request.method !== 'GET') {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy':
      "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'",
    'Referrer-Policy': 'no-referrer',
  });
  response.end(page);
});
server.listen(8789, '127.0.0.1', () => {
  console.log('Open http://localhost:8789/ in the browser that will use the dongle.');
});
