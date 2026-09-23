import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';

const wasmModule = fileURLToPath(new URL('./pkg-web/mikaki_pqc_probe.js', import.meta.url));
const wasmBinary = fileURLToPath(new URL('./pkg-web/mikaki_pqc_probe_bg.wasm', import.meta.url));
const server = createServer(async (request, response) => {
  const files = new Map([
    ['/pkg-web/mikaki_pqc_probe.js', [wasmModule, 'text/javascript']],
    ['/pkg-web/mikaki_pqc_probe_bg.wasm', [wasmBinary, 'application/wasm']],
  ]);
  const requested = files.get(request.url);
  if (!requested) {
    response.writeHead(404).end();
    return;
  }
  try {
    response.writeHead(200, { 'Content-Type': requested[1] }).end(await readFile(requested[0]));
  } catch {
    response.writeHead(500).end();
  }
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${server.address().port}/`);
  const passed = await page.evaluate(async () => {
    const probe = await import('/pkg-web/mikaki_pqc_probe.js');
    await probe.default();
    return probe.self_test();
  });
  assert.equal(passed, true);
  console.log('PQC browser Wasm ML-KEM, ML-DSA and HPKE probe passed');
} finally {
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
}
