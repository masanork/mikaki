// Test-only MDS transport. No conformance trust anchor is embedded in the product.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import init, * as wasm from '../../crates/browser-wasm/pkg/mikaki_browser_wasm.js';
await init({
  module_or_path: readFileSync(
    new URL('../../crates/browser-wasm/pkg/mikaki_browser_wasm_bg.wasm', import.meta.url),
  ),
});
const directory = new URL('../../target/fido-mds/', import.meta.url);
mkdirSync(directory, { recursive: true });
const point = Buffer.from(
  '048a622cf7625b42ebe966c613cac00d56159948aa75fcc8be51c9b48b4ca1403c441e4c3f4eea63b3fad83cc1c49d9d5c47cf09d7890289c21adabfbd2b29cda27ab422ff8414addb0f7acf13122ad93a409526eae90c56d764e82cfbea5ae179',
  'hex',
);
const anchor_spki = createPublicKey({
  key: {
    kty: 'EC',
    crv: 'P-384',
    x: point.subarray(1, 49).toString('base64url'),
    y: point.subarray(49).toString('base64url'),
  },
  format: 'jwk',
})
  .export({ type: 'spki', format: 'der' })
  .toString('base64url');
async function download(url, options = {}, remaining = 3) {
  const u = new URL(url);
  if (
    u.protocol !== 'https:' ||
    !['mds3.fido.tools', 'mds3.certinfra.fidoalliance.org'].includes(u.hostname) ||
    u.port ||
    u.username ||
    u.password
  )
    throw Error(`MDS destination rejected: ${u.href}`);
  const response = await fetch(u, {
    ...options,
    redirect: 'manual',
    signal: AbortSignal.timeout(20000),
  });
  if (response.status >= 300 && response.status < 400 && remaining > 0)
    return download(new URL(response.headers.get('location'), u).href, {}, remaining - 1);
  if (!response.ok) throw Error(`MDS HTTP ${response.status}`);
  const chunks = [];
  let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length;
    if (length > 4194304) throw Error('MDS too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
const endpoint = `http://localhost:${process.env.FIDO_PORT ?? 8080}`;
const endpoints = JSON.parse(
  (
    await download('https://mds3.fido.tools/getEndpoints', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ endpoint }),
    })
  ).toString('utf8'),
);
if (endpoints.status !== 'ok' || endpoints.result.length > 12) throw Error('Invalid endpoint list');
const blobs = await Promise.all(
  endpoints.result.map((url) => download(url).then((b) => b.toString('utf8'))),
);
const cache = new Map();
let accepted = 0;
for (const [i, jwt] of blobs.entries()) {
  let crls = [];
  try {
    const urls = JSON.parse(wasm.mds_crl_urls(jwt));
    crls = await Promise.all(
      urls.map((url) => {
        if (!cache.has(url))
          cache.set(
            url,
            download(url).then((b) => b.toString('base64url')),
          );
        return cache.get(url);
      }),
    );
  } catch {
    console.log(`MDS ${i}: CRL transport rejected`);
  }
  const input = { jwt, anchor_spki, now: Math.floor(Date.now() / 1000), crls };
  writeFileSync(new URL(`${i}.json`, directory), JSON.stringify(input));
  try {
    const verified = JSON.parse(wasm.verify_mds(JSON.stringify(input)));
    console.log(`MDS ${i}: verified BLOB ${verified.number}, ${verified.entries.length} entries`);
    accepted++;
  } catch {
    console.log(`MDS ${i}: rejected by verifier`);
  }
}
if (!accepted) throw Error('No valid MDS BLOB verified');
