/** Exercise the exact native boundary in the pinned workerd provider. */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const root = fileURLToPath(new URL('../..', import.meta.url));
const fixture = JSON.parse(
  await readFile(new URL('../../crates/oidc/testdata/es256-rfc6979.json', import.meta.url), 'utf8'),
) as Record<string, string>;
const bytes = (key: string) => Buffer.from(fixture[key], 'base64url');
const message = Buffer.from(fixture.message);

test('workerd ES256 raw-key compatibility, async input snapshots and provider failure', async () => {
  const bundle = await build({
    stdin: {
      resolveDir: root,
      loader: 'js',
      contents: `
        import { nativeVerifyEs256 } from './crates/oidc/src/native_es256.ts';
        export default { async fetch(request) {
          const { inputs, mutate, fault } = await request.json();
          const bytes = inputs.map(input => new Uint8Array(input));
          const method = fault === 'import' ? 'importKey' : 'verify';
          const original = crypto.subtle[method];
          if (fault) crypto.subtle[method] = () => { throw new Error('injected failure'); };
          try {
            const pending = nativeVerifyEs256(...bytes);
            if (mutate) bytes.forEach(input => input.fill(0));
            return Response.json(await pending);
          } catch { return new Response(null, { status: 422 }); }
          finally { if (fault) crypto.subtle[method] = original; }
        } };`,
    },
    bundle: true,
    write: false,
    format: 'esm',
    target: 'es2022',
  });
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: bundle.outputFiles[0].text,
      compatibilityDate: '2026-09-23',
    }),
  );
  const call = (
    key: Uint8Array,
    signature: Uint8Array,
    input = message,
    mutate = false,
    fault?: string,
  ) =>
    mf.dispatchFetch('http://test.invalid/', {
      method: 'POST',
      body: JSON.stringify({
        inputs: [key, signature, input].map((bytes) => [...bytes]),
        mutate,
        fault,
      }),
    });
  try {
    for (const key of ['public_key', 'compressed_public_key'])
      for (const signature of ['signature', 'alternate_signature']) {
        assert.equal(await (await call(bytes(key), bytes(signature))).json(), true);
        assert.equal(
          await (await call(bytes(key), bytes(signature), Buffer.from('wrong'))).json(),
          false,
        );
      }
    const concurrent = await Promise.all(
      Array.from({ length: 8 }, () => call(bytes('public_key'), bytes('signature'), message, true)),
    );
    for (const response of concurrent) assert.equal(await response.json(), true);
    for (const fault of ['import', 'verify'])
      assert.equal(
        (await call(bytes('public_key'), bytes('signature'), message, false, fault)).status,
        422,
      );
    const invalidPoint = Buffer.alloc(65);
    invalidPoint[0] = 4;
    assert.equal((await call(invalidPoint, bytes('signature'))).status, 422);
    assert.equal((await call(bytes('public_key'), Buffer.alloc(70, 0x30))).status, 422);
  } finally {
    await mf.dispose();
  }
});
