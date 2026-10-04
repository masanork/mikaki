import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Miniflare, Response as RuntimeResponse, convertV4MiniflareOptions } from 'miniflare';
const token = Buffer.alloc(32, 1).toString('base64url');
test('private Android verifier bridge pins upstream, strips caller headers and fails closed on invalid bounded responses', async () => {
  let mode = 'good';
  let calls = 0;
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      scriptPath: new URL(
        '../../services/android-attestation-verifier/bridge/worker.mjs',
        import.meta.url,
      ).pathname,
      compatibilityDate: '2026-10-02',
      bindings: {
        ANDROID_VERIFIER_URL: 'https://verifier.example/verify',
        ANDROID_VERIFIER_TOKEN: token,
      },
      outboundService: async (request) => {
        calls++;
        assert.equal(request.url, 'https://verifier.example/verify');
        assert.equal(request.method, 'POST');
        assert.equal(request.headers.get('Authorization'), `Bearer ${token}`);
        assert.equal(request.headers.get('Cookie'), null);
        assert.equal(request.headers.get('OAuth-Client-Attestation'), null);
        assert.deepEqual(await request.json(), { evidence: 'test' });
        if (mode === 'redirect')
          return new RuntimeResponse(null, {
            status: 302,
            headers: { Location: 'https://evil.example' },
          });
        if (mode === 'error') return new RuntimeResponse('{}', { status: 403 });
        if (mode === 'oversize') return RuntimeResponse.json({ extra: 'x'.repeat(4096) });
        if (mode === 'content')
          return new RuntimeResponse('{}', { headers: { 'Content-Type': 'text/plain' } });
        if (mode === 'timeout') await new Promise((resolve) => setTimeout(resolve, 9000));
        return RuntimeResponse.json({ verified: true });
      },
    }),
  );
  const request = (body = JSON.stringify({ evidence: 'test' })) =>
    mf.dispatchFetch('https://android-verifier.internal/verify', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer attacker',
        Cookie: 'private',
        'OAuth-Client-Attestation': 'private',
      },
      body,
    });
  try {
    let response = await request();
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { verified: true });
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
    for (mode of ['redirect', 'error', 'oversize', 'content', 'timeout']) {
      response = await request();
      assert.equal(response.status, 503, mode);
      assert.deepEqual(await response.json(), { verified: false });
    }
    const before = calls;
    assert.equal((await request('x'.repeat(65537))).status, 503);
    assert.equal(calls, before);
    assert.equal(
      (await mf.dispatchFetch('https://android-verifier.internal/verify?other')).status,
      404,
    );
    await mf.setOptions(
      convertV4MiniflareOptions({
        modules: true,
        scriptPath: new URL(
          '../../services/android-attestation-verifier/bridge/worker.mjs',
          import.meta.url,
        ).pathname,
        compatibilityDate: '2026-10-02',
        bindings: {
          ANDROID_VERIFIER_URL: 'http://evil.example/verify',
          ANDROID_VERIFIER_TOKEN: token,
        },
      }),
    );
    assert.equal((await request()).status, 503);
  } finally {
    await mf.dispose();
  }
});
