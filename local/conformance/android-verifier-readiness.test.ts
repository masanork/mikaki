import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Miniflare, Response as RuntimeResponse, convertV4MiniflareOptions } from 'miniflare';

test('private verifier readiness pins policy/client and current Google status without forwarding caller headers', async () => {
  const token = Buffer.alloc(32, 4).toString('base64url');
  const policy = Buffer.alloc(32, 5).toString('base64url');
  const valid = {
    format: 'android-key-attestation-readiness-v1',
    client_id: 'mikaki-android-wallet',
    verifier_policy_hash: policy,
    status_valid_until: Math.floor(Date.now() / 1000) + 300,
  };
  let payload: Record<string, unknown> = valid;
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
        ANDROID_VERIFIER_POLICY_HASH: policy,
        ANDROID_VERIFIER_CLIENT_ID: 'mikaki-android-wallet',
      },
      outboundService: async (request) => {
        assert.equal(request.url, 'https://verifier.example/readyz');
        assert.equal(request.method, 'GET');
        assert.equal(request.headers.get('Authorization'), `Bearer ${token}`);
        assert.equal(request.headers.get('Cookie'), null);
        return RuntimeResponse.json(payload);
      },
    }),
  );
  try {
    const request = () =>
      mf.dispatchFetch('https://android-verifier.internal/readyz', {
        headers: { Cookie: 'never forward', Authorization: 'Bearer caller' },
      });
    assert.equal((await request()).status, 200);
    for (const change of [
      { verifier_policy_hash: 'different' },
      { client_id: 'other-wallet' },
      { status_valid_until: 1 },
      { status_valid_until: Math.floor(Date.now() / 1000) + 7200 },
      { unreviewed: 'never forward' },
    ]) {
      payload = { ...valid, ...change };
      assert.equal((await request()).status, 503);
    }
  } finally {
    await mf.dispose();
  }
});
