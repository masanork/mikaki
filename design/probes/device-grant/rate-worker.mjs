// Local fixture only: the test supplies time and an HMAC key. Not a public API.
const alphabet = /^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{8}$/;

async function index(input, key) {
  if (typeof input !== 'string' || !/^[A-Za-z2-9-]{8,9}$/.test(input)) return 'invalid';
  const normalized = input.toUpperCase().replace(/^(.{4})-(.{4})$/, '$1$2');
  if (!alphabet.test(normalized)) return 'invalid';
  const raw = Uint8Array.from(key.match(/../g), (hex) => Number.parseInt(hex, 16));
  const hmac = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const digest = await crypto.subtle.sign(
    'HMAC',
    hmac,
    new TextEncoder().encode(`mikaki-device-user-code-v1\0${normalized}`),
  );
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

export default {
  async fetch(request, env) {
    const { code, now } = await request.json();
    try {
      const userIndex = await index(code, env.TEST_KEY);
      const bucket = Math.floor(now / 60);
      const results = await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO rate_probe(bucket,attempts) VALUES(?,1)
          ON CONFLICT(bucket) DO UPDATE SET attempts=attempts+1
          WHERE attempts<5 RETURNING attempts`,
        ).bind(bucket),
        env.DB.prepare(
          `SELECT user_index FROM lookup_probe
          WHERE user_index=? AND state='pending' AND expires_at>? AND changes()=1`,
        ).bind(userIndex, now),
      ]);
      if (results[0].results.length === 0)
        return Response.json({ error: 'limited' }, { status: 429 });
      // Internal-only signal for the experiment, never an actual public response.
      return Response.json({ matched: results[1].results.length === 1 });
    } catch {
      return Response.json({ error: 'unavailable' }, { status: 503 });
    }
  },
};
