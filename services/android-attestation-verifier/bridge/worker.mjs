// Private service-binding bridge to the operator-provisioned JVM verifier.
// Never forward caller authorization, cookies or request-provided upstream URLs.
const unavailable = () =>
  Response.json({ verified: false }, { status: 503, headers: { 'Cache-Control': 'no-store' } });
async function bounded(stream, limit) {
  if (!stream) throw Error('missing body');
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw Error('body limit');
      chunks.push(value);
    }
  } catch (e) {
    await reader.cancel().catch(() => {});
    throw e;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/verify' || url.search) {
      return new Response(null, { status: 404 });
    }
    try {
      const target = new URL(env.ANDROID_VERIFIER_URL);
      if (
        target.protocol !== 'https:' ||
        target.username ||
        target.password ||
        target.pathname !== '/verify' ||
        target.search ||
        target.hash ||
        target.href !== env.ANDROID_VERIFIER_URL
      )
        throw Error('configuration');
      if (!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(env.ANDROID_VERIFIER_TOKEN || ''))
        throw Error('configuration');
      if (request.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json')
        throw Error('content type');
      const body = await bounded(request.body, 65536);
      const response = await fetch(target, {
        method: 'POST',
        body,
        redirect: 'manual',
        signal: AbortSignal.timeout(8000),
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${env.ANDROID_VERIFIER_TOKEN}`,
        },
      });
      if (
        response.status !== 200 ||
        response.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json'
      )
        throw Error('upstream');
      const result = await bounded(response.body, 4096);
      return new Response(result, {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      });
    } catch {
      return unavailable();
    }
  },
};
