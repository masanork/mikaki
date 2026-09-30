/** Isolated Miniflare probe: caller abort does not imply downstream completion stopped. */
import assert from 'node:assert/strict';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

let downstreamFinished = false;
let downstreamSignalAborted;
const runtime = new Miniflare(
  convertV4MiniflareOptions({
    name: 'userinfo-timeout-probe',
    modules: true,
    script: `export default {
      async fetch(_request, env) {
        try {
          const request = new Request('https://claim.internal/', {
            signal: AbortSignal.timeout(100),
          });
          await env.CLAIM.fetch(request);
          return new Response('completed');
        } catch (error) {
          return new Response(error.name, { status: 503 });
        }
      },
    }`,
    serviceBindings: {
      CLAIM: async (request) => {
        await new Promise((resolve) => setTimeout(resolve, 500));
        downstreamSignalAborted = request.signal.aborted;
        downstreamFinished = true;
        return new Response('claim completed');
      },
    },
  }),
);

try {
  const response = await runtime.dispatchFetch('https://userinfo-timeout-probe.invalid/');
  assert.equal(response.status, 503);
  assert.equal(await response.text(), 'TimeoutError');
  assert.equal(downstreamFinished, false);
  await new Promise((resolve) => setTimeout(resolve, 650));
  assert.equal(downstreamFinished, true);
  assert.equal(downstreamSignalAborted, false);
  console.log('caller timed out while downstream service-binding work continued');
} finally {
  await runtime.dispose();
}
