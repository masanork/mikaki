/** Native Git-only productive/evidence transport; never a mint or raw RPC. */
import { jsonBody } from './worker';
export async function gitOp(env: { OP_GIT_STORE: Fetcher }, input: Record<string, unknown>) {
  const response = await env.OP_GIT_STORE.fetch('https://private.invalid/git-effect', {
    method: 'POST',
    body: JSON.stringify(input),
  });
  if (response.status !== 200) throw new Error('git_store_unavailable');
  return jsonBody(response);
}
