/** Native mint-only metadata/custody transport; no public or raw RPC. */
import { jsonBody } from './worker';
import { closed, integer } from './protocol';
import type { MintRecord } from './protocol';
export async function mintOp(env: { OP_MINT_STORE: Fetcher }, input: Record<string, unknown>) {
  const response = await env.OP_MINT_STORE.fetch('https://private.invalid/mint-effect', {
    method: 'POST',
    body: JSON.stringify(input),
  });
  if (response.status !== 200) throw new Error('effect_store_unavailable');
  return jsonBody(response);
}
/** Already retained refusal proof only; no provider access, admission or secret. */
export async function synchronizeMintClosure(env: { OP_MINT_STORE: Fetcher }, r: MintRecord) {
  if (r.state !== 'closed' || !r.observation || !(r.receipt || r.refusal?.receipt))
    throw new Error('effect_unconfirmed');
  let synced = false;
  try {
    const v = await mintOp(env, {
      action: r.refusal ? 'mint-close' : 'capture-mint-closed',
      attempt_id: r.plan.attempt_id,
      digest: r.plan.digest,
      ...r.observation,
      receipt: r.refusal?.receipt ?? r.receipt,
      ...(r.refusal ? { key_version: r.plan.key_version } : {}),
    });
    synced =
      closed(v, ['id', 'state', 'revision']) &&
      v.id === r.plan.attempt_id &&
      v.state === 'closed' &&
      integer(v.revision) &&
      v.revision >= 3;
  } catch {
    /* Frozen/pending or restored Native authority remains fenced. */
  }
  return {
    attempt_id: r.plan.attempt_id,
    state: 'closed' as const,
    repo_id: r.plan.repo_id,
    cleanup: r.refusal ? 'git_bearer_refused' : 'refused',
    op_synchronized: synced,
  };
}
