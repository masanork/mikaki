/** Actual Native saved projections and Git source text. Verification evidence
 * below is explicitly synthetic; the Git/effect composition has its own lane. */
import assert from 'node:assert/strict';
import type { createSourceFixture } from './work-source-fixture.ts';
export async function seedPreparationReview(f: Awaited<ReturnType<typeof createSourceFixture>>) {
  await f.register('code', f.first, {
    role: 'code',
    label: 'Synthetic code',
    files: [],
    ...f.codeSource,
  });
  const call = async (input: Record<string, unknown>, o = f.first) => {
    const r = await f.fixture.fetch('https://work.test/fixture', {
      method: 'POST',
      body: JSON.stringify({ session: o.hash, ...input }),
    });
    const b = (await r.json()) as any;
    assert.equal(r.status, 200, JSON.stringify(b));
    return b;
  };
  const disclosure = await call({
    action: 'disclosure',
    disclosure: f.disclosure,
    expires_at: Math.floor(Date.now() / 1000) + 600,
  });
  async function reserve(task = 'review-task', digest = disclosure.digest, o = f.first) {
    return call(
      {
        action: 'reserve-preparation',
        digest,
        task_repository: task,
        task_namespace: 'mikaki-dev',
        snapshot_namespace: 'mikaki-dev',
      },
      o,
    );
  }
  const reserved = await reserve();
  async function verify(id: string) {
    await call({ action: 'dispatch-preparation', id });
    await call({
      action: 'verify-preparation',
      id,
      preparation_evidence: {
        for_operation: id,
        task_repo_id: 'synthetic-task-repo',
        snapshot_repo_id: 'synthetic-snapshot-repo',
        payload_receipt: '4'.repeat(64),
        credential_receipt: '5'.repeat(64),
      },
    });
  }
  return { call, reserve, verify, reserved, disclosure };
}
