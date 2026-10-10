import assert from 'node:assert/strict';
import { test } from 'node:test';
import { copyHttpPort } from '../../crates/worker/ui/work-copy-view.ts';
const id = 'a'.repeat(43),
  digest = 'b'.repeat(64);
const record = {
  review_digest: digest,
  can_start: false,
  cleanup_pending: false,
  preparation_state: 'verified',
  job: {
    preparation_id: id,
    review_digest: digest,
    state: 'verified',
    next_step: 19,
    total_steps: 19,
    inflight: false,
    updated_at: 1,
  },
};
const reply = (value: unknown) =>
  Response.json({ format_version: 1, checked_at: 1, record: value });
test('progress decoder refuses inconsistent verification and substituted job identity', async () => {
  for (const job of [
    { ...record.job, preparation_id: 'c'.repeat(43) },
    { ...record.job, review_digest: 'c'.repeat(64) },
    { ...record.job, state: 'running' },
    { ...record.job, next_step: 18 },
    { ...record.job, inflight: true },
    { ...record.job, token_id: 'private' },
  ])
    await assert.rejects(
      copyHttpPort(async () => reply({ ...record, job })).read(id, new AbortController().signal),
    );
  await assert.rejects(
    copyHttpPort(async () => reply({ ...record, can_start: true })).read(
      id,
      new AbortController().signal,
    ),
  );
});
test('bounded progress decoder rejects oversize bodies and late aborted replies', async () => {
  await assert.rejects(
    copyHttpPort(
      async () =>
        new Response(
          ' '.repeat(4097) + JSON.stringify({ format_version: 1, checked_at: 1, record }),
        ),
    ).read(id, new AbortController().signal),
  );
  const controller = new AbortController();
  const port = copyHttpPort(async () => {
    controller.abort();
    return reply(record);
  });
  await assert.rejects(port.read(id, controller.signal), { name: 'AbortError' });
});
