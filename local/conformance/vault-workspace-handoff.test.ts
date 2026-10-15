import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  WorkspaceHandoff,
  WORKSPACE_PROTOCOL,
} from '../../crates/worker/ui/vault-workspace-handoff.ts';
import {
  parseWorkspaceSnapshot,
  WORKSPACE_SNAPSHOT_MAX_BYTES,
} from '../../crates/worker/ui/vault-workspace-snapshot.ts';
const origin = 'https://os.example',
  channel = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const snapshot = {
  format: 'cloudflare-os-workspace',
  version: 1,
  title: 'Workspace',
  source: { origin, workspaceId: 'a'.repeat(64), capturedAt: '2026-10-15T00:00:00.000Z' },
  records: [['version', 4]],
  gadgets: [],
};
const text = JSON.stringify(snapshot);
function setup() {
  const sent: { value: unknown; origin: string }[] = [];
  const peer = {
    postMessage(value: unknown, origin: string) {
      sent.push({ value, origin });
    },
  };
  let now = 0;
  const handoff = new WorkspaceHandoff(peer, () => now);
  const receive = (type: string, extra = {}, from = origin, source: unknown = peer) =>
    handoff.receive({
      source,
      origin: from,
      data: { protocol: WORKSPACE_PROTOCOL, channel, type, ...extra },
    });
  return {
    handoff,
    receive,
    sent,
    expire: () => {
      now = 300000;
    },
  };
}
test('workspace save pins the opener, origin, channel and mode, with a post-commit receipt only', () => {
  const s = setup();
  assert.equal(s.receive('offer', { mode: 'save' }, origin, {}), null);
  assert.equal(s.receive('snapshot', { snapshot: text }), null);
  s.receive('offer', { mode: 'save' });
  assert.equal(s.sent.length, 1);
  s.handoff.saved();
  assert.equal(s.sent.length, 1);
  assert.equal(s.receive('snapshot', { snapshot: text }, 'https://other.example'), null);
  assert.throws(
    () => s.receive('snapshot', { snapshot: text.replace(origin, 'https://other.example') }),
    /source mismatch/,
  );
  assert.deepEqual(s.receive('snapshot', { snapshot: text }), { text });
  assert.equal(s.receive('snapshot', { snapshot: text }), null);
  s.handoff.saved();
  assert.deepEqual(s.sent.at(-1), {
    value: { protocol: WORKSPACE_PROTOCOL, channel, type: 'saved' },
    origin,
  });
});
test('restore discloses only an explicitly selected snapshot to its original app origin', () => {
  const s = setup();
  s.receive('offer', { mode: 'restore' });
  assert.equal(s.sent.length, 0);
  assert.equal(s.receive('restored'), null);
  assert.throws(
    () => s.handoff.restore(text.replace(origin, 'https://other.example')),
    /source mismatch/,
  );
  assert.equal(s.sent.length, 0);
  s.handoff.restore(text);
  assert.deepEqual(s.sent[0], {
    value: { protocol: WORKSPACE_PROTOCOL, channel, type: 'snapshot', snapshot: text },
    origin,
  });
  assert.throws(() => s.handoff.restore(text), /source mismatch/);
  assert.deepEqual(s.receive('restored'), { restored: true });
  s.handoff.dispose();
  assert.equal(s.receive('restored'), null);
});
test('expiry, oversize UTF8, unsafe objects and malformed portable rows refuse transfer', () => {
  const s = setup();
  s.receive('offer', { mode: 'restore' });
  s.expire();
  assert.throws(() => s.handoff.restore(text), /expired/);
  for (const value of [
    text.replace('"version":1', '"version":2'),
    text.replace('Workspace', '猫'.repeat(Math.ceil(WORKSPACE_SNAPSHOT_MAX_BYTES / 3))),
    JSON.stringify({
      ...snapshot,
      records: [['bad', { type: 'object', value: [['__proto__', 'pollute']] }]],
    }),
    JSON.stringify({ ...snapshot, records: [['bad', { type: 'capability', value: 'secret' }]] }),
  ])
    assert.throws(() => parseWorkspaceSnapshot(value));
});
