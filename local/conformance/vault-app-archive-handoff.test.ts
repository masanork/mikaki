import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AppArchiveHandoff } from '../../crates/worker/ui/vault-app-archive-handoff.ts';
import { parseThreadArchive } from '../../crates/worker/ui/vault-thread-archive.ts';

const origin = 'https://os.example';
const channel = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const archive = {
  format_version: 2,
  source: {
    app: 'cloudflare-os',
    origin,
    workspace_id: 'workspace',
    chat_id: 0,
    first_sequence: 1,
    last_sequence: 4,
    scope: 'text-segment',
  },
  title: 'Application discussion',
  messages: [
    {
      source_id: '1',
      speaker: 'Alice',
      actor: 'human',
      text: 'Private text',
      timestamp: '2026-10-14T00:00:00.000Z',
    },
  ],
};
const envelope = (type: string, extra = {}) => ({
  protocol: 'mikaki-archive-v1',
  type,
  channel,
  ...extra,
});
function setup() {
  const sent: { data: unknown; origin: string }[] = [];
  const opener = {
    postMessage(data: unknown, origin: string) {
      sent.push({ data, origin });
    },
  };
  let now = 0;
  const handoff = new AppArchiveHandoff(opener, () => now);
  const receive = (data: unknown, from = origin, source: unknown = opener) =>
    handoff.receive({ source, origin: from, data });
  return {
    handoff,
    receive,
    sent,
    advance() {
      now = 300_000;
    },
  };
}
test('only the opener and an exact origin/channel can deliver one bounded archive', () => {
  const s = setup();
  assert.equal(s.receive(envelope('offer'), origin, {}), null);
  assert.equal(s.receive(envelope('archive', { archive: JSON.stringify(archive) })), null);
  assert.equal(s.receive(envelope('offer')), null);
  assert.deepEqual(s.sent, [{ data: envelope('request'), origin }]);
  s.handoff.saved();
  assert.equal(s.sent.length, 1);
  for (const [from, data] of [
    ['https://evil.example', envelope('archive', { archive: JSON.stringify(archive) })],
    [
      origin,
      {
        ...envelope('archive', { archive: JSON.stringify(archive) }),
        channel: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      },
    ],
  ] as const)
    assert.equal(s.receive(data, from), null);
  assert.deepEqual(s.receive(envelope('archive', { archive: JSON.stringify(archive) })), archive);
  assert.equal(s.receive(envelope('archive', { archive: JSON.stringify(archive) })), null);
  s.handoff.saved();
  assert.deepEqual(s.sent.at(-1), { data: envelope('saved'), origin });
});
test('untrusted source origins, mismatched provenance, invalid JSON and oversized Unicode fail closed', () => {
  const s = setup();
  assert.equal(s.receive(envelope('offer'), 'http://remote.example'), null);
  s.receive(envelope('offer'));
  for (const value of [
    JSON.stringify({ ...archive, source: { ...archive.source, origin: 'https://evil.example' } }),
    JSON.stringify({ ...archive, format_version: 1 }),
    '{',
    '猫'.repeat(8001),
  ])
    assert.throws(() => s.receive(envelope('archive', { archive: value })));
  assert.deepEqual(s.receive(envelope('archive', { archive: JSON.stringify(archive) })), archive);
});
test('expiry and disposal prevent subsequent delivery and receipts', () => {
  for (const expire of [false, true]) {
    const s = setup();
    s.receive(envelope('offer'));
    if (expire) s.advance();
    else s.handoff.dispose();
    assert.equal(s.receive(envelope('archive', { archive: JSON.stringify(archive) })), null);
    s.handoff.saved();
    assert.equal(s.sent.length, 1);
  }
});
test('an expired review cannot prepare a new save', () => {
  const s = setup();
  assert.throws(() => s.handoff.authorizeSave());
  s.receive(envelope('offer'));
  s.receive(envelope('archive', { archive: JSON.stringify(archive) }));
  assert.doesNotThrow(() => s.handoff.authorizeSave());
  s.advance();
  assert.throws(() => s.handoff.authorizeSave());
});
test('source messages preserve opaque sequence identity, reject duplicates/reordering and stay in range', () => {
  assert.deepEqual(parseThreadArchive(archive), archive);
  for (const messages of [
    [{ ...archive.messages[0], source_id: '01' }],
    [{ ...archive.messages[0], source_id: '5' }],
    [archive.messages[0], archive.messages[0]],
    [{ ...archive.messages[0], source_id: '4' }, archive.messages[0]],
  ])
    assert.throws(() => parseThreadArchive({ ...archive, messages }));
  assert.throws(() =>
    parseThreadArchive({ ...archive, source: { ...archive.source, secret: 'forbidden' } }),
  );
});
