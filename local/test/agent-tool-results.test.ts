import assert from 'node:assert/strict';
import { test } from 'node:test';
import { toolOutputs, toolResult, unknownSource } from '../../crates/agent-worker/tool-results.ts';

const read = {
  result_version: 1,
  untrusted_content: true,
  id: 'name',
  title: 'Name',
  source: 'vault:name:999',
  text: 'Owner assertion',
  source_info: unknownSource(),
  access: {
    mode: 'local-export',
    source_check: 'not-checked',
    checked_at: 150,
    grant_expires_at: 200,
  },
};
test('structured output validates trust/freshness states and mirrors exactly in legacy text', () => {
  const result = toolResult('read', read);
  assert.deepEqual(result.structuredContent, read);
  const content = result.content[0];
  assert.ok(content?.type === 'text');
  assert.deepEqual(JSON.parse(content.text), result.structuredContent);
  for (const invalid of [
    { ...read, untrusted_content: false },
    { ...read, result_version: 2 },
    { ...read, owner_key: 'never-disclose' },
    { ...read, source_info: { ...read.source_info, revision: 999 } },
    { ...read, source_info: { kind: 'issuer-verified' } },
    { ...read, access: { ...read.access, source_check: 'revision-matched' } },
    { ...read, access: { ...read.access, mode: 'remote-snapshot' } },
  ])
    assert.throws(() => toolResult('read', invalid));
  assert.throws(() => toolResult('list', { ...read, documents: [], next_offset: null }));
});
