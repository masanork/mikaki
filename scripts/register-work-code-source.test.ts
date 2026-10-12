import assert from 'node:assert/strict';
import test from 'node:test';
import { assertQualifiedSourceVersion } from './register-work-code-source.ts';

test('source registration checks the exact active version and top-level API upload annotations', () => {
  const commit = '1e16fd91787bf3b28a26e01ab0332441b40dbd57';
  const id = 'a1da760a-c4f5-4880-8f92-eeb43de5aeab';
  const annotations = {
    'workers/message': `main CI ${commit}`,
    'workers/tag': commit.slice(0, 12),
  };
  assertQualifiedSourceVersion(
    { id, metadata: { created_on: '2026-10-12T13:34:00Z', source: 'api' }, annotations },
    id,
    commit,
  );
  for (const value of [
    undefined,
    {},
    { id, metadata: { annotations } },
    { id: '00000000-0000-4000-8000-000000000000', annotations },
    { id, annotations: { ...annotations, 'workers/message': `main CI ${'0'.repeat(40)}` } },
    { id, annotations: { ...annotations, 'workers/tag': '0'.repeat(12) } },
  ])
    assert.throws(() => assertQualifiedSourceVersion(value, id, commit));
});
