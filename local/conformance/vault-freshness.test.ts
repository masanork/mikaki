import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compareSource, readSavedHead } from '../../crates/worker/ui/vault-freshness.ts';

test('saved version observations reject ambiguous HTTP records and distinguish deletion from missing data', async () => {
  const original = globalThis.fetch;
  let response: Response;
  globalThis.fetch = async (input, options) => {
    assert.equal(input, '/vault/attributes/name');
    assert.equal(options?.cache, 'no-store');
    return response;
  };
  const record = {
    format_version: 1,
    revision: 7,
    ciphertext: 'encrypted',
    owner_envelope: 'wrapped',
  };
  const reply = (body: unknown, status: number, etag?: string) =>
    new Response(JSON.stringify(body), { status, headers: etag ? { ETag: etag } : {} });
  try {
    response = reply(record, 200, '"7"');
    const head = await readSavedHead('name');
    assert.equal(head.state, 'saved');
    assert.equal(head.revision, 7);
    assert.ok(head.checkedAt > 0);
    assert.equal(compareSource({ head, failed: false }, 7), 'same');
    assert.equal(compareSource({ head, failed: false }, 6), 'newer');
    assert.equal(compareSource({ head, failed: false }, 8), 'different');
    assert.equal(compareSource({ head, failed: true }, 7), 'unknown');
    for (const invalid of [
      reply(record, 200),
      reply(record, 200, 'W/"7"'),
      reply(record, 200, '"8"'),
      reply(record, 200, '"9007199254740992"'),
      reply({ ...record, ciphertext: null }, 200, '"7"'),
      reply({ error: 'not_found' }, 503),
      reply({ error: 'authentication_required' }, 401),
      reply({ error: 'unexpected_route' }, 404),
      reply({ error: 'not_found' }, 404, '"0"'),
    ]) {
      response = invalid;
      await assert.rejects(readSavedHead('name'));
    }
    response = reply({ error: 'not_found' }, 404, '"8"');
    const deleted = await readSavedHead('name');
    assert.equal(deleted.state, 'deleted');
    assert.equal(deleted.revision, 8);
    assert.equal(compareSource({ head: deleted, failed: false }, 7), 'deleted');
    response = reply({ error: 'not_found' }, 404);
    const missing = await readSavedHead('name');
    assert.equal(missing.state, 'missing');
    assert.equal(missing.revision, 0);
    assert.equal(compareSource({ head: missing, failed: false }, 7), 'missing');
  } finally {
    globalThis.fetch = original;
  }
});
