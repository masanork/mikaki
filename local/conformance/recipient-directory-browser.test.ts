import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import {
  fetchVerifiedUserInfoRecipient,
  RECIPIENT_CHECKPOINT,
  validateUserInfoRecipient,
} from '../../crates/worker/ui/recipient-directory.ts';

function directory(generation, byte) {
  const publicKey = Buffer.alloc(1184, byte);
  return {
    service_id: 'userinfo',
    algorithm: 'ML-KEM-768',
    key_id: createHash('sha256').update(publicKey).digest('base64url'),
    public_key: publicKey.toString('base64url'),
    generation,
    revision: 2,
  };
}

function memoryStorage() {
  const values = new Map();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
  };
}

test('browser verifies recipient digest, canonical encoding, and generation continuity', async () => {
  const first = directory(1, 7);
  const next = directory(2, 8);
  const storage = memoryStorage();
  let selected = first;
  const fetcher = async (url, options) => {
    assert.equal(url, '/vault/recipient-keys/userinfo');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.credentials, 'same-origin');
    return new Response(JSON.stringify(selected), { status: 200 });
  };
  assert.deepEqual(await fetchVerifiedUserInfoRecipient(fetcher, storage), first);
  assert.deepEqual(await fetchVerifiedUserInfoRecipient(fetcher, storage), first);
  selected = next;
  assert.deepEqual(await fetchVerifiedUserInfoRecipient(fetcher, storage), next);
  selected = first;
  await assert.rejects(fetchVerifiedUserInfoRecipient(fetcher, storage), /continuity/);
  assert.deepEqual(JSON.parse(storage.getItem(RECIPIENT_CHECKPOINT)), {
    generation: 2,
    key_id: next.key_id,
    revision: 2,
  });
  selected = directory(2, 9);
  await assert.rejects(fetchVerifiedUserInfoRecipient(fetcher, storage), /continuity/);
  selected = { ...next, revision: 1 };
  await assert.rejects(fetchVerifiedUserInfoRecipient(fetcher, storage), /continuity/);
  await assert.rejects(validateUserInfoRecipient({ ...next, key_id: first.key_id }), /mismatch/);
  await assert.rejects(validateUserInfoRecipient({ ...next, public_key: `${next.public_key}=` }));
  await assert.rejects(validateUserInfoRecipient({ ...next, public_key: 'AA' }), /length/);
  await assert.rejects(validateUserInfoRecipient({ ...next, generation: 0 }));
});

test('unavailable directory and invalid checkpoints fail closed', async () => {
  const storage = memoryStorage();
  storage.setItem(RECIPIENT_CHECKPOINT, '{');
  const fetcher = async () => new Response(JSON.stringify(directory(1, 1)), { status: 200 });
  await assert.rejects(fetchVerifiedUserInfoRecipient(fetcher, storage));
  const unavailable = async () => new Response(null, { status: 503 });
  await assert.rejects(fetchVerifiedUserInfoRecipient(unavailable, memoryStorage()), /unavailable/);
});
