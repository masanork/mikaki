import assert from 'node:assert/strict';
import { createDecipheriv, createHash, createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import {
  createOwnerKey,
  sealOwnerRecord,
  sealOwnerRecordUserInfoRecipient,
} from '../../crates/worker/ui/vault-owner-crypto.ts';
import { sealRecordUserInfoDataKey } from '../../crates/worker/ui/vault-record-recipient-envelope.ts';
import { openOwnerRecordContentKey } from '../../crates/worker/ui/vault-record-content.ts';
import { validateRecordUserInfoRecipient } from '../../crates/worker/ui/recipient-directory-v2.ts';
import {
  parseVaultRecordSource,
  vaultCiphertextDigest,
} from '../../crates/worker/ui/vault-record-source.ts';
import { OwnerKeySession } from '../../crates/worker/ui/vault-owner-session.ts';
import { VaultScope } from '../../crates/worker/ui/vault-lifecycle.ts';

// Independent Node HMAC/GCM receiver. It does not import the sender's HPKE schedule.
const lp = (...parts: Uint8Array[]) =>
  Buffer.concat(
    parts.flatMap((p) => {
      const n = Buffer.alloc(2);
      n.writeUInt16BE(p.length);
      return [n, Buffer.from(p)];
    }),
  );
const u64 = (n: number) => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(n));
  return out;
};
const text = (s: string) => Buffer.from(s);
const hmac = (key: Uint8Array, data: Uint8Array) =>
  createHmac('sha256', key.length ? key : Buffer.alloc(32))
    .update(data)
    .digest();
function referenceOpen(
  seed: Uint8Array,
  frame: Uint8Array,
  source: Record<string, any>,
  authority: { key_generation: number; owner_key_revision: number },
) {
  const b = Buffer.from(frame);
  assert.equal(b.length, 1187);
  assert.equal(b.subarray(0, 5).toString('hex'), '4d4b565202');
  const suite = b.subarray(5, 11);
  assert.equal(suite.toString('hex'), '004100010002');
  const keys = ml_kem768.keygen(seed);
  assert.deepEqual(b.subarray(11, 43), createHash('sha256').update(keys.publicKey).digest());
  const shared = ml_kem768.decapsulate(b.subarray(51, 1139), keys.secretKey);
  const info = lp(
    text('mikaki-vault-record-recipient-envelope-v2-draft04'),
    new Uint8Array([2]),
    suite,
    text('userinfo'),
    b.subarray(11, 43),
    b.subarray(43, 51),
  );
  const label = (name: string, data: Uint8Array) =>
    Buffer.concat([text('HPKE-v1'), text('HPKE'), suite, text(name), data]);
  const extract = (salt: Uint8Array, name: string, data: Uint8Array) =>
    hmac(salt, label(name, data));
  const schedule = Buffer.concat([
    Buffer.from([0]),
    extract(Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0)),
    extract(Buffer.alloc(0), 'info_hash', info),
  ]);
  const secret = extract(shared, 'secret', Buffer.alloc(0));
  const expand = (name: string, size: number) => {
    const n = Buffer.alloc(2);
    n.writeUInt16BE(size);
    return hmac(secret, Buffer.concat([n, label(name, schedule), Buffer.from([1])])).subarray(
      0,
      size,
    );
  };
  const aad = lp(
    text('2'),
    text(source.origin),
    text(source.owner_id),
    text(source.vault_id),
    text(source.collection_id),
    text(source.record_id),
    text(source.kind),
    u64(source.revision),
    Buffer.from(source.ciphertext_sha256, 'base64url'),
    u64(authority.key_generation),
    u64(authority.owner_key_revision),
    text('userinfo'),
    text('oidc.userinfo.name'),
  );
  const decipher = createDecipheriv('aes-256-gcm', expand('key', 32), expand('base_nonce', 12));
  decipher.setAAD(aad);
  decipher.setAuthTag(b.subarray(-16));
  try {
    return Buffer.concat([decipher.update(b.subarray(1139, -16)), decipher.final()]);
  } finally {
    shared.fill(0);
    secret.fill(0);
    keys.secretKey.fill(0);
  }
}
const fixture = JSON.parse(
  readFileSync(
    new URL('../../design/probes/pqc/record-userinfo-fixture.json', import.meta.url),
    'utf8',
  ),
);

test('independent Node opens product record recipient fixture and exact body', () => {
  const key = referenceOpen(
    Buffer.from(fixture.seed, 'base64url'),
    Buffer.from(fixture.frame, 'base64url'),
    fixture.source,
    fixture.authority,
  );
  const body = Buffer.from(fixture.ciphertext, 'base64url');
  const source = fixture.source;
  const aad = lp(
    ...[
      'mikaki-vault-record-content',
      '2',
      source.origin,
      source.owner_id,
      source.vault_id,
      source.collection_id,
      source.record_id,
      source.kind,
      String(source.revision),
    ].map(text),
  );
  const decipher = createDecipheriv('aes-256-gcm', key, body.subarray(1, 13));
  decipher.setAAD(aad);
  decipher.setAuthTag(body.subarray(-16));
  assert.equal(
    Buffer.concat([decipher.update(body.subarray(13, -16)), decipher.final()]).toString('utf8'),
    fixture.name,
  );
  key.fill(0);
});
for (const [field, value] of Object.entries({
  origin: 'https://other.example',
  owner_id: 'other',
  vault_id: 'other',
  collection_id: 'other',
  record_id: 'other',
  kind: 'other',
  revision: 10,
  ciphertext_sha256: Buffer.alloc(32).toString('base64url'),
})) {
  test(`record recipient rejects substituted ${field}`, () =>
    assert.throws(() =>
      referenceOpen(
        Buffer.from(fixture.seed, 'base64url'),
        Buffer.from(fixture.frame, 'base64url'),
        { ...fixture.source, [field]: value },
        fixture.authority,
      ),
    ));
}
for (const field of ['key_generation', 'owner_key_revision'] as const)
  test(`record recipient rejects ${field} authority substitution`, () =>
    assert.throws(() =>
      referenceOpen(
        Buffer.from(fixture.seed, 'base64url'),
        Buffer.from(fixture.frame, 'base64url'),
        fixture.source,
        { ...fixture.authority, [field]: 2 },
      ),
    ));
for (const offset of [0, 4, 5, 11, 43, 51, 1186])
  test(`record recipient rejects changed frame byte ${offset}`, () => {
    const frame = Buffer.from(fixture.frame, 'base64url');
    frame[offset] ^= 1;
    assert.throws(() =>
      referenceOpen(
        Buffer.from(fixture.seed, 'base64url'),
        frame,
        fixture.source,
        fixture.authority,
      ),
    );
  });

test('record directory cannot accept a format1 suite or extra fields', async () => {
  await assert.rejects(
    validateRecordUserInfoRecipient({
      ...fixture.recipient,
      envelope_suite: 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-v1',
    }),
  );
  await assert.rejects(validateRecordUserInfoRecipient({ ...fixture.recipient, unexpected: true }));
  assert.equal(
    (await validateRecordUserInfoRecipient(fixture.recipient)).key_id,
    fixture.recipient.key_id,
  );
});

test('owner recipient operation authenticates source, strict text and ciphertext first', async () => {
  const context = {
    origin: 'https://mikaki.example',
    ownerId: 'owner',
    vaultId: 'vault',
    keyGeneration: 1,
  };
  const { key } = await createOwnerKey(
    context,
    new Uint8Array([1]),
    new Uint8Array(32),
    new Uint8Array(32),
  );
  const item = { collectionId: 'personal', recordId: 'name', kind: 'name', revision: 9 };
  const record = await sealOwnerRecord(new TextEncoder().encode('Alice'), key, context, item);
  const source = parseVaultRecordSource({
    ...fixture.source,
    ...{
      owner_id: 'owner',
      vault_id: 'vault',
      ciphertext_sha256: await vaultCiphertextDigest(record.ciphertext),
    },
  });
  const frame = await sealOwnerRecordUserInfoRecipient(
    record,
    key,
    context,
    source,
    fixture.authority,
    fixture.recipient,
  );
  assert.equal(
    referenceOpen(Buffer.from(fixture.seed, 'base64url'), frame, source, fixture.authority).length,
    32,
  );
  await assert.rejects(
    sealOwnerRecordUserInfoRecipient(
      { ...record, ciphertext: fixture.ciphertext },
      key,
      context,
      source,
      fixture.authority,
      fixture.recipient,
    ),
  );
  await assert.rejects(
    sealOwnerRecordUserInfoRecipient(
      record,
      key,
      context,
      { ...source, owner_id: 'other' },
      fixture.authority,
      fixture.recipient,
    ),
  );
  for (const plaintext of [
    new Uint8Array(),
    new Uint8Array([0xff]),
    new TextEncoder().encode('x'.repeat(257)),
  ]) {
    const bad = await sealOwnerRecord(plaintext, key, context, item);
    await assert.rejects(
      sealOwnerRecordUserInfoRecipient(
        bad,
        key,
        context,
        { ...source, ciphertext_sha256: await vaultCiphertextDigest(bad.ciphertext) },
        fixture.authority,
        fixture.recipient,
      ),
    );
  }
});

test('owner lease invalidation rejects an in-flight recipient result without exporting keys', async () => {
  const context = {
    origin: 'https://mikaki.example',
    ownerId: 'owner',
    vaultId: 'vault',
    keyGeneration: 1,
  };
  const identity = { account_id: 'owner', credential_id: 'AQ', session_tag: 's'.repeat(43) };
  const scope = new VaultScope(
    () => {},
    undefined,
    undefined,
    async () => Response.json(identity),
  );
  scope.observe(identity);
  const session = new OwnerKeySession(scope, context);
  await session.initialize(async () => ({
    credentialId: new Uint8Array([1]),
    output: new Uint8Array(32),
  }));
  const record = await session.seal(new TextEncoder().encode('Alice'), {
    collectionId: 'personal',
    recordId: 'name',
    kind: 'name',
    revision: 9,
  });
  const source = parseVaultRecordSource({
    ...fixture.source,
    owner_id: 'owner',
    vault_id: 'vault',
    ciphertext_sha256: await vaultCiphertextDigest(record.ciphertext),
  });
  const pending = session.sealUserInfoRecipient(
    record,
    source,
    fixture.authority,
    fixture.recipient,
  );
  session.suspend();
  await assert.rejects(pending);
  assert.equal('getKey' in session, false);
  assert.equal('withKey' in session, false);
  session.dispose();
});

test('recipient helper snapshots the caller key and bindings before asynchronous work', async () => {
  const key = new Uint8Array(32).fill(0x51);
  const source = { ...fixture.source };
  const authority = { ...fixture.authority };
  const recipient = { ...fixture.recipient };
  const pending = sealRecordUserInfoDataKey(key, recipient, {
    source,
    authority,
    ciphertext: fixture.ciphertext,
  });
  key.fill(0x99);
  source.origin = 'https://other.example';
  authority.owner_key_revision = 2;
  recipient.generation = 2;
  const wrapped = await pending;
  const restored = referenceOpen(
    Buffer.from(fixture.seed, 'base64url'),
    wrapped,
    fixture.source,
    fixture.authority,
  );
  assert.deepEqual(restored, Buffer.alloc(32, 0x51));
  assert.deepEqual(key, new Uint8Array(32).fill(0x99), 'caller-owned bytes are untouched');
  restored.fill(0);
});

test('independent content helper requires exact v2 content AAD and digest', async () => {
  const key = referenceOpen(
    Buffer.from(fixture.seed, 'base64url'),
    Buffer.from(fixture.frame, 'base64url'),
    fixture.source,
    fixture.authority,
  );
  try {
    const plaintext = await openOwnerRecordContentKey(
      fixture.ciphertext,
      new Uint8Array(key),
      fixture.source,
    );
    assert.equal(new TextDecoder().decode(plaintext), fixture.name);
    plaintext.fill(0);
    for (const [field, value] of Object.entries({
      storage_version: 1,
      origin: 'https://other.example',
      owner_id: 'other',
      vault_id: 'other',
      collection_id: 'other',
      record_id: 'owner_note',
      kind: 'owner_note',
      revision: 10,
      ciphertext_sha256: Buffer.alloc(32).toString('base64url'),
    })) {
      await assert.rejects(
        openOwnerRecordContentKey(fixture.ciphertext, new Uint8Array(key), {
          ...fixture.source,
          [field]: value,
        }),
      );
    }
    const changed = Buffer.from(fixture.ciphertext, 'base64url');
    changed[0] = 1;
    await assert.rejects(
      openOwnerRecordContentKey(changed.toString('base64url'), new Uint8Array(key), {
        ...fixture.source,
        ciphertext_sha256: createHash('sha256').update(changed).digest('base64url'),
      }),
    );
  } finally {
    key.fill(0);
  }
});

test('record recipient refuses a format1 content body even with its matching digest', async () => {
  const ciphertext = Buffer.from(fixture.ciphertext, 'base64url');
  ciphertext[0] = 1;
  await assert.rejects(
    sealRecordUserInfoDataKey(new Uint8Array(32), fixture.recipient, {
      source: {
        ...fixture.source,
        ciphertext_sha256: createHash('sha256').update(ciphertext).digest('base64url'),
      },
      authority: fixture.authority,
      ciphertext: ciphertext.toString('base64url'),
    }),
  );
});

for (const failAt of [0, 1, 2, 3, 4, 5]) {
  test(`recipient sealing clears every retained import buffer (${failAt ? `failure at HMAC ${failAt}` : 'success'})`, async (t) => {
    const original = crypto.subtle.importKey.bind(crypto.subtle);
    const retained: Uint8Array[] = [];
    let hmacImports = 0;
    let nonzeroImports = 0;
    t.mock.method(
      crypto.subtle,
      'importKey',
      async (...args: Parameters<typeof crypto.subtle.importKey>) => {
        if (args[0] === 'raw' && ArrayBuffer.isView(args[1])) {
          const input = args[1];
          // Keep the exact backing storage passed to WebCrypto, not a snapshot.
          const view = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
          retained.push(view);
          if (view.some((byte) => byte !== 0)) nonzeroImports++;
        }
        const algorithm = typeof args[2] === 'string' ? args[2] : args[2].name;
        if (algorithm === 'HMAC' && ++hmacImports === failAt)
          throw new Error('injected HMAC import failure');
        return original(...args);
      },
    );
    const callerKey = new Uint8Array(32).fill(0x51);
    const pending = sealRecordUserInfoDataKey(callerKey, fixture.recipient, {
      source: fixture.source,
      authority: fixture.authority,
      ciphertext: fixture.ciphertext,
    });
    if (failAt) {
      await assert.rejects(pending, /injected HMAC import failure/);
      assert.equal(hmacImports, failAt);
    } else {
      const frame = await pending;
      assert.equal(frame.length, 1187);
      assert.equal(hmacImports, 5);
      assert.equal(retained.length, 6, 'five HMAC imports and the AES sealing-key import');
      assert.equal(
        nonzeroImports,
        4,
        'test observed the shared secret, two HKDF copies and AES key',
      );
    }
    assert.ok(retained.length > 0);
    for (const buffer of retained)
      assert.ok(
        buffer.every((byte) => byte === 0),
        'temporary imported key bytes must be cleared',
      );
    assert.deepEqual(callerKey, new Uint8Array(32).fill(0x51), 'caller key is not consumed');
  });
}
