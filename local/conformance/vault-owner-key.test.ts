import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createCipheriv, hkdfSync } from 'node:crypto';
import {
  createOwnerKey,
  openOwnerKey,
  rewrapOwnerKey,
  rewrapOwnerRecord,
  parseOwnerKeyEnvelope,
  sealOwnerRecord,
  openOwnerRecord,
  OWNER_RECORD_MAX_BYTES,
  type OwnerKeyContext,
  type OwnerRecordContext,
} from '../../crates/worker/ui/vault-owner-crypto.ts';
import { OwnerKeySession } from '../../crates/worker/ui/vault-owner-session.ts';
import {
  VaultScope,
  VAULT_IDLE_MS,
  VAULT_ABSOLUTE_MS,
} from '../../crates/worker/ui/vault-lifecycle.ts';
import { encodeBase64Url, decodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';

const bytes = (n = 32) => crypto.getRandomValues(new Uint8Array(n));
const text = (s: string) => new TextEncoder().encode(s);
const context: OwnerKeyContext = {
  origin: 'https://auth.mikaki.org',
  ownerId: 'owner',
  vaultId: 'vault',
  keyGeneration: 1,
};
const item: OwnerRecordContext = {
  collectionId: 'profile',
  recordId: 'name',
  kind: 'attribute',
  revision: 1,
};
function fixture(clock?: () => number) {
  const credential = bytes(),
    output = bytes();
  const identity = {
    account_id: 'owner',
    credential_id: encodeBase64Url(credential),
    session_tag: 's'.repeat(43),
  };
  const scope = new VaultScope(
    () => {},
    clock,
    clock,
    async () => Response.json(identity),
  );
  scope.observe(identity);
  return { credential, output, identity, scope };
}
function corrupt(value: string) {
  const decoded = decodeBase64Url(value);
  decoded[decoded.length - 1]! ^= 1;
  return encodeBase64Url(decoded);
}

test('one owner-key ceremony opens/saves many records; keys are nonextractable and PRF bytes consumed', async () => {
  const f = fixture();
  const used = f.output.slice();
  const created = await createOwnerKey(context, f.credential, bytes(), used);
  assert(used.every((v) => v === 0));
  assert.equal(created.key.extractable, false);
  await assert.rejects(crypto.subtle.exportKey('raw', created.key));
  const session = new OwnerKeySession(f.scope, context);
  let ceremonies = 0;
  let evaluated: Uint8Array<ArrayBuffer>;
  const evaluate = async () => {
    ceremonies++;
    evaluated = f.output.slice();
    return { credentialId: f.credential, output: evaluated };
  };
  await session.unlock(created.envelope, evaluate);
  assert(evaluated!.every((v) => v === 0));
  await session.unlock(created.envelope, evaluate);
  for (let revision = 1; revision <= 10; revision++) {
    const c = { ...item, recordId: `record-${revision}`, revision };
    const p = text(`会話 ${revision}`);
    const record = await session.seal(p, c);
    const restored = await session.open(record, c);
    assert.deepEqual(restored, p);
    restored.fill(0);
  }
  assert.equal(ceremonies, 1);
  assert.equal(session.opened, true);
  session.lock();
  assert.equal(session.opened, false);
  await assert.rejects(session.seal(text('late'), item));
});

test('independent Node HKDF/AES-GCM vector agrees with specified v2 field encoding', async () => {
  const root = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  const output = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 32));
  const credential = new Uint8Array([0xa0, 0xa1, 0xa2]);
  const input = new Uint8Array(32).fill(0x40),
    salt = new Uint8Array(32).fill(0x50),
    nonce = new Uint8Array(12).fill(0x60);
  const encode = (values: string[]) =>
    Buffer.concat(
      values.flatMap((value) => {
        const field = Buffer.from(value, 'utf8'),
          size = Buffer.alloc(2);
        size.writeUInt16BE(field.length);
        return [size, field];
      }),
    );
  const common = [
    '2',
    context.origin,
    'owner',
    'vault',
    '1',
    encodeBase64Url(credential),
    encodeBase64Url(input),
  ];
  const key = hkdfSync('sha256', output, salt, encode(['mikaki-vault-owner-kek', ...common]), 32);
  const encrypt = (key: Uint8Array, iv: Uint8Array, aad: Buffer, body: Uint8Array) => {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad);
    return Buffer.concat([cipher.update(body), cipher.final(), cipher.getAuthTag()]);
  };
  const envelope = {
    format_version: 2,
    kind: 'owner-key',
    credential_id: encodeBase64Url(credential),
    prf_input: encodeBase64Url(input),
    salt: encodeBase64Url(salt),
    nonce: encodeBase64Url(nonce),
    wrapped_key: encrypt(
      new Uint8Array(key),
      nonce,
      encode(['mikaki-vault-owner-wrap', ...common]),
      root,
    ).toString('base64url'),
  };
  const opened = await openOwnerKey(envelope, context, credential, output);
  assert(output.every((v) => v === 0));
  const dek = new Uint8Array(32).fill(0x70),
    dataNonce = new Uint8Array(12).fill(0x80),
    keyNonce = new Uint8Array(12).fill(0x90);
  const recordCommon = [
    '2',
    context.origin,
    'owner',
    'vault',
    '1',
    'profile',
    'name',
    'attribute',
    '1',
  ];
  const p = text('known v2 record');
  const record = {
    format_version: 2 as const,
    ciphertext: Buffer.concat([
      Buffer.from([2]),
      dataNonce,
      encrypt(
        dek,
        dataNonce,
        encode(['mikaki-vault-record-content', ...recordCommon.filter((_, i) => i !== 4)]),
        p,
      ),
    ]).toString('base64url'),
    key_envelope: Buffer.concat([
      Buffer.from([2]),
      keyNonce,
      encrypt(root, keyNonce, encode(['mikaki-vault-record-key', ...recordCommon]), dek),
    ]).toString('base64url'),
  };
  assert.deepEqual(await openOwnerRecord(record, opened, context, item), p);
});

test('owner wrapping rejects wrong origin/owner/vault/generation/credential/input and tampering', async () => {
  const f = fixture(),
    created = await createOwnerKey(context, f.credential, bytes(), f.output.slice());
  for (const c of [
    { ...context, origin: 'https://other.example' },
    { ...context, ownerId: 'other' },
    { ...context, vaultId: 'other' },
    { ...context, keyGeneration: 2 },
  ])
    await assert.rejects(openOwnerKey(created.envelope, c, f.credential, f.output.slice()));
  await assert.rejects(openOwnerKey(created.envelope, context, bytes(), f.output.slice()));
  for (const field of ['prf_input', 'salt', 'nonce', 'wrapped_key'] as const)
    await assert.rejects(
      openOwnerKey(
        { ...created.envelope, [field]: corrupt(created.envelope[field]) },
        context,
        f.credential,
        f.output.slice(),
      ),
    );
  const absent = new Uint8Array(0);
  await assert.rejects(openOwnerKey(created.envelope, context, f.credential, absent));
  const failed = bytes();
  await assert.rejects(openOwnerKey(created.envelope, context, f.credential, failed));
  assert(failed.every((v) => v === 0));
});

test('records bind every identity/version field and use fresh keys/nonces; size and strict encodings are enforced', async () => {
  const f = fixture(),
    created = await createOwnerKey(context, f.credential, bytes(), f.output.slice());
  const first = await sealOwnerRecord(text('name'), created.key, context, item);
  const second = await sealOwnerRecord(text('name'), created.key, context, item);
  assert.notEqual(first.ciphertext, second.ciphertext);
  assert.notEqual(first.key_envelope, second.key_envelope);
  for (const r of [
    { ...item, collectionId: 'other' },
    { ...item, recordId: 'other' },
    { ...item, kind: 'message' },
    { ...item, revision: 2 },
  ])
    await assert.rejects(openOwnerRecord(first, created.key, context, r));
  for (const c of [
    { ...context, origin: 'https://other.example' },
    { ...context, ownerId: 'other' },
    { ...context, vaultId: 'other' },
    { ...context, keyGeneration: 2 },
  ])
    await assert.rejects(openOwnerRecord(first, created.key, c, item));
  for (const field of ['ciphertext', 'key_envelope'] as const)
    await assert.rejects(
      openOwnerRecord({ ...first, [field]: corrupt(first[field]) }, created.key, context, item),
    );
  await assert.rejects(
    openOwnerRecord({ ...first, key_envelope: second.key_envelope }, created.key, context, item),
  );
  const max = await sealOwnerRecord(
    new Uint8Array(OWNER_RECORD_MAX_BYTES - 29),
    created.key,
    context,
    item,
  );
  assert.equal(
    (await openOwnerRecord(max, created.key, context, item)).length,
    OWNER_RECORD_MAX_BYTES - 29,
  );
  await assert.rejects(
    sealOwnerRecord(new Uint8Array(OWNER_RECORD_MAX_BYTES - 28), created.key, context, item),
  );
  for (const bad of [
    { ...created.envelope, format_version: 1 },
    { ...created.envelope, extra: true },
    { ...created.envelope, salt: 'a=' },
    { ...created.envelope, credential_id: 'x'.repeat(10000) },
    { ...created.envelope, nonce: '' },
  ])
    assert.throws(() => parseOwnerKeyEnvelope(bad));
});

test('additional credential wraps the same owner key without rewriting record ciphertext', async () => {
  const f = fixture(),
    created = await createOwnerKey(context, f.credential, bytes(), f.output.slice());
  const record = await sealOwnerRecord(text('retained'), created.key, context, item);
  const target = bytes(),
    targetOutput = bytes(),
    sourceConsumed = f.output.slice(),
    targetConsumed = targetOutput.slice();
  const envelope = await rewrapOwnerKey(
    created.envelope,
    context,
    f.credential,
    sourceConsumed,
    target,
    bytes(),
    targetConsumed,
  );
  assert(sourceConsumed.every((v) => v === 0));
  assert(targetConsumed.every((v) => v === 0));
  const targetKey = await openOwnerKey(envelope, context, target, targetOutput.slice());
  assert.deepEqual(await openOwnerRecord(record, targetKey, context, item), text('retained'));
  const originalKey = await openOwnerKey(created.envelope, context, f.credential, f.output.slice());
  assert.deepEqual(await openOwnerRecord(record, originalKey, context, item), text('retained'));
  await assert.rejects(openOwnerKey(envelope, context, f.credential, f.output.slice()));
  await assert.rejects(
    rewrapOwnerKey(
      created.envelope,
      context,
      f.credential,
      f.output.slice(),
      f.credential,
      bytes(),
      targetOutput.slice(),
    ),
  );
});

test('parent rotation keeps ciphertext while changing its envelope; content-key rotation reseals it', async () => {
  const f = fixture(),
    first = await createOwnerKey(context, f.credential, bytes(), f.output.slice());
  const nextContext = { ...context, keyGeneration: 2 };
  const next = await createOwnerKey(nextContext, f.credential, bytes(), f.output.slice());
  const record = await sealOwnerRecord(text('retained body'), first.key, context, item);
  const rotated = await rewrapOwnerRecord(record, first.key, context, next.key, nextContext, item);
  assert.equal(rotated.ciphertext, record.ciphertext);
  assert.notEqual(rotated.key_envelope, record.key_envelope);
  assert.deepEqual(
    await openOwnerRecord(rotated, next.key, nextContext, item),
    text('retained body'),
  );
  await assert.rejects(openOwnerRecord(rotated, first.key, context, item));
  await assert.rejects(openOwnerRecord(record, next.key, nextContext, item));
  await assert.rejects(
    rewrapOwnerRecord(
      { ...record, ciphertext: corrupt(record.ciphertext) },
      first.key,
      context,
      next.key,
      nextContext,
      item,
    ),
  );
  for (const bad of [
    { ...nextContext, ownerId: 'other' },
    { ...nextContext, origin: 'https://other.example' },
    { ...nextContext, vaultId: 'other' },
    { ...nextContext, keyGeneration: 3 },
  ])
    await assert.rejects(rewrapOwnerRecord(record, first.key, context, next.key, bad, item));
  const replacement = await sealOwnerRecord(text('retained body'), next.key, nextContext, {
    ...item,
    revision: 2,
  });
  assert.notEqual(replacement.ciphertext, record.ciphertext);
});

test('lock while PRF is pending consumes late output and cannot restore key; duplicate unlock is rejected', async () => {
  const f = fixture(),
    created = await createOwnerKey(context, f.credential, bytes(), f.output.slice());
  const session = new OwnerKeySession(f.scope, context);
  let resolve!: (value: {
    credentialId: Uint8Array<ArrayBuffer>;
    output: Uint8Array<ArrayBuffer>;
  }) => void;
  let entered!: () => void;
  const started = new Promise<void>((r) => (entered = r));
  const late = new Promise<{
    credentialId: Uint8Array<ArrayBuffer>;
    output: Uint8Array<ArrayBuffer>;
  }>((r) => (resolve = r));
  const pending = session.unlock(created.envelope, async () => {
    entered();
    return late;
  });
  await started;
  await assert.rejects(
    session.unlock(created.envelope, async () => {
      throw new Error('must not run');
    }),
  );
  session.lock();
  const output = f.output.slice();
  resolve({ credentialId: f.credential, output });
  await assert.rejects(pending);
  assert(output.every((v) => v === 0));
  assert.equal(session.opened, false);
});

test('wrong credential and canceled/unsupported PRF never open an owner lease', async () => {
  const f = fixture(),
    created = await createOwnerKey(context, f.credential, bytes(), f.output.slice());
  const session = new OwnerKeySession(f.scope, context),
    wrong = f.output.slice();
  await assert.rejects(
    session.unlock(created.envelope, async () => ({ credentialId: bytes(), output: wrong })),
  );
  assert(wrong.every((v) => v === 0));
  assert.equal(session.opened, false);
  await assert.rejects(
    session.unlock(created.envelope, async () => {
      throw new DOMException('cancel', 'NotAllowedError');
    }),
  );
  await assert.rejects(
    session.unlock(created.envelope, async () => ({
      credentialId: f.credential,
      output: new Uint8Array(0),
    })),
  );
  assert.equal(session.opened, false);
});

test('initialization also rejects and clears a late PRF result after disposal', async () => {
  const f = fixture(),
    session = new OwnerKeySession(f.scope, context);
  let resolve!: (value: {
    credentialId: Uint8Array<ArrayBuffer>;
    output: Uint8Array<ArrayBuffer>;
  }) => void;
  let entered!: () => void;
  const started = new Promise<void>((r) => (entered = r));
  const response = new Promise<{
    credentialId: Uint8Array<ArrayBuffer>;
    output: Uint8Array<ArrayBuffer>;
  }>((r) => (resolve = r));
  const pending = session.initialize(async () => {
    entered();
    return response;
  });
  await started;
  session.dispose();
  const output = f.output.slice();
  resolve({ credentialId: f.credential, output });
  await assert.rejects(pending);
  assert(output.every((v) => v === 0));
  assert.equal(session.opened, false);
});

test('suspend/resume retains a valid owner lease without new PRF; late plaintext/seal results are rejected', async () => {
  const f = fixture(),
    created = await createOwnerKey(context, f.credential, bytes(), f.output.slice());
  let visible = true,
    calls = 0;
  const session = new OwnerKeySession(f.scope, context, () => visible);
  await session.unlock(created.envelope, async () => {
    calls++;
    return { credentialId: f.credential, output: f.output.slice() };
  });
  const record = await session.seal(text('value'), item);
  visible = false;
  session.suspend();
  assert.equal(session.opened, false);
  await assert.rejects(session.open(record, item));
  visible = true;
  await session.resume();
  assert.equal(session.opened, true);
  assert.equal(calls, 1);
  const pending = session.open(record, item);
  session.suspend();
  await assert.rejects(pending);
  await session.resume();
  const save = session.seal(text('late save'), item);
  session.dispose();
  await assert.rejects(save);
  assert.equal(session.opened, false);
});

test('idle/absolute expiry, session replacement and pagehide abort the owner-key lease', async () => {
  for (const reason of ['idle', 'absolute', 'session', 'pagehide'] as const) {
    let now = 0;
    const f = fixture(() => now),
      created = await createOwnerKey(context, f.credential, bytes(), f.output.slice());
    const session = new OwnerKeySession(f.scope, context);
    await session.unlock(created.envelope, async () => ({
      credentialId: f.credential,
      output: f.output.slice(),
    }));
    if (reason === 'idle') now = VAULT_IDLE_MS;
    if (reason === 'absolute') now = VAULT_ABSOLUTE_MS;
    if (reason === 'session')
      assert.throws(() => f.scope.observe({ ...f.identity, session_tag: 't'.repeat(43) }));
    if (reason === 'pagehide') f.scope.end('pagehide');
    assert.equal(session.opened, false);
    assert.equal(f.scope.signal.aborted, true);
  }
});

test('new format rejects an opaque v1 envelope; plaintext input/context are snapshotted', async () => {
  const f = fixture();
  const created = await createOwnerKey(context, f.credential, bytes(), f.output.slice());
  const c = { ...context },
    r = { ...item },
    p = text('original');
  const pending = sealOwnerRecord(p, created.key, c, r);
  p.fill(0);
  c.ownerId = 'changed';
  r.recordId = 'changed';
  const record = await pending;
  assert.deepEqual(await openOwnerRecord(record, created.key, context, item), text('original'));
  const retired = { format_version: 1, ciphertext: 'opaque-retired-data' } as never;
  await assert.rejects(openOwnerRecord(retired, created.key, context, item));
});
