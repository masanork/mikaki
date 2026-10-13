import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { createSourceFixture } from './support/work-source-fixture.ts';

const rawKey = Buffer.alloc(32, 7);
function field(bytes: Buffer) {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  return Buffer.concat([length, bytes]);
}
const fingerprint = createHash('sha256')
  .update(field(Buffer.from('mikaki.work-credential-key.v1')))
  .update(field(rawKey))
  .digest('hex');
const bindings = {
  WORK_CREDENTIAL_KEY_ADMIN_ENABLED: 'true',
  WORK_CREDENTIAL_KEY_FLOOR: '1',
  WORK_CREDENTIAL_KEY_V1: rawKey.toString('base64url'),
  WORK_CREDENTIAL_KEY_V2: Buffer.alloc(32, 8).toString('base64url'),
};
const input = {
  action: 'initialize-work-credential-key',
  key_version: 1,
  expected_fingerprint: fingerprint,
};
async function fixture(overrides: Record<string, string> = {}, enrolled = true) {
  return createSourceFixture(
    undefined,
    false,
    enrolled ? 'product' : 'product-unenrolled',
    false,
    3600,
    false,
    { ...bindings, ...overrides },
  );
}
function call(f: Awaited<ReturnType<typeof fixture>>, value: unknown) {
  return f.fixture.fetch('https://work.test/authority-fixture', {
    method: 'POST',
    body: JSON.stringify(value),
  });
}
async function count(f: Awaited<ReturnType<typeof fixture>>, table: string) {
  return Number(await f.DB.prepare(`SELECT count(*) AS n FROM ${table}`).first('n'));
}

test('initial key activation uses enrolled product authority and retries only the retained metadata', async () => {
  const f = await fixture();
  try {
    const inspect = { action: 'inspect-work-credential-key', key_version: 1 };
    assert.deepEqual(await (await call(f, inspect)).json(), { key: null });
    const results = await Promise.all([call(f, input), call(f, input)]);
    assert.ok(results.some((r) => r.status === 200));
    assert.ok(results.every((r) => [200, 409].includes(r.status)));
    assert.equal(await count(f, 'work_credential_key'), 1);
    assert.equal(await count(f, 'work_credential_key_audit'), 1);
    const marker = await f.DB.prepare('SELECT sequence,tip FROM work_authority_checkpoint').first();
    const expected = { key: { version: 1, fingerprint, state: 'active' } };
    const retry = await call(f, input);
    assert.equal(retry.status, 200);
    assert.equal(retry.headers.get('Cache-Control'), 'no-store');
    assert.deepEqual(await retry.json(), expected);
    assert.deepEqual(await (await call(f, inspect)).json(), expected);
    assert.deepEqual(
      await f.DB.prepare('SELECT sequence,tip FROM work_authority_checkpoint').first(),
      marker,
    );
    assert.equal(await count(f, 'work_credential_key_audit'), 1);
    assert.equal(await count(f, 'work_credential_attempt'), 0);
    assert.equal(await count(f, 'work_task_repository'), 0);
    assert.equal(await count(f, 'work_grant'), 0);
    assert.equal(await count(f, 'work_run'), 0);
    assert.equal(
      (await f.http('/authority', f.first, { method: 'POST', body: JSON.stringify(input) })).status,
      404,
    );
    assert.equal(
      (
        await f.http('/work/credential-key', f.first, {
          method: 'POST',
          body: JSON.stringify(input),
        })
      ).status,
      404,
    );
    const { OP_AUTHORITY_ADMIN } = await f.fixture.getEnv();
    assert.equal((await OP_AUTHORITY_ADMIN.administer_op_authority()).status, 404);
    const secondKey = Buffer.alloc(32, 8);
    const secondFingerprint = createHash('sha256')
      .update(field(Buffer.from('mikaki.work-credential-key.v1')))
      .update(field(secondKey))
      .digest('hex');
    assert.equal(
      (await call(f, { ...input, key_version: 2, expected_fingerprint: secondFingerprint })).status,
      409,
    );
    assert.deepEqual(
      await f.DB.prepare('SELECT version,fingerprint,state FROM work_credential_key')
        .all()
        .then((r: { results: unknown[] }) => r.results),
      [expected.key],
    );
  } finally {
    await f.close();
  }
});

test('key fingerprint, closed input, floor and disabled/missing secret fail before registration', async (t) => {
  const f = await fixture();
  try {
    for (const value of [
      { ...input, expected_fingerprint: '0'.repeat(64) },
      { ...input, key_version: 0 },
      { ...input, key_version: Number.MAX_SAFE_INTEGER + 1 },
      { ...input, plaintext: rawKey.toString('base64url') },
      { ...input, expected_fingerprint: 'not-a-digest' },
      { action: 'retire-work-credential-key', key_version: 1 },
    ])
      assert.equal((await call(f, value)).status, 409);
    assert.equal(await count(f, 'work_credential_key'), 0);
    assert.equal(await count(f, 'work_credential_key_audit'), 0);
  } finally {
    await f.close();
  }
  const overrides: Record<string, string>[] = [
    { WORK_CREDENTIAL_KEY_ADMIN_ENABLED: 'false' },
    { WORK_CREDENTIAL_KEY_V1: '' },
    { WORK_CREDENTIAL_KEY_FLOOR: '2' },
  ];
  for (const override of overrides)
    await t.test(Object.keys(override)[0]!, async () => {
      const f = await fixture(override);
      try {
        assert.equal((await call(f, input)).status, 409);
        assert.equal(await count(f, 'work_credential_key'), 0);
        assert.equal(await count(f, 'work_credential_key_audit'), 0);
      } finally {
        await f.close();
      }
    });
});

test('key audit failure rolls back the activation and preserves a usable authority frame', async () => {
  const f = await fixture();
  try {
    await f.DB.prepare(
      "CREATE TRIGGER synthetic_key_audit_failure BEFORE INSERT ON work_credential_key_audit BEGIN SELECT RAISE(ABORT,'synthetic audit unavailable'); END",
    ).run();
    assert.equal((await call(f, input)).status, 409);
    assert.equal(await count(f, 'work_credential_key'), 0);
    assert.equal(await count(f, 'work_credential_key_audit'), 0);
    await f.DB.prepare('DROP TRIGGER synthetic_key_audit_failure').run();
    assert.equal((await call(f, input)).status, 200);
    assert.equal(await count(f, 'work_credential_key_audit'), 1);
  } finally {
    await f.close();
  }
});

test('unenrolled or independently frozen authority cannot initialize a key', async () => {
  const absent = await fixture({}, false);
  try {
    assert.equal((await call(absent, input)).status, 409);
    assert.equal(await count(absent, 'work_credential_key'), 0);
  } finally {
    await absent.close();
  }
  const f = await fixture();
  try {
    const frozen = await f.checkpoint({ action: 'freeze' });
    assert.equal(frozen.status, 200);
    assert.equal((await call(f, input)).status, 409);
    assert.equal(await count(f, 'work_credential_key'), 0);
  } finally {
    await f.close();
  }
});
