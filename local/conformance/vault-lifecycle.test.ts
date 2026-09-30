import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  VaultScope,
  VAULT_IDLE_MS,
  VAULT_ABSOLUTE_MS,
  parseVaultIdentity,
  type LockReason,
} from '../../crates/worker/ui/vault-lifecycle.ts';

const identity = { account_id: 'owner', credential_id: 'credential', session_tag: 's'.repeat(43) };
test('Vault deadlines use both clocks, expire at the boundary, and never renew absolute expiry', () => {
  let wall = 0,
    mono = 0;
  const reasons: LockReason[] = [];
  const scope = new VaultScope(
    (reason) => reasons.push(reason),
    () => wall,
    () => mono,
  );
  for (let minute = 10; minute < 60; minute += 10) {
    wall = mono = minute * 60_000;
    scope.activity();
  }
  wall = mono = VAULT_ABSOLUTE_MS;
  assert.throws(() => scope.activity(), /locked/);
  assert.deepEqual(reasons, ['absolute']);
  const idle = new VaultScope(
    (reason) => reasons.push(reason),
    () => wall,
    () => mono,
  );
  wall += VAULT_IDLE_MS - 1;
  assert.equal(idle.expired(), null);
  wall += 1;
  assert.throws(() => idle.assert(), /locked/);
  assert.equal(reasons.at(-1), 'idle');
  const rollback = new VaultScope(
    (reason) => reasons.push(reason),
    () => wall,
    () => mono,
  );
  wall -= 1;
  assert.throws(() => rollback.assert(), /locked/);
  const monotonic = new VaultScope(
    (reason) => reasons.push(reason),
    () => wall,
    () => mono,
  );
  mono += VAULT_IDLE_MS;
  assert.throws(() => monotonic.assert(), /locked/);
});
test('resume verification blocks outgoing writes, and detects same-account replacement sessions', async () => {
  let release!: (response: Response) => void;
  let writes = 0;
  const reasons: LockReason[] = [];
  const scope = new VaultScope(
    (reason) => reasons.push(reason),
    () => 0,
    () => 0,
    async (_input, init) => {
      if (init?.method === 'PUT') {
        writes++;
        return new Response('{}');
      }
      return await new Promise<Response>((resolve) => {
        release = resolve;
      });
    },
  );
  scope.observe(identity);
  const verification = scope.verify();
  const write = scope.request('/vault/attributes/name', { method: 'PUT' });
  await Promise.resolve();
  assert.equal(writes, 0);
  release(Response.json({ ...identity, session_tag: 't'.repeat(43) }));
  await verification;
  await assert.rejects(write, /locked/);
  assert.equal(writes, 0);
  assert.deepEqual(reasons, ['session']);
});
test('lock aborts in-flight requests and rejects late replies and future requests', async () => {
  let release!: (response: Response) => void;
  let signal: AbortSignal | null = null;
  let requests = 0;
  const scope = new VaultScope(
    () => {},
    () => 0,
    () => 0,
    async (_input, init) => {
      requests++;
      signal = init?.signal ?? null;
      return await new Promise<Response>((resolve) => {
        release = resolve;
      });
    },
  );
  const pending = scope.request('/vault/attributes/name');
  await Promise.resolve();
  scope.end('manual');
  assert.equal((signal as AbortSignal | null)?.aborted, true);
  release(Response.json({ data: 'late response' }));
  await assert.rejects(pending, /locked/);
  await assert.rejects(scope.request('/vault/attributes/name', { method: 'PUT' }), /locked/);
  assert.equal(requests, 1);
});
test('malformed identity, unavailable verification and unauthorized responses lock fail closed', async () => {
  assert.throws(() => parseVaultIdentity({ ...identity, session_tag: undefined }));
  for (const status of [401, 503]) {
    const reasons: LockReason[] = [];
    const scope = new VaultScope(
      (reason) => reasons.push(reason),
      () => 0,
      () => 0,
      async () => new Response('{}', { status }),
    );
    scope.observe(identity);
    await scope.verify();
    assert.equal(scope.signal.aborted, true);
    assert.deepEqual(reasons, [status === 401 ? 'session' : 'unconfirmed']);
  }
});

test('a forbidden grant does not discard a valid session, but failed confirmation does', async () => {
  for (const valid of [true, false]) {
    const reasons: LockReason[] = [];
    const scope = new VaultScope(
      (reason) => reasons.push(reason),
      () => 0,
      () => 0,
      async (input) =>
        input === '/vault/session'
          ? valid
            ? Response.json(identity)
            : new Response('{}', { status: 503 })
          : new Response('{}', { status: 403 }),
    );
    scope.observe(identity);
    if (valid) {
      assert.equal((await scope.request('/vault/agents/grants', { method: 'POST' })).status, 403);
      assert.deepEqual(reasons, []);
    } else {
      await assert.rejects(scope.request('/vault/agents/grants', { method: 'POST' }), /locked/);
      assert.deepEqual(reasons, ['unconfirmed']);
    }
  }
});
