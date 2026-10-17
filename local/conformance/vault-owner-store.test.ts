/** Client-side contracts without a Worker: exercise real scope, crypto and response parsing. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { VaultScope } from '../../crates/worker/ui/vault-lifecycle.ts';
import { encodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';
import { ownerLoginPrfInput } from '../../crates/worker/ui/vault-login-prf.ts';
import {
  createOwnerKey,
  OWNER_KEY_SUITE,
  wrapOwnerKeyForLogin,
} from '../../crates/worker/ui/vault-owner-crypto.ts';
import {
  commitOwnerKeyWrapperOperation,
  createOwnerKeyWrapperOperation,
  openOwnerVault,
  readOwnerKey,
  readOwnerKeyWrappers,
  sameOwnerAuthority,
} from '../../crates/worker/ui/vault-owner-store.ts';

const origin = 'https://mikaki.test';
const random = () => crypto.getRandomValues(new Uint8Array(32));
async function fixture() {
  const credential = random(),
    output = random();
  const context = { origin, ownerId: 'owner', vaultId: 'vault', keyGeneration: 1 };
  const { envelope } = await createOwnerKey(context, credential, random(), output.slice());
  const identity = {
    account_id: 'owner',
    credential_id: encodeBase64Url(credential),
    session_tag: 's'.repeat(43),
  };
  const stored = { context, revision: 1, envelope };
  const wire = {
    format_version: 2,
    suite: OWNER_KEY_SUITE,
    origin,
    owner_id: 'owner',
    vault_id: 'vault',
    key_generation: 1,
    revision: 1,
    owner_envelope: envelope,
  };
  const responses: (() => Response | Promise<Response>)[] = [];
  const calls: { path: string; init?: RequestInit }[] = [];
  const scope = new VaultScope(
    () => {},
    undefined,
    undefined,
    async (input, init) => {
      calls.push({ path: String(input), init });
      const next = responses.shift();
      assert.ok(next, 'unexpected request');
      return next();
    },
  );
  scope.observe(identity);
  const reply = (value: unknown, status = 200, etag = '"1"') =>
    responses.push(() => Response.json(value, { status, headers: { etag } }));
  return { scope, responses, calls, reply, stored, wire, credential, output, identity };
}

test('owner-key reads require the exact owner, credential, format, generation and ETag', async () => {
  const f = await fixture();
  f.reply(f.wire);
  assert.deepEqual(await readOwnerKey(f.scope, origin), f.stored);
  assert.equal(f.calls[0].init?.cache, 'no-store');
  for (const patch of [
    { owner_id: 'another-owner' },
    { origin: 'https://other.test' },
    { format_version: 1 },
    { suite: 'unknown' },
    { revision: 0 },
    { revision: 1.5 },
    { key_generation: 0 },
    { vault_id: '' },
    { owner_envelope: { ...f.wire.owner_envelope, credential_id: encodeBase64Url(random()) } },
  ]) {
    f.reply({ ...f.wire, ...patch });
    await assert.rejects(readOwnerKey(f.scope, origin));
  }
  f.reply(f.wire, 200, '"2"');
  await assert.rejects(readOwnerKey(f.scope, origin), /revision mismatch/);
  for (const value of [null, [], 'invalid']) {
    f.reply(value);
    await assert.rejects(readOwnerKey(f.scope, origin));
  }
  f.reply({ error: 'owner_key_missing' }, 404);
  assert.equal(await readOwnerKey(f.scope, origin), null);
  f.reply({ error: 'unrelated' }, 404);
  await assert.rejects(readOwnerKey(f.scope, origin), /unavailable/);
  f.reply({ error: 'credential_not_wrapped' }, 409);
  await assert.rejects(readOwnerKey(f.scope, origin), /credential_not_wrapped/);
  f.responses.push(() => new Response('invalid JSON'));
  await assert.rejects(readOwnerKey(f.scope, origin));
});

test('additive login custody must keep the original owner authority and fixed PRF input', async () => {
  const f = await fixture();
  const loginOutput = random();
  const login = await wrapOwnerKeyForLogin(
    f.stored.envelope,
    f.stored.context,
    f.credential,
    f.output.slice(),
    loginOutput.slice(),
  );
  f.reply(f.wire);
  f.reply({ ...f.wire, login_envelope: login });
  const result = await readOwnerKey(f.scope, origin, true);
  assert.deepEqual(result?.loginEnvelope, login);
  assert.equal(sameOwnerAuthority(f.stored, result!), true);
  assert.equal(f.calls[1].path, '/vault/owner-key/login-wrap');
  for (const patch of [
    { revision: 2 },
    { vault_id: 'other' },
    { owner_envelope: { ...f.stored.envelope, nonce: encodeBase64Url(random().slice(0, 12)) } },
    { login_envelope: { ...login, credential_id: encodeBase64Url(random()) } },
    { login_envelope: { ...login, prf_input: encodeBase64Url(random()) } },
  ]) {
    f.reply(f.wire);
    f.reply({ ...f.wire, login_envelope: login, ...patch });
    await assert.rejects(readOwnerKey(f.scope, origin, true));
  }
  f.reply(f.wire);
  f.reply({ error: 'login_wrapper_missing' }, 404);
  assert.deepEqual(await readOwnerKey(f.scope, origin, true), f.stored);
  f.reply(f.wire);
  f.reply({ error: 'unavailable' }, 503);
  await assert.rejects(readOwnerKey(f.scope, origin, true), /unavailable/);
  assert.equal(sameOwnerAuthority(f.stored, { ...f.stored, revision: 2 }), false);
});

test('wrapper registry rejects ambiguous credentials, wrong authority and inactive current credentials', async () => {
  const f = await fixture();
  const credentials = [{ credential_id: f.stored.envelope.credential_id, active: 1 }];
  const wire = { vault_id: 'vault', key_generation: 1, revision: 1, credentials };
  f.reply(wire);
  const registry = await readOwnerKeyWrappers(f.scope, f.stored);
  assert.equal(registry.credentials[0].active, true);
  assert.ok(Object.isFrozen(registry.credentials));
  for (const patch of [
    { extra: true },
    { vault_id: 'other' },
    { key_generation: 2 },
    { revision: 2 },
    { credentials: null },
    { credentials: Array(11).fill(credentials[0]) },
    { credentials: [credentials[0], credentials[0]] },
    { credentials: [{ ...credentials[0], active: 0 }] },
    { credentials: [{ ...credentials[0], active: true }] },
    { credentials: [{ ...credentials[0], extra: true }] },
    { credentials: [{ credential_id: 'a=', active: 1 }] },
    { credentials: [{ credential_id: '', active: 1 }] },
    { credentials: [{ credential_id: encodeBase64Url(new Uint8Array(513)), active: 1 }] },
    { credentials: [null] },
  ]) {
    f.reply({ ...wire, ...patch });
    await assert.rejects(readOwnerKeyWrappers(f.scope, f.stored));
  }
  f.reply(wire, 200, '"2"');
  await assert.rejects(readOwnerKeyWrappers(f.scope, f.stored), /owner_key_changed/);
  for (const status of [409, 503]) {
    f.reply({}, status);
    await assert.rejects(
      readOwnerKeyWrappers(f.scope, f.stored),
      status === 409 ? /owner_key_changed/ : /wrappers_unavailable/,
    );
  }
});

test('wrapper mutation retries preserve the same body and operation ID; receipts bind every field', async () => {
  const f = await fixture();
  for (const method of ['PUT', 'DELETE'] as const) {
    const operation = createOwnerKeyWrapperOperation(
      method,
      f.stored,
      f.stored.envelope.credential_id,
      method === 'PUT' ? f.stored.envelope : undefined,
    );
    assert.ok(Object.isFrozen(operation));
    const receipt = {
      action: operation.action,
      credential_id: operation.credentialId,
      key_generation: operation.keyGeneration,
      operation_id: operation.operationId,
      previous_revision: 1,
      revision: 2,
      vault_id: 'vault',
    };
    for (let attempt = 0; attempt < 2; attempt++) {
      f.reply(receipt, 200, '"2"');
      const result = await commitOwnerKeyWrapperOperation(f.scope, operation);
      assert.equal(result.operationId, operation.operationId);
      const { init } = f.calls.at(-1)!;
      assert.equal(init?.body, operation.body);
      assert.equal(new Headers(init?.headers).get('X-Operation-ID'), operation.operationId);
      assert.equal(new Headers(init?.headers).get('If-Match'), '"1"');
    }
    for (const field of Object.keys(receipt)) {
      f.reply({ ...receipt, [field]: 'wrong' }, 200, '"2"');
      await assert.rejects(commitOwnerKeyWrapperOperation(f.scope, operation), /unconfirmed/);
    }
    f.reply({ ...receipt, extra: true }, 200, '"2"');
    await assert.rejects(commitOwnerKeyWrapperOperation(f.scope, operation), /unconfirmed/);
    f.reply(receipt, 200, '"1"');
    await assert.rejects(commitOwnerKeyWrapperOperation(f.scope, operation), /unconfirmed/);
    for (const [status, error] of [
      [409, 'conflict'],
      [403, 'origin'],
      [400, 'rejected'],
      [503, 'unavailable'],
    ] as const) {
      f.reply({}, status);
      if (status === 403) f.reply(f.identity);
      await assert.rejects(commitOwnerKeyWrapperOperation(f.scope, operation), new RegExp(error));
    }
    f.responses.push(() => new Response('bad JSON'));
    await assert.rejects(commitOwnerKeyWrapperOperation(f.scope, operation));
  }
  assert.throws(() =>
    createOwnerKeyWrapperOperation('PUT', f.stored, f.stored.envelope.credential_id),
  );
  assert.throws(() =>
    createOwnerKeyWrapperOperation(
      'DELETE',
      f.stored,
      f.stored.envelope.credential_id,
      f.stored.envelope,
    ),
  );
  assert.throws(() => createOwnerKeyWrapperOperation('DELETE', f.stored, 'a='));
});

test('a lost bootstrap response reconciles only the exact encrypted candidate without a second initialization', async () => {
  const f = await fixture();
  f.reply({ error: 'owner_key_missing' }, 404);
  let candidate: Record<string, any>;
  f.responses.push(() => {
    const body = JSON.parse(String(f.calls.at(-1)?.init?.body));
    candidate = { ...body, origin, owner_id: 'owner', revision: 1 };
    throw new Error('response lost after commit');
  });
  f.responses.push(() => Response.json(candidate, { headers: { etag: '"1"' } }));
  let ceremonies = 0;
  const result = await openOwnerVault(f.scope, origin, async () => {
    ceremonies++;
    return { credentialId: f.credential, output: f.output.slice() };
  });
  try {
    assert.equal(result.created, true);
    assert.equal(result.session.opened, true);
    assert.equal(ceremonies, 1);
    assert.equal(f.calls.filter(({ init }) => init?.method === 'PUT').length, 1);
    assert.equal(new Headers(f.calls[1].init?.headers).get('If-None-Match'), '*');
  } finally {
    result.session.dispose();
  }
});

test('bootstrap conflict and a scope invalidated during PRF never leave an open owner lease', async () => {
  const f = await fixture();
  f.reply({ error: 'owner_key_missing' }, 404);
  f.reply({}, 409);
  f.reply(f.wire);
  await assert.rejects(
    openOwnerVault(f.scope, origin, async () => ({
      credentialId: f.credential,
      output: f.output.slice(),
    })),
    /conflict\/unconfirmed/,
  );
  const g = await fixture();
  g.reply({ error: 'owner_key_missing' }, 404);
  const evaluated = g.output.slice();
  await assert.rejects(
    openOwnerVault(g.scope, origin, async () => {
      g.scope.end('pagehide');
      return { credentialId: g.credential, output: evaluated };
    }),
  );
  assert.ok(evaluated.every((byte) => byte === 0));
  assert.equal(g.calls.length, 1, 'never writes a root after invalidation');
});

test('existing owner keys unlock through fixed login custody without creating another root', async () => {
  const f = await fixture();
  const loginOutput = random();
  const login = await wrapOwnerKeyForLogin(
    f.stored.envelope,
    f.stored.context,
    f.credential,
    f.output.slice(),
    loginOutput.slice(),
  );
  f.reply(f.wire);
  f.reply({ ...f.wire, login_envelope: login });
  const consumed = loginOutput.slice();
  const result = await openOwnerVault(
    f.scope,
    origin,
    async (_credential, input) => {
      assert.deepEqual(input, ownerLoginPrfInput());
      return { credentialId: f.credential, output: consumed };
    },
    undefined,
    true,
  );
  try {
    assert.equal(result.created, false);
    assert.equal(result.session.opened, true);
    assert.ok(consumed.every((byte) => byte === 0));
    assert.ok(f.calls.every(({ init }) => !init?.method));
  } finally {
    result.session.dispose();
  }
});
