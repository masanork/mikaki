import assert from 'node:assert/strict';
import { test } from 'node:test';
import { VaultScope } from '../../crates/worker/ui/vault-lifecycle.ts';
import { OwnerVaultController } from '../../crates/worker/ui/vault-owner-controller.ts';
import {
  OwnerRecordStore,
  OWNER_NAME,
  OWNER_NOTE,
} from '../../crates/worker/ui/vault-owner-record-store.ts';
import { encodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';

const credential = new Uint8Array(32).fill(8);
const identity = {
  account_id: 'owner',
  credential_id: encodeBase64Url(credential),
  session_tag: 's'.repeat(43),
};
function fixture() {
  let root: Record<string, unknown> | null = null;
  const heads = new Map<string, Record<string, unknown>>(),
    operations = new Map<string, { bytes: string; revision: number; deleted: boolean }>();
  let calls = 0,
    lost = false,
    visible = true;
  const requests: RequestInit[] = [];
  let hold: Promise<void> | undefined;
  let rejectedRecord: string | null = null;
  let sessionTag = identity.session_tag;
  const transport: typeof fetch = async (input, init) => {
    const path = String(input);
    if (path === '/vault/session') return Response.json({ ...identity, session_tag: sessionTag });
    if (path === '/vault/owner-key') {
      if (init?.method === 'PUT')
        root = {
          ...JSON.parse(String(init.body)),
          revision: 1,
          origin: 'https://mikaki.test',
          owner_id: 'owner',
        };
      return root
        ? Response.json(root, { headers: { ETag: `"${root['revision']}"` } })
        : Response.json({ error: 'owner_key_missing' }, { status: 404 });
    }
    if (rejectedRecord) return Response.json({ error: rejectedRecord }, { status: 409 });
    if (init?.method === 'PUT' || init?.method === 'DELETE') {
      requests.push(init);
      const value = JSON.parse(String(init.body));
      const headers = new Headers(init.headers),
        id = headers.get('X-Operation-ID')!;
      const bytes = JSON.stringify([
        path,
        init.method,
        headers.get('If-Match'),
        headers.get('If-None-Match'),
        init.body,
      ]);
      const existing = operations.get(id);
      if (existing && existing.bytes !== bytes)
        return Response.json({ error: 'operation_id_reused' }, { status: 409 });
      const outcome = existing ?? {
        bytes,
        revision: value.revision,
        deleted: init.method === 'DELETE',
      };
      if (!existing) {
        const current = heads.get(path),
          revision = Number(current?.['revision'] ?? 0);
        if (value.revision !== revision + 1)
          return Response.json({ error: 'revision_conflict' }, { status: 409 });
        heads.set(path, { ...value, deleted: outcome.deleted });
        operations.set(id, outcome);
      }
      if (lost) {
        lost = false;
        throw new Error('lost response after commit');
      }
      return Response.json(
        { revision: outcome.revision, deleted: outcome.deleted },
        { headers: { ETag: `"${outcome.revision}"` } },
      );
    }
    const current = heads.get(path);
    if (hold) await hold;
    if (!current) return Response.json({ error: 'not_found' }, { status: 404 });
    if (current['deleted'])
      return Response.json(
        { error: 'not_found', deleted: true },
        { status: 404, headers: { ETag: `"${current['revision']}"` } },
      );
    const [, , , collection_id, record_id] = path.split('/');
    return Response.json(
      {
        ...current,
        owner_id: 'owner',
        origin: 'https://mikaki.test',
        collection_id,
        record_id,
        owner_key_revision: root!['revision'],
      },
      { headers: { ETag: `"${current['revision']}"` } },
    );
  };
  const scope = new VaultScope(() => {}, undefined, undefined, transport);
  const owner = new OwnerVaultController(
    scope,
    'https://mikaki.test',
    async () => {
      calls++;
      return { credentialId: credential, output: new Uint8Array(32).fill(9) };
    },
    () => visible,
  );
  return {
    owner,
    scope,
    heads,
    requests,
    calls: () => calls,
    lose: () => {
      lost = true;
    },
    rootExists: () => root !== null,
    replaceSession: () => {
      sessionTag = 'r'.repeat(43);
    },
    rejectRecord: (code: string | null) => {
      rejectedRecord = code;
    },
    rootRevision: (revision: number) => {
      root!['revision'] = revision;
    },
    visible: (value: boolean) => {
      visible = value;
    },
    hold: (value: Promise<void> | undefined) => {
      hold = value;
    },
  };
}

test('unified owner controller opens once, preserves exact retries, uses fresh revisions, and never replays historical success over tombstones', async () => {
  const f = fixture();
  await f.owner.open();
  const name = new OwnerRecordStore(f.owner, OWNER_NAME),
    note = new OwnerRecordStore(f.owner, OWNER_NOTE);
  assert.deepEqual(await name.read(), { revision: 0, deleted: false, record: null });
  const first = await name.prepare('PUT', 0, new TextEncoder().encode('First name'));
  f.lose();
  await assert.rejects(name.commit(first));
  await name.commit(first);
  assert.equal(f.requests[0]!.body, f.requests[1]!.body);
  assert.equal(
    new Headers(f.requests[0]!.headers).get('X-Operation-ID'),
    new Headers(f.requests[1]!.headers).get('X-Operation-ID'),
  );
  const opened = await name.readPlaintext(await name.read());
  assert.equal(new TextDecoder().decode(opened), 'First name');
  opened.fill(0);
  await note.commit(await note.prepare('PUT', 0, new TextEncoder().encode('Independent note')));
  const second = await name.prepare('PUT', 1, new TextEncoder().encode('First name'));
  assert.notEqual(JSON.parse(first.body).ciphertext, JSON.parse(second.body).ciphertext);
  await name.commit(second);
  const stale = await name.prepare('PUT', 1, new TextEncoder().encode('Stale'));
  await assert.rejects(name.commit(stale), /revision_conflict/);
  const deletion = await name.prepare('DELETE', 2);
  await name.commit(deletion);
  assert.deepEqual(await name.commit(first), { revision: 1, deleted: false });
  assert.deepEqual(await name.read(), { revision: 3, deleted: true, record: null });
  await name.commit(await name.prepare('PUT', 3, new TextEncoder().encode('Explicit new content')));
  assert.equal((await name.read()).revision, 4);
  await f.owner.open();
  assert.equal(f.calls(), 1);
  f.visible(false);
  f.owner.suspend();
  await assert.rejects(name.read());
  f.visible(true);
  await f.owner.resume();
  assert.equal(f.calls(), 1);
  assert.equal((await name.read()).revision, 4);
  f.owner.lock();
  await assert.rejects(name.commit(first));
});

test('late reads and observed root authority changes cannot restore or continue a lease', async () => {
  const f = fixture();
  await f.owner.open();
  const store = new OwnerRecordStore(f.owner, OWNER_NAME);
  await store.commit(await store.prepare('PUT', 0, new TextEncoder().encode('Private')));
  let release!: () => void;
  f.hold(
    new Promise<void>((resolve) => {
      release = resolve;
    }),
  );
  const pending = store.read();
  await new Promise((resolve) => setImmediate(resolve));
  f.owner.suspend();
  release();
  await assert.rejects(pending);
  f.hold(undefined);
  await f.owner.resume();
  f.rootRevision(2);
  await assert.rejects(store.read(), /owner_key_changed/);
  assert.equal(f.scope.signal.aborted, true);
  assert.throws(() => f.owner.lease());
});

test('late PRF output is cleared and cancelled initialization never stores an owner key', async () => {
  let release!: (value: {
    credentialId: Uint8Array<ArrayBuffer>;
    output: Uint8Array<ArrayBuffer>;
  }) => void;
  let entered!: () => void,
    writes = 0;
  const begun = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const result = new Promise<{
    credentialId: Uint8Array<ArrayBuffer>;
    output: Uint8Array<ArrayBuffer>;
  }>((resolve) => {
    release = resolve;
  });
  const scope = new VaultScope(
    () => {},
    undefined,
    undefined,
    async (url, init) => {
      if (String(url) === '/vault/session') return Response.json(identity);
      if (init?.method === 'PUT') writes++;
      return Response.json({ error: 'owner_key_missing' }, { status: 404 });
    },
  );
  const owner = new OwnerVaultController(scope, 'https://mikaki.test', async () => {
    entered();
    return result;
  });
  const pending = owner.open();
  await begun;
  owner.suspend();
  const output = new Uint8Array(32).fill(2);
  release({ credentialId: credential, output });
  await assert.rejects(pending);
  assert.equal(
    output.every((byte) => byte === 0),
    true,
  );
  assert.equal(writes, 0);
  assert.throws(() => owner.lease());
});

test('suspension after PRF during crypto cannot submit a stale bootstrap', async () => {
  const f = fixture();
  const original = crypto.subtle.encrypt;
  let entered!: () => void, release!: () => void;
  const begun = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  crypto.subtle.encrypt = async (...args: Parameters<SubtleCrypto['encrypt']>) => {
    entered();
    await held;
    return original.apply(crypto.subtle, args);
  };
  try {
    const opening = f.owner.open();
    await begun;
    f.owner.suspend();
    await f.owner.resume();
    release();
    await assert.rejects(opening, /Stale Vault operation/);
    assert.equal(f.rootExists(), false);
    assert.throws(() => f.owner.lease());
  } finally {
    release();
    crypto.subtle.encrypt = original;
  }
});

test('missing owner authority locks reads and writes; a head race keeps unrelated drafts available after root recheck', async () => {
  for (const method of ['read', 'write']) {
    const f = fixture();
    await f.owner.open();
    const store = new OwnerRecordStore(f.owner, OWNER_NAME);
    const pending = await store.prepare('PUT', 0, new TextEncoder().encode('Private'));
    f.rejectRecord('owner_key_unavailable');
    await assert.rejects(
      method === 'read' ? store.read() : store.commit(pending),
      /owner_key_changed/,
    );
    assert.equal(f.scope.signal.aborted, true);
    assert.throws(() => f.owner.lease());
  }
  const f = fixture();
  await f.owner.open();
  const store = new OwnerRecordStore(f.owner, OWNER_NAME);
  f.rejectRecord('record_changed');
  await assert.rejects(store.read(), /record_changed/);
  assert.equal(f.owner.lease().session.opened, true);
  f.rootRevision(2);
  await assert.rejects(store.read(), /owner_key_changed/);
  assert.equal(f.scope.signal.aborted, true);
});

test('authority recheck cannot preserve a lease under a replacement same-owner session', async () => {
  const f = fixture();
  await f.owner.open();
  const store = new OwnerRecordStore(f.owner, OWNER_NAME);
  f.rejectRecord('record_changed');
  f.replaceSession();
  await assert.rejects(store.read());
  assert.equal(f.scope.signal.aborted, true);
  assert.throws(() => f.owner.lease());
});
