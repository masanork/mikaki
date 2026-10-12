import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createVaultWebMcpTools,
  type VaultWebMcpHost,
  type WebMcpSelection,
} from '../../crates/worker/ui/vault-webmcp.ts';
import {
  registerWebMcpTools,
  WebMcpFailure,
  type WebMcpTool,
} from '../../crates/worker/ui/webmcp.ts';
import { encodeOwnerNote, newOwnerNote } from '../../crates/worker/ui/vault-note.ts';

function fixture() {
  let selection: WebMcpSelection = {
    name: 1,
    note: 2,
    threads: [{ id: 'approved', revision: 3, title: 'Approved' }],
  };
  let epoch = 1,
    dirty = false,
    visible = true,
    locked = false,
    verifyCalls = 0;
  const reads: string[] = [],
    drafts: unknown[] = [];
  const buffers: Uint8Array<ArrayBuffer>[] = [];
  const archive = (title: string) => ({
    format_version: 1,
    title,
    messages: [
      {
        speaker: 'Alice',
        actor: 'human',
        text: 'Find this sentence',
        timestamp: '2026-10-12T00:00:00.000Z',
      },
    ],
  });
  const data = new Map([
    ['personal/name', { revision: 1, bytes: new TextEncoder().encode('Saved name') }],
    [
      'personal/owner_note',
      { revision: 2, bytes: encodeOwnerNote(newOwnerNote('Saved note', 'Private text')) },
    ],
    [
      'threads/approved',
      { revision: 3, bytes: new TextEncoder().encode(JSON.stringify(archive('Approved'))) },
    ],
    [
      'threads/forbidden',
      {
        revision: 1,
        bytes: new TextEncoder().encode(JSON.stringify(archive('Secret unselected conversation'))),
      },
    ],
  ]);
  let verifyGate: (() => Promise<void>) | undefined;
  const owner = {
    checkpoint: () => {
      if (locked) throw new Error('private details');
      return epoch;
    },
    assertCurrent: (token: number) => {
      if (locked || token !== epoch) throw new Error('private details');
    },
    verifyAuthority: async () => {
      verifyCalls++;
      await verifyGate?.();
      if (locked) throw new Error('private details');
    },
  };
  const host: VaultWebMcpHost = {
    owner: () => (locked ? null : (owner as ReturnType<VaultWebMcpHost['owner']>)),
    store: () =>
      ({
        read: async (collection: string, id: string) => {
          reads.push(`${collection}/${id}`);
          const record = data.get(`${collection}/${id}`)!;
          const plaintext = record.bytes.slice();
          buffers.push(plaintext);
          return { revision: record.revision, plaintext };
        },
      }) as unknown as ReturnType<VaultWebMcpHost['store']>,
    selection: () => selection,
    blocked: () => false,
    hasDrafts: () => dirty,
    visible: () => visible,
    search: async (records, query, signal) => {
      signal.throwIfAborted();
      assert.deepEqual(
        records.map((record) => record.id),
        ['approved'],
      );
      assert.equal(query, 'sentence');
      return {
        hits: [{ thread: 'approved', revision: 3, message: 0, text: 'Find this sentence' }],
        truncated: false,
      };
    },
    openThread: async (id, revision) => {
      drafts.push({ id, revision });
    },
    prepareName: async (name, revision) => {
      dirty = true;
      drafts.push({ name, revision });
      return { revision, status: 'review_required' };
    },
    prepareNote: async (title, text, revision) => {
      dirty = true;
      drafts.push({ title, text, revision });
      return { revision, status: 'review_required' };
    },
    review: async (action) => {
      drafts.push({ action });
    },
  };
  const tools = createVaultWebMcpTools(host);
  const invoke = (name: string, args: unknown = {}) =>
    tools
      .find((tool) => tool.name === name)!
      .execute(args, { signal: new AbortController().signal });
  return {
    invoke,
    tools,
    reads,
    drafts,
    buffers,
    data,
    verifyCount: () => verifyCalls,
    setDirty: (value: boolean) => {
      dirty = value;
    },
    setHidden: () => {
      visible = false;
    },
    lock: () => {
      locked = true;
      epoch++;
    },
    setSelection: (value: WebMcpSelection) => {
      selection = value;
    },
    gate: (value: () => Promise<void>) => {
      verifyGate = value;
    },
  };
}
test('WebMCP reads and searches only selected exact revisions, clears temporary plaintext, and stages drafts', async () => {
  const f = fixture();
  assert.deepEqual(
    ((await f.invoke('mikaki_search_selected', { query: 'sentence' })) as { hits: unknown[] }).hits
      .length,
    1,
  );
  assert.deepEqual(f.reads, ['threads/approved']);
  assert.deepEqual(
    await f.invoke('mikaki_read_selected', { target: 'owner_note', max_characters: 7 }),
    { target: 'owner_note', revision: 2, title: 'Saved note', text: 'Private', truncated: true },
  );
  await assert.rejects(
    f.invoke('mikaki_read_selected', { target: 'thread', thread_id: 'forbidden' }),
    { code: 'not_selected' },
  );
  assert(!f.reads.includes('threads/forbidden'));
  assert(f.buffers.every((bytes) => bytes.every((byte) => byte === 0)));
  assert.deepEqual(await f.invoke('mikaki_prepare_name_edit', { name: 'Draft name' }), {
    revision: 1,
    status: 'review_required',
  });
  await assert.rejects(f.invoke('mikaki_prepare_note_edit', { title: 'Draft', text: 'Body' }), {
    code: 'unsaved_changes',
  });
  f.setDirty(false);
  await f.invoke('mikaki_prepare_note_edit', { title: 'Draft', text: 'Body' });
  assert.equal(f.drafts.length, 2);
  assert(f.verifyCount() >= 6);
  assert.equal(
    new TextDecoder().decode(f.data.get('personal/name')!.bytes),
    'Saved name',
    'drafts do not save',
  );
});
test('WebMCP rejects bad input, stale records, hidden/locked pages, and permissions changed during verification', async () => {
  const f = fixture();
  for (const [name, args] of [
    ['mikaki_search_selected', { query: 'a'.repeat(257) }],
    ['mikaki_get_vault_state', { secret: true }],
    ['mikaki_read_selected', { target: 'name', thread_id: 'approved' }],
    ['mikaki_prepare_note_edit', { title: 'x', text: '\ud800' }],
    ['mikaki_review_vault_action', { action: 'execute_sql' }],
  ] as const)
    await assert.rejects(f.invoke(name, args), { code: 'invalid_input' });
  f.data.get('threads/approved')!.revision = 4;
  await assert.rejects(f.invoke('mikaki_search_selected', { query: 'sentence' }), {
    code: 'record_changed',
  });
  assert(f.buffers.every((bytes) => bytes.every((byte) => byte === 0)));
  const g = fixture();
  g.gate(async () => {
    g.setSelection({ name: null, note: null, threads: [] });
  });
  await assert.rejects(g.invoke('mikaki_read_selected', { target: 'name' }), {
    code: 'selection_changed',
  });
  assert.equal(g.reads.length, 0);
  const h = fixture();
  h.setHidden();
  await assert.rejects(h.invoke('mikaki_read_selected', { target: 'name' }), {
    code: 'unavailable',
  });
  const l = fixture();
  l.lock();
  await assert.rejects(l.invoke('mikaki_read_selected', { target: 'name' }), { code: 'locked' });
});
test('registration combines caller/lifetime cancellation, excludes concurrent calls, and sanitizes failures', async () => {
  const registered: WebMcpTool[] = [];
  const lifetime = new AbortController();
  let release!: () => void;
  let calls = 0;
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  await registerWebMcpTools(
    {
      registerTool: (tool, options) => {
        assert.equal(options.signal, lifetime.signal);
        registered.push(tool);
      },
    },
    [
      {
        name: 'test',
        description: 'test',
        inputSchema: {},
        execute: async (_args, { signal }) => {
          calls++;
          await blocked;
          signal.throwIfAborted();
          throw new Error('private signing key');
        },
      },
    ],
    lifetime.signal,
  );
  const caller = new AbortController();
  const pending = registered[0]!.execute({}, { signal: caller.signal });
  assert.deepEqual(await registered[0]!.execute({}, { signal: caller.signal }), {
    ok: false,
    error: 'busy',
  });
  caller.abort();
  release();
  assert.deepEqual(await pending, { ok: false, error: 'cancelled' });
  assert.equal(calls, 1);
  assert.deepEqual(await registered[0]!.execute({}, { signal: new AbortController().signal }), {
    ok: false,
    error: 'unavailable',
  });
  lifetime.abort();
  assert.deepEqual(await registered[0]!.execute({}, { signal: new AbortController().signal }), {
    ok: false,
    error: 'cancelled',
  });
  assert.equal(calls, 2, 'unregistered callbacks cannot start work');
  assert.equal(new WebMcpFailure('not_selected').message, 'not_selected');
});
