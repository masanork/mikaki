import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  createWorkWebMcpTools,
  type WorkAssistantSnapshot,
  type WorkWebMcpHost,
} from '../../crates/worker/ui/work-webmcp.ts';
import { registerWebMcpTools, type WebMcpTool } from '../../crates/worker/ui/webmcp.ts';
import type { SourceRead } from '../../crates/worker/ui/work-source-view.ts';

function fixture(page: WorkAssistantSnapshot['page'] = 'sources') {
  const state: WorkAssistantSnapshot = {
    page,
    version: 'private-version-1',
    selection: 'private-selection-1',
    busy: false,
    loaded: true,
    items: [{ id: 'context', label: 'Selected source', role: 'personal' }],
    files: [{ source_id: 'context', path: 'writing.md', bytes: 12 }],
    selected: 'code',
    prepared: null,
    copy: page === 'copy' ? { can_start: true, state: 'not_started' } : null,
  };
  let permission: string | null = null,
    verifies = 0;
  const actions: { action: string; args: Record<string, unknown> }[] = [];
  let verification: ((count: number) => void | Promise<void>) | undefined;
  let invocation: (() => void | Promise<void>) | undefined;
  const host: WorkWebMcpHost = {
    page,
    snapshot: () => state,
    visible: () => true,
    verify: async () => {
      await verification?.(++verifies);
    },
    available: () => true,
    invoke: async (action, args, signal) => {
      signal.throwIfAborted();
      actions.push({ action, args });
      await invocation?.();
    },
    contents: () =>
      [
        {
          source: { source_id: 'context' },
          files: [{ path: 'writing.md', bytes: 12, content: '日本語の内容です。' }],
        },
      ] as SourceRead[],
  };
  const tools = createWorkWebMcpTools(host, () => permission);
  const invoke = (name: string, args: unknown = {}, signal = new AbortController().signal) => {
    const tool = tools.find((tool) => tool.name === name);
    assert(tool, name);
    return tool.execute(args, { signal });
  };
  return {
    state,
    host,
    tools,
    actions,
    invoke,
    permit: () => {
      permission = state.selection;
    },
    revoke: () => {
      permission = null;
    },
    verification: (fn: typeof verification) => {
      verification = fn;
    },
    invocation: (fn: typeof invocation) => {
      invocation = fn;
    },
  };
}
test('Work tools call the shared screen actions and return public projections without authority tokens', async () => {
  const f = fixture();
  const result = await f.invoke('mikaki_get_work_state');
  assert(!JSON.stringify(result).includes('private-'));
  await f.invoke('mikaki_select_work_files', { source_id: 'context', paths: ['writing.md'] });
  await f.invoke('mikaki_select_work_code', { source_id: 'code' });
  await f.invoke('mikaki_inspect_work_selection');
  await f.invoke('mikaki_prepare_work_copy');
  assert.deepEqual(
    f.actions.map((a) => a.action),
    ['select_files', 'select_code', 'inspect', 'prepare'],
  );
  assert(!JSON.stringify(await f.invoke('mikaki_get_work_state')).includes('日本語'));
});
test('contents require exact selection permission, a fresh source inspection, and bounded Unicode output', async () => {
  const f = fixture();
  await assert.rejects(f.invoke('mikaki_read_work_file', { file_index: 0 }), {
    code: 'content_not_permitted',
  });
  assert.equal(f.actions.length, 0);
  f.permit();
  assert.deepEqual(await f.invoke('mikaki_read_work_file', { file_index: 0, max_characters: 3 }), {
    source_id: 'context',
    path: 'writing.md',
    bytes: 12,
    content: '日本語',
    truncated: true,
  });
  assert.deepEqual(
    f.actions.map((a) => a.action),
    ['inspect'],
  );
  f.state.selection = 'new-selection';
  await assert.rejects(f.invoke('mikaki_read_work_file', { file_index: 0 }), {
    code: 'content_not_permitted',
  });
  f.permit();
  await assert.rejects(f.invoke('mikaki_read_work_file', { file_index: 1 }), {
    code: 'not_selected',
  });
});
test('revocation during inspection or final authority verification returns no plaintext', async () => {
  for (const phase of ['inspect', 'verify'] as const) {
    const f = fixture();
    f.permit();
    if (phase === 'inspect') f.invocation(() => f.revoke());
    else
      f.verification((count) => {
        if (count === 2) f.revoke();
      });
    await assert.rejects(f.invoke('mikaki_read_work_file', { file_index: 0 }), {
      code: 'selection_changed',
    });
  }
});
test('selection changes during either verification refuse stale actions and results', async () => {
  for (const phase of [1, 2]) {
    const f = fixture();
    f.verification((count) => {
      if (count === phase) f.state.version = 'different';
    });
    await assert.rejects(f.invoke('mikaki_prepare_work_copy'), { code: 'selection_changed' });
    assert.equal(f.actions.length, phase === 1 ? 0 : 1);
  }
});
test('caller cancellation consumes no additional operation and rejects late contents', async () => {
  const f = fixture(),
    caller = new AbortController();
  f.permit();
  f.invocation(() => caller.abort());
  await assert.rejects(f.invoke('mikaki_read_work_file', { file_index: 0 }, caller.signal), {
    name: 'AbortError',
  });
  assert.equal(f.actions.length, 1);
  const g = fixture();
  await assert.rejects(g.invoke('mikaki_prepare_work_copy', {}, caller.signal), {
    name: 'AbortError',
  });
  assert.equal(g.actions.length, 0);
});
test('closed schemas, busy views and unavailable actions refuse without dispatch', async () => {
  const f = fixture();
  for (const [name, args] of [
    ['mikaki_get_work_state', { bearer: 'token' }],
    ['mikaki_prepare_work_copy', { approved: true }],
    ['mikaki_select_work_files', { source_id: 'context', paths: ['x', 'x'] }],
    ['mikaki_select_work_code', { source_id: '../other-owner' }],
    ['mikaki_read_work_file', { file_index: -1 }],
    ['mikaki_read_work_file', { file_index: 0, max_characters: 4001 }],
    ['mikaki_refresh_work', { more: 'true' }],
  ] as const)
    await assert.rejects(f.invoke(name, args), { code: 'invalid_input' });
  f.state.busy = true;
  await assert.rejects(f.invoke('mikaki_prepare_work_copy'), { code: 'busy' });
  f.state.busy = false;
  f.host.visible = () => false;
  await assert.rejects(f.invoke('mikaki_prepare_work_copy'), { code: 'unavailable' });
  f.host.visible = () => true;
  f.host.available = () => false;
  await assert.rejects(f.invoke('mikaki_prepare_work_copy'), { code: 'unavailable' });
  assert.equal(f.actions.length, 0);
});
test('copy review tools only request the existing human review; no tool approves, starts or stops a copy', async () => {
  const f = fixture('copy');
  assert(!f.tools.some((tool) => /prepare|select|read_work_file|inspect/.test(tool.name)));
  for (const action of ['start_copy', 'stop_copy']) {
    assert.deepEqual(await f.invoke('mikaki_review_work_action', { action }), {
      status: 'review_required',
      action,
    });
  }
  assert(f.actions.every((a) => a.action === 'review'));
  await assert.rejects(f.invoke('mikaki_review_work_action', { action: 'bootstrap' }), {
    code: 'invalid_input',
  });
  await assert.rejects(
    f.invoke('mikaki_review_work_action', { action: 'start_copy', approved: true }),
    { code: 'invalid_input' },
  );
});
test('native registration rejects concurrent calls and sanitizes failed authority checks', async () => {
  const f = fixture();
  let release!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  f.verification(async () => {
    await pending;
    throw new Error('private owner details');
  });
  const registered: WebMcpTool[] = [],
    lifetime = new AbortController();
  await registerWebMcpTools(
    {
      registerTool: (tool) => {
        registered.push(tool);
      },
    },
    f.tools,
    lifetime.signal,
  );
  const first = registered[0]!.execute({}, { signal: lifetime.signal });
  assert.deepEqual(await registered[1]!.execute({}, { signal: lifetime.signal }), {
    ok: false,
    error: 'busy',
  });
  release();
  assert.deepEqual(await first, { ok: false, error: 'unavailable' });
});
