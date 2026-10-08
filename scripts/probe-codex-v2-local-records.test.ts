import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  makeSyntheticRecord,
  completedMcpCalls,
  classifyCodexDiagnostic,
  codexJsonlDiagnostic,
  summarizeCodexJsonl,
  exactAuditDelta,
  findToolOutputs,
  verifyStructuredOutput,
} from './probe-codex-v2-local-records.ts';
import { toolOutputs } from '../crates/agent-worker/tool-results.ts';

test('Codex probe fixture binds one v2 OwnerNote to source and authority', () => {
  const fixture = makeSyntheticRecord('owner_note', 1_800_000_000);
  const bundle = JSON.parse(fixture.bundleBytes) as Record<string, unknown>;
  assert.equal(bundle['version'], 2);
  assert.equal(bundle['collection'], 'vault-records');
  const documents = bundle['documents'] as Record<string, unknown>[];
  assert.equal(documents.length, 1);
  const document = documents[0]!;
  assert.equal(document['id'], 'owner_note');
  const sourceInfo = document['source_info'] as Record<string, unknown>;
  assert.equal(sourceInfo['kind'], 'vault-record');
  assert.deepEqual(sourceInfo['source'], fixture.source);
  assert.deepEqual(sourceInfo['authority'], fixture.authority);
  assert.match(String(document['text']), /v2-probe-needle/);
  const grant = toolOutputs.read.parse({
    result_version: 1,
    untrusted_content: true,
    ...document,
    access: {
      mode: 'local-export',
      source_check: 'not-checked',
      checked_at: 1_800_000_000,
      grant_expires_at: 1_800_000_600,
    },
  });
  if (grant.source_info.kind !== 'vault-record') throw new Error('Expected a v2 record source');
  assert.deepEqual(grant.source_info.source, fixture.source);
  assert.deepEqual(grant.source_info.authority, fixture.authority);
  assert.deepEqual(fixture.grant.document_ids, ['owner_note']);
  assert.deepEqual(fixture.grant.operations, ['list', 'search', 'read']);
});

test('Codex probe counts only completed MCP tool events for its named server', () => {
  const events = [
    {
      type: 'item.started',
      item: { type: 'mcp_tool_call', server: 'mikaki_v2_local', tool: 'mikaki_read' },
    },
    {
      type: 'item.completed',
      item: { type: 'mcp_tool_call', server: 'mikaki_v2_local', tool: 'mikaki_list' },
    },
    {
      type: 'item.completed',
      item: { type: 'mcp_tool_call', server: 'mikaki_v2_local', tool: 'mikaki_search' },
    },
    {
      type: 'item.completed',
      item: { type: 'mcp_tool_call', server: 'mikaki_v2_local', tool: 'mikaki_read' },
    },
    {
      type: 'item.completed',
      item: { type: 'mcp_tool_call', server: 'other', tool: 'mikaki_read' },
    },
    { type: 'item.completed', item: { type: 'agent_message', text: 'done' } },
  ];
  assert.deepEqual(
    completedMcpCalls(events.map((event) => JSON.stringify(event)).join('\n')).map(
      ({ server, tool, failed }) => ({ server, tool, failed }),
    ),
    [
      { server: 'mikaki_v2_local', tool: 'mikaki_list', failed: false },
      { server: 'mikaki_v2_local', tool: 'mikaki_search', failed: false },
      { server: 'mikaki_v2_local', tool: 'mikaki_read', failed: false },
      { server: 'other', tool: 'mikaki_read', failed: false },
    ],
  );
});

test('Codex MCP tool completion rejects item, status, and result errors', () => {
  const events = [
    {
      type: 'item.completed',
      item: {
        type: 'mcp_tool_call',
        server: 'mikaki_v2_local',
        tool: 'mikaki_list',
        status: 'failed',
      },
    },
    {
      type: 'item.completed',
      item: {
        type: 'mcp_tool_call',
        server: 'mikaki_v2_local',
        tool: 'mikaki_search',
        error: { message: 'failed' },
      },
    },
    {
      type: 'item.completed',
      item: {
        type: 'mcp_tool_call',
        server: 'mikaki_v2_local',
        tool: 'mikaki_read',
        result: { isError: true },
      },
    },
  ];
  assert.deepEqual(
    completedMcpCalls(events.map((event) => JSON.stringify(event)).join('\n')).map(
      (call) => call.failed,
    ),
    [true, true, true],
  );
});

test('Codex stderr classification exposes only a known diagnostic category', () => {
  assert.equal(classifyCodexDiagnostic('HTTP 429: rate limit exceeded'), 'rate_limit');
  assert.equal(classifyCodexDiagnostic('401 Unauthorized: login required'), 'authentication');
  assert.equal(classifyCodexDiagnostic('The requested model is unavailable'), 'model_unavailable');
  assert.equal(classifyCodexDiagnostic('fetch failed: ECONNRESET'), 'network');
  assert.equal(classifyCodexDiagnostic('error: unknown option --bad'), 'cli_arguments');
  assert.equal(classifyCodexDiagnostic('Failed to initialize MCP server'), 'mcp_startup');
  assert.equal(classifyCodexDiagnostic('MCP server configuration is invalid'), 'configuration');
  assert.equal(classifyCodexDiagnostic('ENOENT: no such file or directory'), 'filesystem');
  assert.equal(classifyCodexDiagnostic('sensitive arbitrary text'), 'unclassified');
});

test('Codex event summary reports only fixed event counts and whether a turn started', () => {
  const jsonl = [
    { type: 'thread.started', thread_id: 'private-id' },
    { type: 'turn.started', turn_id: 'private-id' },
    { type: 'item.started', item: { type: 'mcp_tool_call', tool: 'private-tool' } },
    { type: 'item.completed', item: { type: 'agent_message', text: 'private output' } },
    { type: 'error', message: 'private error' },
    { type: 'unknown.private-event', payload: 'private' },
  ]
    .map((event) => JSON.stringify(event))
    .join('\n');
  const summary = summarizeCodexJsonl(jsonl);
  assert.deepEqual(summary, {
    started: true,
    thread_started: 1,
    turn_started: 1,
    item_started: 1,
    item_completed: 1,
    error: 1,
    turn_failed: 0,
    other: 1,
  });
  assert.equal(JSON.stringify(summary).includes('private'), false);
  assert.deepEqual(summarizeCodexJsonl('not-json'), {
    started: false,
    thread_started: 0,
    turn_started: 0,
    item_started: 0,
    item_completed: 0,
    error: 0,
    turn_failed: 0,
    other: 0,
  });
});

test('Codex JSONL backend errors expose only safe event kind, category, and numeric HTTP status', () => {
  const event = {
    type: 'error',
    message: 'Sensitive response body: HTTP 503 model unavailable',
    code: 'secret-internal-code',
    status: 503,
  };
  const diagnostic = codexJsonlDiagnostic(JSON.stringify(event));
  assert.deepEqual(diagnostic, {
    eventKind: 'error',
    category: 'model_unavailable',
    httpStatus: 503,
  });
  assert.equal(JSON.stringify(diagnostic).includes('Sensitive'), false);
  assert.equal(JSON.stringify(diagnostic).includes('secret-internal-code'), false);
  assert.equal(
    codexJsonlDiagnostic(
      JSON.stringify({
        type: 'item.completed',
        item: { type: 'mcp_tool_call', error: { message: 'denied', status: 403 } },
      }),
      false,
    ),
    null,
    'Expected tool-call errors are inspected by the invocation contract instead',
  );
});

test('Codex audit delta must match exact allowed and denied calls', () => {
  const positive = [
    { operation: 'list', outcome: 'allowed' },
    { operation: 'search', outcome: 'allowed' },
    { operation: 'read', outcome: 'allowed' },
  ];
  assert.equal(exactAuditDelta([], positive, positive), true);
  assert.equal(exactAuditDelta([], [...positive, positive[2]!], positive), false);
  assert.equal(
    exactAuditDelta(
      positive,
      [...positive, { operation: 'read', outcome: 'denied' }],
      [{ operation: 'read', outcome: 'denied' }],
    ),
    true,
  );
  assert.equal(
    exactAuditDelta(
      positive,
      [...positive, { operation: 'read', outcome: 'allowed' }],
      [{ operation: 'read', outcome: 'denied' }],
    ),
    false,
  );
});

test('Codex JSONL structured result parsing validates v2 read metadata when exposed', () => {
  const fixture = makeSyntheticRecord('name', 1_800_000_000);
  const output = {
    result_version: 1,
    untrusted_content: true,
    ...JSON.parse(fixture.bundleBytes).documents[0],
    access: {
      mode: 'local-export',
      source_check: 'not-checked',
      checked_at: 1_800_000_000,
      grant_expires_at: 1_800_000_600,
    },
  };
  const events = [
    {
      type: 'item.completed',
      item: {
        type: 'mcp_tool_call',
        server: 'mikaki_v2_local',
        tool: 'mikaki_read',
        result: { structuredContent: output },
      },
    },
  ];
  const results = findToolOutputs(events, 'read');
  assert.equal(results.length, 1);
  const parsed = toolOutputs.read.parse(results[0]);
  if (parsed.source_info.kind !== 'vault-record') throw new Error('Expected a v2 record source');
  assert.deepEqual(parsed.source_info.source, fixture.source);
  assert.deepEqual(parsed.source_info.authority, fixture.authority);
});

test('Codex structuredContent is retained even when malformed so validation can fail closed', () => {
  const fixture = makeSyntheticRecord('name', 1_800_000_000);
  const events = [
    {
      type: 'item.completed',
      item: {
        type: 'mcp_tool_call',
        server: 'mikaki_v2_local',
        tool: 'mikaki_read',
        result: { structuredContent: { result_version: 99 } },
      },
    },
  ];
  const jsonl = events.map((event) => JSON.stringify(event)).join('\n');
  const calls = completedMcpCalls(jsonl);
  assert.deepEqual(findToolOutputs(calls[0]!.event, 'read'), [{ result_version: 99 }]);
  assert.throws(() =>
    verifyStructuredOutput(calls, 'read', 'name', fixture.source, fixture.authority),
  );
  assert.equal(
    verifyStructuredOutput(
      completedMcpCalls(
        JSON.stringify({
          type: 'item.completed',
          item: { type: 'mcp_tool_call', server: 'mikaki_v2_local', tool: 'mikaki_read' },
        }),
      ),
      'read',
      'name',
      fixture.source,
      fixture.authority,
    ),
    'not_exposed',
  );
});
