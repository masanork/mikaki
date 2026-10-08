import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  makeSyntheticRecord,
  completedMcpCalls,
  findToolOutputs,
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
  assert.deepEqual(completedMcpCalls(events.map((event) => JSON.stringify(event)).join('\n')), [
    { server: 'mikaki_v2_local', tool: 'mikaki_list' },
    { server: 'mikaki_v2_local', tool: 'mikaki_search' },
    { server: 'mikaki_v2_local', tool: 'mikaki_read' },
    { server: 'other', tool: 'mikaki_read' },
  ]);
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
