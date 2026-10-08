/** Optional Codex CLI smoke using a synthetic v2 Owner record and local stdio only. */
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { toolOutputs } from '../crates/agent-worker/tool-results.ts';
import { encodeOwnerNote, newOwnerNote } from '../crates/worker/ui/vault-note.ts';

export type RecordId = 'name' | 'owner_note';

export function makeSyntheticRecord(recordId: RecordId, now: number) {
  const text =
    recordId === 'name'
      ? 'Synthetic Codex local v2 name; search marker v2-probe-needle.'
      : new TextDecoder().decode(
          encodeOwnerNote(
            newOwnerNote('Synthetic Codex local v2 note', 'Search marker v2-probe-needle.'),
          ),
        );
  // This digest identifies synthetic opaque bytes only; the probe creates no Vault ciphertext.
  const ciphertextSha256 = createHash('sha256')
    .update(`synthetic-vault-ciphertext:${recordId}`)
    .digest('base64url');
  const source = Object.freeze({
    storage_version: 2 as const,
    origin: 'https://mikaki.test',
    owner_id: 'synthetic-owner',
    vault_id: 'synthetic-vault',
    collection_id: 'personal' as const,
    record_id: recordId,
    kind: recordId,
    revision: 2,
    ciphertext_sha256: ciphertextSha256,
  });
  const authority = Object.freeze({ key_generation: 1, owner_key_revision: 1 });
  const document = {
    id: recordId,
    title: recordId === 'name' ? 'Synthetic name' : 'Synthetic OwnerNote',
    source: `vault:${recordId}:2:self-asserted`,
    source_info: {
      kind: 'vault-record' as const,
      source,
      authority,
      provenance: 'self-asserted' as const,
      confirmed_at: now,
    },
    text,
  };
  const bundle = {
    version: 2 as const,
    owner: 'synthetic-owner',
    collection: 'vault-records' as const,
    documents: [document],
  };
  const bundleBytes = JSON.stringify(bundle);
  const grant = {
    version: 2 as const,
    id: randomBytes(32).toString('base64url'),
    owner: 'synthetic-owner',
    delegate: 'codex-v2-probe',
    service: 'Codex CLI synthetic local probe',
    collection: 'vault-records' as const,
    export_sha256: createHash('sha256').update(bundleBytes).digest('hex'),
    document_ids: [recordId],
    sources: [{ source, authority }],
    operations: ['list', 'search', 'read'] as const,
    not_before: now - 1,
    expires_at: now + 600,
    revoked: false,
  };
  return { recordId, source, authority, bundleBytes, grant, text };
}

type JsonRecord = Record<string, unknown>;
function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Parse only completed Codex MCP calls; never include event contents in reports. */
export function completedMcpCalls(jsonl: string): Array<{ server: string; tool: string }> {
  const calls: Array<{ server: string; tool: string }> = [];
  for (const line of jsonl.split(/\r?\n/).filter(Boolean)) {
    let event: unknown;
    try {
      event = JSON.parse(line);
    } catch {
      continue;
    }
    if (!isRecord(event) || event['type'] !== 'item.completed' || !isRecord(event['item']))
      continue;
    const item = event['item'];
    if (item['type'] !== 'mcp_tool_call') continue;
    const server = item['server'];
    const tool = item['tool'] ?? item['tool_name'] ?? item['name'];
    if (typeof server === 'string' && typeof tool === 'string') calls.push({ server, tool });
  }
  return calls;
}

function parseJsonl(jsonl: string): unknown[] {
  const events: unknown[] = [];
  for (const line of jsonl.split(/\r?\n/).filter(Boolean)) {
    try {
      events.push(JSON.parse(line));
    } catch {
      // Ignore non-JSON progress lines; they are never emitted in the report.
    }
  }
  return events;
}

async function runCodex(args: string[], prompt: string): Promise<string> {
  return new Promise((resolvePromise, reject) => {
    // The Codex CLI documents `-` as the prompt-from-stdin sentinel, keeping
    // synthetic prompt text out of process listings.
    const child = spawn(process.env['CODEX_BIN'] ?? 'codex', [...args, '-'], {
      cwd: process.cwd(),
      env: process.env,
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    const stdout: Buffer[] = [];
    let bytes = 0;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
    }, 120_000);
    child.stdout.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > 2 * 1024 * 1024) {
        child.kill('SIGTERM');
        return;
      }
      stdout.push(Buffer.from(chunk));
    });
    child.on('error', () => {
      clearTimeout(timer);
      reject(new Error('codex_unavailable'));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (timedOut) return reject(new Error('codex_timeout'));
      if (bytes > 2 * 1024 * 1024) return reject(new Error('codex_output_limit'));
      if (code !== 0) return reject(new Error('codex_failed'));
      resolvePromise(Buffer.concat(stdout).toString('utf8'));
    });
    child.stdin.end(prompt);
  });
}

function codexArgs(dir: string, serverArgs: string[]) {
  const config = `mcp_servers.mikaki_v2_local={command=${JSON.stringify(process.execPath)},args=${JSON.stringify(serverArgs)},required=true}`;
  return [
    'exec',
    '--ignore-user-config',
    '--ignore-rules',
    '--skip-git-repo-check',
    '--ephemeral',
    '--sandbox',
    'read-only',
    '--json',
    '-C',
    dir,
    '-c',
    config,
  ];
}

export function findToolOutputs(value: unknown, tool: 'list' | 'search' | 'read'): unknown[] {
  const found: unknown[] = [];
  const seen = new Set<string>();
  const add = (result: unknown) => {
    const key = JSON.stringify(result);
    if (!seen.has(key)) {
      seen.add(key);
      found.push(result);
    }
  };
  const visit = (current: unknown, depth: number) => {
    if (depth > 12) return;
    if (typeof current === 'string') {
      if (current.length > 128 * 1024) return;
      try {
        visit(JSON.parse(current), depth + 1);
      } catch {
        return;
      }
      return;
    }
    if (Array.isArray(current)) {
      for (const item of current) visit(item, depth + 1);
      return;
    }
    if (!isRecord(current)) return;
    if (
      isRecord(current['structuredContent']) &&
      toolOutputs[tool].safeParse(current['structuredContent']).success
    )
      add(current['structuredContent']);
    if (toolOutputs[tool].safeParse(current).success) add(current);
    for (const [key, child] of Object.entries(current)) {
      if (key === 'text' && typeof child === 'string') visit(child, depth + 1);
      else if (child && typeof child === 'object') visit(child, depth + 1);
    }
  };
  visit(value, 0);
  return found;
}

async function sdkPreflight(
  serverArgs: string[],
  recordId: RecordId,
  source: unknown,
  authority: unknown,
) {
  const client = new Client({ name: 'codex-v2-probe-preflight', version: '1' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: serverArgs,
    stderr: 'pipe',
  });
  try {
    await client.connect(transport);
    const list = await client.callTool({ name: 'mikaki_list', arguments: {} });
    const search = await client.callTool({
      name: 'mikaki_search',
      arguments: { query: 'v2-probe-needle' },
    });
    const read = await client.callTool({ name: 'mikaki_read', arguments: { id: recordId } });
    const parsed = {
      list: toolOutputs.list.parse(list.structuredContent),
      search: toolOutputs.search.parse(search.structuredContent),
      read: toolOutputs.read.parse(read.structuredContent),
    };
    if (
      list.isError ||
      search.isError ||
      read.isError ||
      parsed.list.documents.length !== 1 ||
      parsed.list.documents[0]?.id !== recordId ||
      parsed.list.documents[0]?.source_info.kind !== 'vault-record' ||
      JSON.stringify(parsed.list.documents[0]?.source_info.source) !== JSON.stringify(source) ||
      JSON.stringify(parsed.list.documents[0]?.source_info.authority) !==
        JSON.stringify(authority) ||
      parsed.search.documents.length !== 1 ||
      parsed.search.documents[0]?.id !== recordId ||
      parsed.search.documents[0]?.source_info.kind !== 'vault-record' ||
      JSON.stringify(parsed.search.documents[0]?.source_info.source) !== JSON.stringify(source) ||
      JSON.stringify(parsed.search.documents[0]?.source_info.authority) !==
        JSON.stringify(authority) ||
      parsed.read.id !== recordId ||
      parsed.read.source_info.kind !== 'vault-record' ||
      JSON.stringify(parsed.read.source_info.source) !== JSON.stringify(source) ||
      JSON.stringify(parsed.read.source_info.authority) !== JSON.stringify(authority)
    )
      throw new Error('stdio_contract_failed');
    const grant = JSON.parse(await readFile(serverArgs[1]!, 'utf8')) as JsonRecord;
    grant['revoked'] = true;
    await writeFile(serverArgs[1]!, JSON.stringify(grant), { mode: 0o600 });
    const denied = await client.callTool({ name: 'mikaki_read', arguments: { id: recordId } });
    if (!denied.isError || denied.structuredContent !== undefined)
      throw new Error('stdio_revoke_failed');
    return { calls: ['list', 'search', 'read'], revokedReadDenied: true };
  } finally {
    await client.close();
    await transport.close();
  }
}

async function auditSummary(path: string) {
  try {
    const lines = (await readFile(path, 'utf8')).trim().split(/\r?\n/).filter(Boolean);
    return lines.map((line) => {
      const item = JSON.parse(line) as JsonRecord;
      return { operation: item['operation'], outcome: item['outcome'] };
    });
  } catch {
    return [];
  }
}

export async function probe(recordId: RecordId) {
  const now = Math.floor(Date.now() / 1000);
  const fixture = makeSyntheticRecord(recordId, now);
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-codex-v2-'));
  const exportPath = join(dir, 'export.json');
  const grantPath = join(dir, 'grant.json');
  const auditPath = join(dir, 'audit.jsonl');
  const codexAuditPath = join(dir, 'codex-audit.jsonl');
  try {
    await writeFile(exportPath, fixture.bundleBytes, { mode: 0o600, flag: 'wx' });
    await writeFile(grantPath, JSON.stringify(fixture.grant), { mode: 0o600, flag: 'wx' });
    const serverArgs = [
      resolve('local/agent-mcp.ts'),
      grantPath,
      exportPath,
      auditPath,
      'codex-v2-probe',
    ];
    const preflight = await sdkPreflight(serverArgs, recordId, fixture.source, fixture.authority);
    await writeFile(grantPath, JSON.stringify(fixture.grant), { mode: 0o600 });
    const codexServerArgs = [...serverArgs.slice(0, 3), codexAuditPath, ...serverArgs.slice(4)];
    const targetPrompt = JSON.stringify({ id: recordId });
    const positiveJsonl = await runCodex(
      codexArgs(dir, codexServerArgs),
      `Use only the MCP server mikaki_v2_local. Call mikaki_list with {}, then mikaki_search with {"query":"v2-probe-needle"}, then mikaki_read with ${targetPrompt}, exactly once each. Do not use any other tools. Do not repeat or quote returned content. Finish with the single word done.`,
    );
    const positiveCalls = completedMcpCalls(positiveJsonl).filter(
      (call) => call.server === 'mikaki_v2_local',
    );
    const completedTools = ['mikaki_list', 'mikaki_search', 'mikaki_read'].filter((tool) =>
      positiveCalls.some((call) => call.tool === tool),
    );
    // Codex versions differ in whether structuredContent is surfaced in JSONL. When exposed,
    // validate it; the SDK preflight above always checks the exact structured source/authority.
    const events = parseJsonl(positiveJsonl);
    const codexStructured = (['list', 'search', 'read'] as const).map((tool) => {
      const outputs = findToolOutputs(events, tool);
      for (const value of outputs) {
        const parsed = toolOutputs[tool].parse(value);
        type ResultDocument = {
          id: string;
          source_info: {
            kind: 'vault-record';
            source: unknown;
            authority: unknown;
          };
        };
        const documents: readonly ResultDocument[] =
          tool === 'read'
            ? [parsed as unknown as ResultDocument]
            : (parsed as unknown as { documents: readonly ResultDocument[] }).documents;
        if (
          documents.length !== 1 ||
          documents[0]?.id !== recordId ||
          documents[0]?.source_info.kind !== 'vault-record' ||
          JSON.stringify(documents[0]?.source_info.source) !== JSON.stringify(fixture.source) ||
          JSON.stringify(documents[0]?.source_info.authority) !== JSON.stringify(fixture.authority)
        )
          throw new Error('codex_structured_source_mismatch');
      }
      return outputs.length > 0;
    });
    const allowedAudit = await auditSummary(codexAuditPath);
    if (
      completedTools.length !== 3 ||
      !['list', 'search', 'read'].every((op) =>
        allowedAudit.some((entry) => entry.operation === op && entry.outcome === 'allowed'),
      )
    )
      throw new Error('codex_positive_calls_incomplete');

    const grant = JSON.parse(await readFile(grantPath, 'utf8')) as JsonRecord;
    grant['revoked'] = true;
    await writeFile(grantPath, JSON.stringify(grant), { mode: 0o600 });
    const revokedJsonl = await runCodex(
      codexArgs(dir, codexServerArgs),
      `Use only the MCP server mikaki_v2_local. Call mikaki_read with ${targetPrompt} exactly once. Do not use any other tools or repeat/quote content. Finish with one word.`,
    );
    const revokeCall = completedMcpCalls(revokedJsonl).some(
      (call) => call.server === 'mikaki_v2_local' && call.tool === 'mikaki_read',
    );
    const allAudit = await auditSummary(codexAuditPath);
    const deniedRead = allAudit.some(
      (entry) => entry.operation === 'read' && entry.outcome === 'denied',
    );
    if (!revokeCall || !deniedRead) throw new Error('codex_revoke_not_observed');
    return {
      passed: true,
      client: 'Codex CLI',
      data: 'synthetic-only',
      record: recordId,
      mcp_server: 'local-stdio',
      completed_tools: completedTools,
      sdk_structured_source_authority_verified: true,
      codex_jsonl_structured_content_exposed: codexStructured,
      revoked_read_denied: true,
      preflight,
      audit_entries: allAudit.length,
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [record, ...extra] = process.argv.slice(2);
  if ((record !== undefined && record !== 'name' && record !== 'owner_note') || extra.length) {
    process.stderr.write('Usage: npm run probe:codex-v2-local-records -- [name|owner_note]\n');
    process.exit(2);
  }
  try {
    const result = await probe((record as RecordId | undefined) ?? 'owner_note');
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    const code = error instanceof Error ? error.message : 'probe_failed';
    process.stderr.write(`${JSON.stringify({ passed: false, error: code })}\n`);
    process.exitCode = 1;
  }
}
