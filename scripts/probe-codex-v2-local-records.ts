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

export type CompletedMcpCall = Readonly<{
  server: string;
  tool: string;
  failed: boolean;
  event: JsonRecord;
}>;

export type CodexDiagnosticCategory =
  | 'rate_limit'
  | 'authentication'
  | 'model_unavailable'
  | 'network'
  | 'cli_arguments'
  | 'mcp_startup'
  | 'configuration'
  | 'filesystem'
  | 'unclassified';
export type CodexErrorEventKind = 'error' | 'turn_failed' | 'item_error' | 'other_error';

export type CodexJsonlDiagnostic = Readonly<{
  eventKind: CodexErrorEventKind;
  category: CodexDiagnosticCategory;
  httpStatus?: number;
}>;

export type CodexEventSummary = Readonly<{
  started: boolean;
  thread_started: number;
  turn_started: number;
  item_started: number;
  item_completed: number;
  error: number;
  turn_failed: number;
  other: number;
}>;

const repoRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));

export function classifyCodexDiagnostic(stderr: string): CodexDiagnosticCategory {
  if (/rate[\s_-]?limit|too many requests|\b429\b|quota exceeded/i.test(stderr))
    return 'rate_limit';
  if (
    /unauthori[sz]ed|authentication|not logged in|login required|invalid api key|\b401\b/i.test(
      stderr,
    )
  )
    return 'authentication';
  if (/model.{0,80}(?:not found|unavailable|not available|unsupported)|unknown model/i.test(stderr))
    return 'model_unavailable';
  if (
    /ECONN[A-Z]+|ENOTFOUND|ETIMEDOUT|fetch failed|network error|socket hang up|connection refused|TLS handshake/i.test(
      stderr,
    )
  )
    return 'network';
  if (
    /unknown (?:option|argument)|unrecognized option|invalid (?:option|argument)|usage:|unexpected argument/i.test(
      stderr,
    )
  )
    return 'cli_arguments';
  if (
    /mcp.{0,60}(?:start|spawn|initiali[sz]e|handshake|connect)|(?:start|spawn|initiali[sz]e).{0,60}mcp/i.test(
      stderr,
    )
  )
    return 'mcp_startup';
  if (
    /invalid (?:toml|configuration|config)|configuration error|(?:config|configuration).{0,80}(?:invalid|error)|mcp_servers.{0,40}(?:invalid|unknown|missing)/i.test(
      stderr,
    )
  )
    return 'configuration';
  if (/ENOENT|EACCES|permission denied|no such file or directory|cannot open/i.test(stderr))
    return 'filesystem';
  return 'unclassified';
}

export function summarizeCodexJsonl(jsonl: string): CodexEventSummary {
  const counts = {
    thread_started: 0,
    turn_started: 0,
    item_started: 0,
    item_completed: 0,
    error: 0,
    turn_failed: 0,
    other: 0,
  };
  for (const line of jsonl.split(/\r?\n/).filter(Boolean)) {
    try {
      const event: unknown = JSON.parse(line);
      if (!isRecord(event) || typeof event['type'] !== 'string') continue;
      switch (event['type']) {
        case 'thread.started':
          counts.thread_started++;
          break;
        case 'turn.started':
          counts.turn_started++;
          break;
        case 'item.started':
          counts.item_started++;
          break;
        case 'item.completed':
          counts.item_completed++;
          break;
        case 'error':
          counts.error++;
          break;
        case 'turn.failed':
          counts.turn_failed++;
          break;
        default:
          counts.other++;
      }
    } catch {
      // Non-JSON progress text is ignored and never reported.
    }
  }
  return { started: counts.thread_started + counts.turn_started > 0, ...counts };
}

export function codexJsonlDiagnostic(
  jsonl: string,
  includeToolErrors = true,
): CodexJsonlDiagnostic | null {
  for (const line of jsonl.split(/\r?\n/).filter(Boolean)) {
    let event: unknown;
    try {
      event = JSON.parse(line);
    } catch {
      continue;
    }
    if (!isRecord(event)) continue;
    const type = event['type'];
    const item = isRecord(event['item']) ? event['item'] : undefined;
    const topError = event['error'];
    const itemError = item?.['error'];
    const hasError =
      type === 'error' ||
      type === 'turn.failed' ||
      item?.['type'] === 'error' ||
      (includeToolErrors && item?.['type'] === 'mcp_tool_call' && itemError != null) ||
      (topError !== undefined && topError !== null) ||
      (includeToolErrors && itemError !== undefined && itemError !== null);
    if (!hasError) continue;

    const error = isRecord(itemError) ? itemError : isRecord(topError) ? topError : undefined;
    const messages = [
      event['message'],
      typeof topError === 'string' ? topError : undefined,
      error?.['message'],
      typeof itemError === 'string' ? itemError : undefined,
    ].filter((value): value is string => typeof value === 'string');
    const codes = [
      event['code'],
      event['status'],
      event['status_code'],
      error?.['code'],
      error?.['status'],
    ];
    const httpStatus = codes.find(
      (value): value is number =>
        typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599,
    );
    return {
      eventKind:
        type === 'error'
          ? 'error'
          : type === 'turn.failed'
            ? 'turn_failed'
            : item?.['type'] === 'error' || (includeToolErrors && itemError != null)
              ? 'item_error'
              : 'other_error',
      category: classifyCodexDiagnostic(
        [...messages, ...(httpStatus ? [String(httpStatus)] : [])].join('\n'),
      ),
      ...(httpStatus !== undefined ? { httpStatus } : {}),
    };
  }
  return null;
}

class CodexCliError extends Error {
  readonly code:
    | 'codex_unavailable'
    | 'codex_timeout'
    | 'codex_output_limit'
    | 'codex_failed'
    | 'codex_backend_error';
  readonly exitCode: number | null | undefined;
  readonly diagnosticCategory: CodexDiagnosticCategory | undefined;
  readonly errorEventKind: CodexErrorEventKind | undefined;
  readonly httpStatus: number | undefined;
  readonly stdoutEvents: CodexEventSummary | undefined;

  constructor(
    code:
      | 'codex_unavailable'
      | 'codex_timeout'
      | 'codex_output_limit'
      | 'codex_failed'
      | 'codex_backend_error',
    exitCode?: number | null,
    diagnosticCategory?: CodexDiagnosticCategory,
    errorEventKind?: CodexErrorEventKind,
    httpStatus?: number,
    stdoutEvents?: CodexEventSummary,
  ) {
    super(code);
    this.code = code;
    this.exitCode = exitCode;
    this.diagnosticCategory = diagnosticCategory;
    this.errorEventKind = errorEventKind;
    this.httpStatus = httpStatus;
    this.stdoutEvents = stdoutEvents;
  }
}

/** Parse completed Codex MCP calls and retain result envelopes only for local validation. */
export function completedMcpCalls(jsonl: string): CompletedMcpCall[] {
  const calls: CompletedMcpCall[] = [];
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
    if (typeof server !== 'string' || typeof tool !== 'string') continue;
    const result = item['result'];
    const status = typeof item['status'] === 'string' ? item['status'].toLowerCase() : undefined;
    calls.push({
      server,
      tool,
      event: item,
      failed:
        (item['error'] !== undefined && item['error'] !== null) ||
        (status !== undefined && !['completed', 'success', 'succeeded'].includes(status)) ||
        (isRecord(result) && result['isError'] === true),
    });
  }
  return calls;
}

async function runCodex(
  args: string[],
  prompt: string,
): Promise<{ jsonl: string; stdoutEvents: CodexEventSummary }> {
  return new Promise((resolvePromise, reject) => {
    // The Codex CLI documents `-` as the prompt-from-stdin sentinel, keeping
    // synthetic prompt text out of process listings.
    const child = spawn(process.env['CODEX_BIN'] ?? 'codex', [...args, '-'], {
      cwd: repoRoot,
      env: process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let bytes = 0;
    let capturedStderrBytes = 0;
    let failure: Error | undefined;
    let killTimer: NodeJS.Timeout | undefined;
    const clearStderr = () => {
      for (const chunk of stderr) chunk.fill(0);
      stderr.length = 0;
      capturedStderrBytes = 0;
    };
    const stop = (reason: string) => {
      if (failure) return;
      failure = new CodexCliError(reason as CodexCliError['code']);
      child.kill('SIGTERM');
      killTimer = setTimeout(() => child.kill('SIGKILL'), 1_000);
    };
    const timer = setTimeout(() => stop('codex_timeout'), 120_000);
    child.stdout.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > 2 * 1024 * 1024) {
        stop('codex_output_limit');
        return;
      }
      stdout.push(Buffer.from(chunk));
    });
    child.stderr.on('data', (chunk: Buffer) => {
      const remaining = 16 * 1024 - capturedStderrBytes;
      if (remaining > 0) {
        const captured = Buffer.from(chunk.subarray(0, remaining));
        stderr.push(captured);
        capturedStderrBytes += captured.length;
      }
    });
    child.on('error', () => {
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      clearStderr();
      reject(new CodexCliError('codex_unavailable'));
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (killTimer) clearTimeout(killTimer);
      if (failure) {
        clearStderr();
        return reject(failure);
      }
      const output = Buffer.concat(stdout);
      const jsonl = output.toString('utf8');
      const stdoutEvents = summarizeCodexJsonl(jsonl);
      const jsonlDiagnostic = codexJsonlDiagnostic(jsonl, code !== 0);
      if (jsonlDiagnostic) {
        output.fill(0);
        clearStderr();
        return reject(
          new CodexCliError(
            'codex_backend_error',
            code,
            jsonlDiagnostic.category,
            jsonlDiagnostic.eventKind,
            jsonlDiagnostic.httpStatus,
            stdoutEvents,
          ),
        );
      }
      output.fill(0);
      if (code !== 0) {
        const diagnostic = Buffer.concat(stderr);
        const diagnosticCategory = classifyCodexDiagnostic(diagnostic.toString('utf8'));
        diagnostic.fill(0);
        clearStderr();
        return reject(
          new CodexCliError(
            'codex_failed',
            code,
            diagnosticCategory,
            undefined,
            undefined,
            stdoutEvents,
          ),
        );
      }
      clearStderr();
      resolvePromise({ jsonl, stdoutEvents });
    });
    child.stdin.on('error', () => {});
    child.stdin.end(prompt);
  });
}

async function withTimeout<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label}_timeout`)), 10_000);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function codexArgs(dir: string, serverArgs: string[]) {
  const config = `mcp_servers={mikaki_v2_local={command=${JSON.stringify(process.execPath)},args=${JSON.stringify(serverArgs)},required=true}}`;
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
    if (Object.hasOwn(current, 'structuredContent')) add(current['structuredContent']);
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
    cwd: repoRoot,
    stderr: 'pipe',
  });
  try {
    await withTimeout(client.connect(transport), 'sdk_connect');
    const list = await withTimeout(
      client.callTool({ name: 'mikaki_list', arguments: {} }),
      'sdk_list',
    );
    const search = await withTimeout(
      client.callTool({
        name: 'mikaki_search',
        arguments: { query: 'v2-probe-needle' },
      }),
      'sdk_search',
    );
    const read = await withTimeout(
      client.callTool({ name: 'mikaki_read', arguments: { id: recordId } }),
      'sdk_read',
    );
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
    const denied = await withTimeout(
      client.callTool({ name: 'mikaki_read', arguments: { id: recordId } }),
      'sdk_revoked_read',
    );
    if (!denied.isError || denied.structuredContent !== undefined)
      throw new Error('stdio_revoke_failed');
    return { calls: ['list', 'search', 'read'], revokedReadDenied: true };
  } finally {
    await Promise.allSettled([
      Promise.resolve().then(() => client.close()),
      Promise.resolve().then(() => transport.close()),
    ]);
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

export function exactAuditDelta(
  before: readonly { operation: unknown; outcome: unknown }[],
  after: readonly { operation: unknown; outcome: unknown }[],
  expected: readonly { operation: string; outcome: string }[],
): boolean {
  const counts = (rows: readonly { operation: unknown; outcome: unknown }[]) => {
    const map = new Map<string, number>();
    for (const row of rows) {
      const key = `${String(row.operation)}\0${String(row.outcome)}`;
      map.set(key, (map.get(key) ?? 0) + 1);
    }
    return map;
  };
  const oldCounts = counts(before);
  const nextCounts = counts(after);
  const wanted = counts(expected);
  const keys = new Set([...oldCounts.keys(), ...nextCounts.keys(), ...wanted.keys()]);
  return [...keys].every(
    (key) => (nextCounts.get(key) ?? 0) === (oldCounts.get(key) ?? 0) + (wanted.get(key) ?? 0),
  );
}

function assertCalls(
  calls: readonly CompletedMcpCall[],
  expectedTools: readonly string[],
  expectedFailed: boolean,
) {
  if (
    calls.length !== expectedTools.length ||
    calls.some(
      (call, index) => call.tool !== expectedTools[index] || call.failed !== expectedFailed,
    )
  )
    throw new Error('codex_tool_calls_incomplete');
}

export function verifyStructuredOutput(
  calls: readonly CompletedMcpCall[],
  tool: 'list' | 'search' | 'read',
  recordId: RecordId,
  source: unknown,
  authority: unknown,
): 'verified' | 'not_exposed' {
  const call = calls.find((item) => item.tool === `mikaki_${tool}`);
  if (!call) throw new Error('codex_tool_call_missing');
  const outputs = findToolOutputs(call.event, tool);
  if (outputs.length === 0) return 'not_exposed';
  if (outputs.length !== 1) throw new Error('codex_structured_result_ambiguous');
  const parsed = toolOutputs[tool].parse(outputs[0]);
  type ResultDocument = {
    id: string;
    source_info: { kind: 'vault-record'; source: unknown; authority: unknown };
  };
  const documents: readonly ResultDocument[] =
    tool === 'read'
      ? [parsed as unknown as ResultDocument]
      : (parsed as unknown as { documents: readonly ResultDocument[] }).documents;
  if (
    documents.length !== 1 ||
    documents[0]?.id !== recordId ||
    documents[0]?.source_info.kind !== 'vault-record' ||
    JSON.stringify(documents[0]?.source_info.source) !== JSON.stringify(source) ||
    JSON.stringify(documents[0]?.source_info.authority) !== JSON.stringify(authority)
  )
    throw new Error('codex_structured_source_mismatch');
  return 'verified';
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
      join(repoRoot, 'local/agent-mcp.ts'),
      grantPath,
      exportPath,
      auditPath,
      'codex-v2-probe',
    ];
    const preflight = await sdkPreflight(serverArgs, recordId, fixture.source, fixture.authority);
    await writeFile(grantPath, JSON.stringify(fixture.grant), { mode: 0o600 });
    const codexServerArgs = [...serverArgs.slice(0, 3), codexAuditPath, ...serverArgs.slice(4)];
    const targetPrompt = JSON.stringify({ id: recordId });
    const positiveRun = await runCodex(
      codexArgs(dir, codexServerArgs),
      `Use only the MCP server mikaki_v2_local. Call mikaki_list with {}, then mikaki_search with {"query":"v2-probe-needle"}, then mikaki_read with ${targetPrompt}, exactly once each. Do not use any other tools. Do not repeat or quote returned content. Finish with the single word done.`,
    );
    const positiveCalls = completedMcpCalls(positiveRun.jsonl);
    if (positiveCalls.some((call) => call.server !== 'mikaki_v2_local'))
      throw new Error('codex_unexpected_mcp_server');
    assertCalls(positiveCalls, ['mikaki_list', 'mikaki_search', 'mikaki_read'], false);
    const codexStructured = {
      list: verifyStructuredOutput(
        positiveCalls,
        'list',
        recordId,
        fixture.source,
        fixture.authority,
      ),
      search: verifyStructuredOutput(
        positiveCalls,
        'search',
        recordId,
        fixture.source,
        fixture.authority,
      ),
      read: verifyStructuredOutput(
        positiveCalls,
        'read',
        recordId,
        fixture.source,
        fixture.authority,
      ),
    };
    const positiveAudit = await auditSummary(codexAuditPath);
    const exactPositiveAudit = exactAuditDelta([], positiveAudit, [
      { operation: 'list', outcome: 'allowed' },
      { operation: 'search', outcome: 'allowed' },
      { operation: 'read', outcome: 'allowed' },
    ]);
    if (!exactPositiveAudit) throw new Error('codex_positive_calls_incomplete');

    const grant = JSON.parse(await readFile(grantPath, 'utf8')) as JsonRecord;
    grant['revoked'] = true;
    await writeFile(grantPath, JSON.stringify(grant), { mode: 0o600 });
    const revokedRun = await runCodex(
      codexArgs(dir, codexServerArgs),
      `Use only the MCP server mikaki_v2_local. Call mikaki_read with ${targetPrompt} exactly once. Do not use any other tools or repeat/quote content. Finish with one word.`,
    );
    const revokeCalls = completedMcpCalls(revokedRun.jsonl);
    if (revokeCalls.some((call) => call.server !== 'mikaki_v2_local'))
      throw new Error('codex_unexpected_mcp_server');
    assertCalls(revokeCalls, ['mikaki_read'], true);
    const allAudit = await auditSummary(codexAuditPath);
    const exactDeniedAudit = exactAuditDelta(positiveAudit, allAudit, [
      { operation: 'read', outcome: 'denied' },
    ]);
    if (!exactDeniedAudit) throw new Error('codex_revoke_not_observed');
    return {
      passed: true,
      client: 'Codex CLI',
      data: 'synthetic-only',
      record: recordId,
      mcp_server: 'local-stdio',
      codex_invocation: {
        positive_tool_calls: ['list', 'search', 'read'],
        positive_event_summary: positiveRun.stdoutEvents,
        structured_content_source_authority: codexStructured,
        revoked_invocation_tool_calls: ['read'],
        revoked_event_summary: revokedRun.stdoutEvents,
        revoked_read_denied: true,
        note: 'The revocation check uses a new Codex invocation with the same local MCP configuration.',
      },
      sdk_preflight: {
        source_authority_verified: true,
        calls: preflight.calls,
        revoked_read_denied: preflight.revokedReadDenied,
      },
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
    if (error instanceof CodexCliError) {
      process.stderr.write(
        `${JSON.stringify({
          passed: false,
          error: error.code,
          ...(error.exitCode !== undefined ? { exit_code: error.exitCode } : {}),
          ...(error.diagnosticCategory ? { diagnostic_category: error.diagnosticCategory } : {}),
          ...(error.errorEventKind ? { error_event_kind: error.errorEventKind } : {}),
          ...(error.httpStatus !== undefined ? { http_status: error.httpStatus } : {}),
          ...(error.stdoutEvents ? { stdout_events: error.stdoutEvents } : {}),
        })}\n`,
      );
    } else {
      const code =
        error instanceof Error && /^[a-z_]+$/.test(error.message) ? error.message : 'probe_failed';
      process.stderr.write(`${JSON.stringify({ passed: false, error: code })}\n`);
    }
    process.exitCode = 1;
  }
}
