/** Optional real-client smoke against synthetic data; never touches production grants. */
import { execFile, type ExecFileOptions } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

function run(
  command: string,
  args: string[],
  options: ExecFileOptions = {},
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      command,
      args,
      { ...options, encoding: 'utf8' },
      (error, stdout, stderr) => {
        if (error) reject(error);
        else resolve({ stdout, stderr });
      },
    );
    // Codex consumes additional stdin even when a prompt argument is present.
    child.stdin?.end();
  });
}
const dir = await mkdtemp(join(tmpdir(), 'mikaki-agent-client-'));
const outputDir = resolve('local/generated/agent-client-probe');
await mkdir(outputDir, { recursive: true, mode: 0o700 });
const grokHome = join(dir, 'grok-probe-home');
await mkdir(grokHome, { mode: 0o700 });
await run('git', ['init', '--quiet', dir]);
const bytes = JSON.stringify({
  version: 1,
  owner: 'synthetic-owner',
  collection: 'smoke',
  documents: [{ id: 'note', title: 'Synthetic probe', source: 'test', text: 'mikaki-probe-ok' }],
});
const exportPath = join(dir, 'export.json');
await writeFile(exportPath, bytes, { mode: 0o600 });
const entry = resolve('local/agent-mcp.ts');
const expires = Math.floor(Date.now() / 1000) + 3600;
async function grant(delegate: string, service: string) {
  const path = join(dir, `${delegate}.json`);
  await writeFile(
    path,
    JSON.stringify({
      version: 1,
      id: randomBytes(16).toString('hex'),
      owner: 'synthetic-owner',
      collection: 'smoke',
      delegate,
      service,
      export_sha256: createHash('sha256').update(bytes).digest('hex'),
      document_ids: ['note'],
      operations: ['list', 'search', 'read'],
      not_before: expires - 3600,
      expires_at: expires,
      revoked: false,
    }),
    { mode: 0o600 },
  );
  return [entry, path, exportPath, join(dir, `${delegate}-audit.jsonl`), delegate];
}
const grokArgs = await grant('grok-probe', 'xAI');
await writeFile(
  join(grokHome, 'config.toml'),
  `[mcp_servers.mikaki_probe]\ncommand = ${JSON.stringify(process.execPath)}\nargs = ${JSON.stringify(grokArgs)}\n`,
  { mode: 0o600 },
);
const results: Record<string, unknown> = {
  date: new Date().toISOString(),
  synthetic_data_only: true,
};
try {
  const result = await run(
    'grok',
    [
      '--cwd',
      dir,
      '--leader-socket',
      join(dir, 'grok.sock'),
      'mcp',
      'doctor',
      'mikaki_probe',
      '--json',
    ],
    { timeout: 60000, maxBuffer: 1024 * 1024, env: { ...process.env, GROK_HOME: grokHome } },
  );
  await writeFile(join(outputDir, 'grok.json'), result.stdout, { mode: 0o600 });
  results.grok = { passed: JSON.parse(result.stdout).healthy_count === 1 };
} catch (error) {
  results.grok = { passed: false, error: error instanceof Error ? error.message : 'failed' };
}
const codexArgs = await grant('codex-probe', 'OpenAI');
const config = `mcp_servers={mikaki_probe={command=${JSON.stringify(process.execPath)},args=${JSON.stringify(codexArgs)},required=true}}`;
try {
  const result = await run(
    'codex',
    [
      'exec',
      '--ignore-user-config',
      '--ignore-rules',
      '--skip-git-repo-check',
      '--ephemeral',
      '-C',
      dir,
      '--sandbox',
      'read-only',
      '--json',
      '-c',
      config,
      'Connection smoke only. Do not use shell, network, other tools, or subagents. Call mikaki_probe.mikaki_read with id note once, then reply with the returned note text.',
    ],
    { timeout: 120000, maxBuffer: 1024 * 1024 },
  );
  await writeFile(join(outputDir, 'codex.jsonl'), result.stdout, { mode: 0o600 });
  await writeFile(join(outputDir, 'codex-stderr.txt'), result.stderr, { mode: 0o600 });
  // Require a completed MCP tool call, not just a model answer containing the known string.
  const events = result.stdout
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  results.codex = {
    passed: events.some(
      (event) =>
        event.type === 'item.completed' &&
        typeof event.item === 'object' &&
        event.item !== null &&
        'type' in event.item &&
        event.item.type === 'mcp_tool_call' &&
        JSON.stringify(event.item).includes('mikaki-probe-ok'),
    ),
  };
} catch (error) {
  results.codex = { passed: false, error: error instanceof Error ? error.message : 'failed' };
}
await writeFile(join(outputDir, 'summary.json'), JSON.stringify(results, null, 2) + '\n', {
  mode: 0o600,
});
console.log(JSON.stringify(results));
