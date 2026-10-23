/** Stage a Chat key in an inactive clone; never deploy, enable Chat or write application data. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkBindings, sourceIsCurrent } from './deploy-production.ts';
import { releaseSource, type ReleaseSource } from './release-inventory.ts';
import {
  assertChatPreflightContext,
  chatPreflightRunId,
  inspectChatCandidate,
  inspectChatDisabledBaseline,
  inspectChatQualityGate,
} from './prepare-chat-beta-promotion.ts';
import { messagingIssuerPublicKey } from './messaging-issuer-key.ts';
import { cloudflareMetadataGet, type MetadataGet } from './production-worker-inventory.ts';
import { PRODUCTION_WORK_TARGET } from './production-work-adoption.ts';
import { uploadedVersionView } from './production-wrangler.ts';

const CONFIG = 'crates/worker/wrangler.production.jsonc';
const KEY = 'MESSAGING_ISSUER_KEY';
const BASE = `/accounts/${PRODUCTION_WORK_TARGET.account}/workers/scripts/mikaki-auth`;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
type Row = Record<string, unknown>;
function object(value: unknown): Row {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  return value as Row;
}
function result(value: unknown): Row {
  const envelope = object(value);
  assert.equal(envelope.success, true);
  return object(envelope.result);
}

export function assertKeyStagePreflight(
  report: unknown,
  source: ReleaseSource,
  runId: number,
  baselineId: string,
  now = Date.now(),
) {
  assert.match(baselineId, uuid);
  const r = object(report);
  assert.equal(r.schema, 'mikaki-chat-beta-preflight-v1');
  assert.equal(r.status, 'passed');
  assert.deepEqual(r.source, source);
  assert.equal(object(r.candidate).run_id, runId);
  assert.equal(object(r.baseline).version_id, baselineId);
  assert.equal(object(r.baseline).chat, 'disabled');
  assert.equal(object(r.sonar).quality_gate, 'OK');
  assert.equal(r.candidate_bytes, 'verified');
  assert.equal(r.production_chat_schema, 'complete');
  assert.equal(r.mutations, false);
  assert.equal(r.promotion_ready, false);
  assert.equal(typeof r.checked_at, 'string');
  const age = now - Date.parse(String(r.checked_at));
  assert.ok(Number.isFinite(age) && age >= 0 && age <= 15 * 60_000, 'Fresh preflight required');
}

type Version = {
  id: string;
  annotations: Record<string, unknown>;
  resources: Parameters<typeof checkBindings>[0]['resources'] & {
    script: { etag: string };
  };
};
type Config = Parameters<typeof inspectChatDisabledBaseline>[2];
type Baseline = Awaited<ReturnType<typeof inspectChatDisabledBaseline>>;
type StageIO = {
  get: MetadataGet;
  current(): Promise<void>;
  version(id: string): Promise<Version>;
  secret(operation: 'put' | 'delete', message: string, input?: string): Promise<string>;
  save(report: Row): void;
};

async function latest(get: MetadataGet, expected: string) {
  const items = result(await get(`${BASE}/versions?page=1&per_page=1`)).items;
  assert.ok(Array.isArray(items) && items.length === 1);
  assert.equal(object(items[0]).id, expected, 'Latest upload changed; do not modify its secrets');
}

export function assertKeyClone(
  version: Version,
  baseline: Version,
  message: string,
  source: ReleaseSource,
  withKey: boolean,
) {
  assert.match(version.id, uuid);
  assert.notEqual(version.id, baseline.id);
  assert.equal(version.annotations['workers/message'], message);
  assert.equal(version.annotations['workers/tag'], `chat-key-${source.commit.slice(0, 12)}`);
  assert.match(baseline.resources.script.etag, /^[a-f0-9]{32,128}$/);
  assert.equal(version.resources.script.etag, baseline.resources.script.etag);
  assert.deepEqual(version.resources.script_runtime, baseline.resources.script_runtime);
  const order = (a: Row, b: Row) => String(a.name).localeCompare(String(b.name));
  assert.deepEqual(
    [...version.resources.bindings].sort(order),
    [...baseline.resources.bindings, ...(withKey ? [{ name: KEY, type: 'secret_text' }] : [])].sort(
      order,
    ),
  );
}

/** One write per operation, no retry or cleanup after an ambiguous outcome. */
export async function stageChatKey(
  source: ReleaseSource,
  config: Config,
  baseline: Baseline,
  raw: string,
  expectedPublicKey: string,
  io: StageIO,
) {
  const record: Row = {
    schema: 'mikaki-chat-key-stage-v1',
    source,
    baseline,
    status: 'failed',
    stage: 'key_validation',
    writes_attempted: false,
    active_change_requested: false,
    promotion_ready: false,
    remote_public_key_verified: false,
  };
  try {
    assert.equal(source.clean, true);
    assert.match(source.commit, /^[a-f0-9]{40}$/);
    assert.match(baseline.version_id, uuid);
    record.key = messagingIssuerPublicKey(raw, expectedPublicKey);
    const stable = async (latestId: string) => {
      await io.current();
      assert.deepEqual(await inspectChatDisabledBaseline(io.get, source, config), baseline);
      const exposure = result(await io.get(`${BASE}/subdomain`));
      assert.equal(exposure.enabled, false);
      assert.equal(exposure.previews_enabled, false);
      await latest(io.get, latestId);
    };
    record.stage = 'baseline';
    await stable(baseline.version_id);
    const original = await io.version(baseline.version_id);
    assert.equal(original.id, baseline.version_id);
    assert.match(original.resources.script.etag, /^[a-f0-9]{32,128}$/);
    const mutate = async (operation: 'put' | 'delete', previous: string) => {
      await stable(previous);
      record.stage = operation === 'put' ? 'stage_key' : 'clear_inheritance_tail';
      record.writes_attempted = true;
      io.save({ ...record });
      const message = `Chat key ${operation} ${source.commit}`;
      const output = await io.secret(operation, message, operation === 'put' ? raw : undefined);
      const id = output.match(
        /Created version ([a-f0-9-]{36}) with \d secrets? created and \d secrets? deleted\./,
      )?.[1];
      assert.ok(id && uuid.test(id), 'Unconfirmed secret version; inspect before retrying');
      assert.notEqual(id, previous);
      record[operation === 'put' ? 'key_version_id' : 'clean_tail_version_id'] = id;
      io.save({ ...record });
      const cloned = await io.version(id);
      assert.equal(cloned.id, id);
      assertKeyClone(cloned, original, message, source, operation === 'put');
      await stable(id);
      return id;
    };
    const keyVersion = await mutate('put', baseline.version_id);
    // versions upload inherits secrets from latest. Leave a normal, key-free
    // inactive successor so an ordinary release cannot inherit this staged key.
    const tail = await mutate('delete', keyVersion);
    assert.notEqual(tail, keyVersion);
    record.stage = 'complete';
    record.status = 'passed';
    record.checked_at = new Date().toISOString();
    record.remaining = [
      'remote_public_key_and_same_origin_configuration',
      'remote_populated_disable_and_code_rollback',
      'physical_passkey_prf_and_two_owner_qualification',
      'protected_beta_activation_path',
    ];
    io.save({ ...record });
    return record;
  } catch {
    record.status = 'failed';
    io.save({ ...record });
    throw new Error('Chat key staging failed; inspect the sanitized report before retrying.');
  }
}

async function main() {
  assert.equal(process.argv.length, 3);
  const runId = chatPreflightRunId(process.argv[2]);
  const root = fileURLToPath(new URL('../', import.meta.url));
  const source = releaseSource(root);
  assertChatPreflightContext(process.env, source, true);
  const directory = join(root, 'artifacts/chat-key-stage');
  const reportPath = join(directory, 'report.json');
  assert.equal(existsSync(reportPath), false, 'Fresh key-stage report required');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeFileSync(
    reportPath,
    JSON.stringify(
      {
        schema: 'mikaki-chat-key-stage-v1',
        source,
        status: 'failed',
        stage: 'custody_and_preflight',
        writes_attempted: false,
        active_change_requested: false,
        promotion_ready: false,
        remote_public_key_verified: false,
      },
      null,
      2,
    ) + '\n',
    { mode: 0o600 },
  );
  const raw = process.env.MESSAGING_ISSUER_KEY ?? '';
  const expected = process.env.EXPECTED_CHAT_PUBLIC_KEY ?? '';
  messagingIssuerPublicKey(raw, expected);
  const preflight = JSON.parse(
    readFileSync(join(root, 'artifacts/chat-beta-preflight/report.json'), 'utf8'),
  );
  assertKeyStagePreflight(preflight, source, runId, process.env.EXPECTED_BASELINE_VERSION ?? '');
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    WRANGLER_LOG: 'log',
    WRANGLER_SEND_METRICS: 'false',
  };
  delete env.MESSAGING_ISSUER_KEY;
  const command = (binary: string, args: string[], input?: string) =>
    execFileSync(binary, args, {
      cwd: root,
      env,
      input,
      encoding: 'utf8',
      timeout: 120_000,
      maxBuffer: 4 * 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  const githubGet = async (path: string) => JSON.parse(command('gh', ['api', path]));
  assert.deepEqual(await inspectChatCandidate(githubGet, runId, source), preflight.candidate);
  const sonarGet = async (path: string) =>
    JSON.parse(
      command('curl', [
        '--fail',
        '--silent',
        '--show-error',
        '--proto',
        '=https',
        '--connect-timeout',
        '10',
        '--max-time',
        '25',
        `https://sonarcloud.io/api/${path}`,
      ]),
    );
  assert.deepEqual(await inspectChatQualityGate(sonarGet, source), preflight.sonar);
  const config = JSON.parse(readFileSync(join(root, CONFIG), 'utf8'));
  const get = cloudflareMetadataGet(
    PRODUCTION_WORK_TARGET.account,
    process.env.CLOUDFLARE_API_TOKEN!,
  );
  const wrangler = (args: string[], input?: string) =>
    command(join(root, 'node_modules/.bin/wrangler'), args, input);
  await stageChatKey(source, config, preflight.baseline, raw, expected, {
    get,
    current: async () => {
      command('git', ['fetch', 'origin', 'main']);
      command('git', ['merge-base', '--is-ancestor', source.commit, 'origin/main']);
      const changed = command('git', ['diff', '--name-only', source.commit, 'origin/main']).trim();
      assert.ok(sourceIsCurrent(changed ? changed.split('\n') : []));
      assert.deepEqual(releaseSource(root), source);
    },
    version: async (id) => JSON.parse(await uploadedVersionView(id, CONFIG, wrangler)),
    secret: async (operation, message, input) =>
      wrangler(
        [
          'versions',
          'secret',
          'bulk',
          '--config',
          CONFIG,
          '--tag',
          `chat-key-${source.commit.slice(0, 12)}`,
          '--message',
          message,
        ],
        JSON.stringify({ [KEY]: operation === 'put' ? input : null }),
      ),
    save: (report) =>
      writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n', {
        mode: 0o600,
      }),
  });
  console.log('Chat key staged in an inactive version; active deployment unchanged.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await main();
  } catch {
    console.error('Chat key stage failed; inspect its sanitized report before retrying.');
    process.exitCode = 1;
  }
}
