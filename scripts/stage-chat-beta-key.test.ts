import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { assertKeyClone, assertKeyStagePreflight, stageChatKey } from './stage-chat-beta-key.ts';
import { PRODUCTION_WORK_TARGET } from './production-work-adoption.ts';

const source = { commit: 'a'.repeat(40), clean: true };
const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const base = `/accounts/${PRODUCTION_WORK_TARGET.account}/workers/scripts/mikaki-auth`;
function fixture() {
  const { kty, crv, x, d } = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
  const raw = JSON.stringify({ kty, crv, x, d });
  const production = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
  const config = {
    account_id: String(PRODUCTION_WORK_TARGET.account),
    name: 'mikaki-auth',
    compatibility_date: '2026-09-23',
    vars: { ISSUER: 'https://auth.mikaki.org' },
    secrets: { required: ['OP_PRIVATE_JWK'] },
    d1_databases: [{ binding: 'DB', database_id: String(PRODUCTION_WORK_TARGET.database) }],
    queues: production.queues,
  };
  const baseline = { deployment_id: id(2), version_id: id(1), chat: 'disabled' as const };
  const original = {
    id: id(1),
    annotations: {
      'workers/tag': source.commit.slice(0, 12),
      'workers/message': `main CI ${source.commit}`,
    },
    resources: {
      script: { etag: 'b'.repeat(64) },
      script_runtime: { compatibility_date: config.compatibility_date },
      bindings: [
        { name: 'DB', type: 'd1', database_id: config.d1_databases[0]!.database_id },
        { name: 'ISSUER', type: 'plain_text', text: config.vars.ISSUER },
        { name: 'OP_PRIVATE_JWK', type: 'secret_text' },
        { name: 'LOGOUT_QUEUE', type: 'queue', queue_name: 'mikaki-logout-wakeups' },
      ] as Record<string, unknown>[],
    },
  };
  const versions = new Map([[original.id, original]]);
  let latest = original.id,
    currentCalls = 0;
  const writes: { operation: string; input?: string }[] = [];
  const reports: Record<string, unknown>[] = [];
  const deployment = {
    id: baseline.deployment_id,
    strategy: 'percentage',
    versions: [{ version_id: original.id, percentage: 100 }],
  };
  const exposure = { enabled: false, previews_enabled: false };
  const io = {
    get: async (path: string) => {
      if (path === `${base}/deployments?page=1&per_page=1`)
        return { success: true, result: { deployments: [deployment] } };
      if (path === `${base}/versions?page=1&per_page=1`)
        return { success: true, result: { items: [{ id: latest }] } };
      if (path === `${base}/subdomain`) return { success: true, result: exposure };
      const version = versions.get(path.slice(`${base}/versions/`.length));
      assert.ok(version, `Unexpected metadata path ${path}`);
      return { success: true, result: version };
    },
    current: async () => {
      currentCalls++;
    },
    version: async (versionId: string) => {
      const version = versions.get(versionId);
      assert.ok(version);
      return structuredClone(version);
    },
    secret: async (operation: 'put' | 'delete', message: string, input?: string) => {
      writes.push({ operation, input });
      if (operation === 'put') assert.equal(input, raw);
      else assert.equal(input, undefined);
      const next = structuredClone(original);
      next.id = id(operation === 'put' ? 3 : 4);
      next.annotations = {
        'workers/tag': `chat-key-${source.commit.slice(0, 12)}`,
        'workers/message': message,
      };
      if (operation === 'put')
        next.resources.bindings.push({ name: 'MESSAGING_ISSUER_KEY', type: 'secret_text' });
      versions.set(next.id, next);
      latest = next.id;
      return `Success! Created version ${next.id} with ${operation === 'put' ? '1 secret created and 0 secrets' : '0 secrets created and 1 secret'} deleted.`;
    },
    save: (report: Record<string, unknown>) => {
      reports.push(structuredClone(report));
    },
  };
  return {
    raw,
    x: x!,
    d: d!,
    config,
    baseline,
    original,
    versions,
    writes,
    reports,
    io,
    deployment,
    exposure,
    setLatest: (value: string) => {
      latest = value;
    },
    currentCalls: () => currentCalls,
  };
}
const run = (f: ReturnType<typeof fixture>) =>
  stageChatKey(source, f.config, f.baseline, f.raw, f.x, f.io);

test('staging preserves active traffic and code; a key-free inactive tail prevents later inheritance', async () => {
  const f = fixture(),
    report = await run(f);
  assert.deepEqual(
    f.writes.map((w) => w.operation),
    ['put', 'delete'],
  );
  assert.equal(report.status, 'passed');
  assert.equal(report.key_version_id, id(3));
  assert.equal(report.clean_tail_version_id, id(4));
  assert.equal(report.promotion_ready, false);
  assert.equal(report.remote_public_key_verified, false);
  assert.equal(report.active_change_requested, false);
  assert.deepEqual(f.deployment.versions, [{ version_id: id(1), percentage: 100 }]);
  assert.ok(f.currentCalls() >= 5);
  assert.ok(
    f.versions.get(id(3))!.resources.bindings.some((b) => b.name === 'MESSAGING_ISSUER_KEY'),
  );
  assert.ok(
    !f.versions.get(id(4))!.resources.bindings.some((b) => b.name === 'MESSAGING_ISSUER_KEY'),
  );
  assert.ok(!JSON.stringify(f.reports).includes(f.d));
});

test('wrong public pin, disabled preview drift, active split, unknown latest or stale source stop before any write', async () => {
  for (const change of [
    (f: ReturnType<typeof fixture>) => {
      f.x = 'A'.repeat(43);
    },
    (f: ReturnType<typeof fixture>) => {
      f.exposure.previews_enabled = true;
    },
    (f: ReturnType<typeof fixture>) => {
      f.exposure.enabled = true;
    },
    (f: ReturnType<typeof fixture>) => {
      f.deployment.versions[0]!.percentage = 99;
    },
    (f: ReturnType<typeof fixture>) => {
      f.setLatest(id(9));
    },
    (f: ReturnType<typeof fixture>) => {
      f.io.current = async () => {
        throw new Error('Application advanced');
      };
    },
    (f: ReturnType<typeof fixture>) => {
      f.original.resources.script.etag = '';
    },
  ]) {
    const f = fixture();
    change(f);
    await assert.rejects(run(f));
    assert.equal(f.writes.length, 0);
    assert.equal(f.reports.at(-1)!.writes_attempted, false);
  }
});

test('changed code, bindings or annotations in a secret clone prevent any follow-up mutation', async () => {
  for (const change of [
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.script.etag = 'c'.repeat(64);
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.bindings.push({
        name: 'MESSAGING_BETA_ENABLED',
        type: 'plain_text',
        text: 'true',
      });
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.bindings[0]!.database_id = id(9);
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.bindings[2]!.name = 'MISSING_ORIGINAL_KEY';
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.annotations['workers/message'] = 'unreviewed';
    },
  ]) {
    const f = fixture(),
      version = f.io.version;
    f.io.version = async (versionId) => {
      const value = await version(versionId);
      if (versionId === id(3)) change(value);
      return value;
    };
    await assert.rejects(run(f));
    assert.equal(f.writes.length, 1);
    assert.equal(f.reports.at(-1)!.key_version_id, id(3));
    assert.equal(f.reports.at(-1)!.status, 'failed');
  }
});

test('ambiguous writes are never retried and never expose subprocess errors or private material', async () => {
  for (const failing of ['put', 'delete']) {
    const f = fixture(),
      secret = f.io.secret;
    f.io.secret = async (operation, message, input) => {
      if (operation === failing) {
        f.writes.push({ operation });
        throw new Error(f.raw);
      }
      return secret(operation, message, input);
    };
    await assert.rejects(
      run(f),
      (e) => e instanceof Error && !e.message.includes(f.d) && e.cause === undefined,
    );
    assert.equal(f.writes.length, failing === 'put' ? 1 : 2);
    const last = f.reports.at(-1)!;
    assert.equal(last.writes_attempted, true);
    assert.equal(last.status, 'failed');
    assert.equal(last.key_version_id, failing === 'delete' ? id(3) : undefined);
    assert.ok(!JSON.stringify(f.reports).includes(f.d));
  }
});

test('an out-of-band latest upload after staging prevents deleting secrets from that unrelated version', async () => {
  const f = fixture(),
    secret = f.io.secret;
  f.io.secret = async (...args) => {
    const value = await secret(...args);
    f.setLatest(id(9));
    return value;
  };
  await assert.rejects(run(f));
  assert.equal(f.writes.length, 1);
});

test('clone validation rejects a baseline ID substitution or a changed runtime', () => {
  const f = fixture(),
    clone = structuredClone(f.original);
  assert.throws(() => assertKeyClone(clone, f.original, '', source, true));
  clone.id = id(3);
  clone.annotations = {
    'workers/tag': `chat-key-${source.commit.slice(0, 12)}`,
    'workers/message': 'test',
  };
  clone.resources.script_runtime.compatibility_date = '2026-10-23';
  assert.throws(() => assertKeyClone(clone, f.original, 'test', source, false));
});

test('only a fresh successful exact-source preflight and reviewed baseline can precede key staging', () => {
  const now = Date.now();
  const report = {
    schema: 'mikaki-chat-beta-preflight-v1',
    status: 'passed',
    source,
    candidate: { run_id: 12 },
    baseline: { version_id: id(1), chat: 'disabled' },
    sonar: { quality_gate: 'OK' },
    candidate_bytes: 'verified',
    production_chat_schema: 'complete',
    mutations: false,
    promotion_ready: false,
    checked_at: new Date(now).toISOString(),
  };
  assertKeyStagePreflight(report, source, 12, id(1), now);
  for (const [name, value] of Object.entries({
    status: 'failed',
    source: { ...source, clean: false },
    candidate: { run_id: 13 },
    baseline: { version_id: id(9), chat: 'disabled' },
    sonar: { quality_gate: 'ERROR' },
    candidate_bytes: 'unknown',
    production_chat_schema: 'partial',
    mutations: true,
    promotion_ready: true,
    checked_at: new Date(now - 16 * 60_000).toISOString(),
  }))
    assert.throws(() =>
      assertKeyStagePreflight({ ...report, [name]: value }, source, 12, id(1), now),
    );
  for (const checked_at of ['invalid', new Date(now + 1).toISOString()])
    assert.throws(() => assertKeyStagePreflight({ ...report, checked_at }, source, 12, id(1), now));
});
