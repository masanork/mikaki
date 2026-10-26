import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  chatReleaseConfig,
  stageChatRelease,
  withChatReleaseSecret,
} from './stage-chat-beta-release.ts';
import { assertChatPreflightContext } from './prepare-chat-beta-promotion.ts';
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
    compatibility_date: production.compatibility_date,
    vars: { MIKAKI_ISSUER: 'https://auth.mikaki.org' },
    secrets: { required: ['OP_PRIVATE_JWK'] },
    d1_databases: [{ binding: 'DB', database_id: String(PRODUCTION_WORK_TARGET.database) }],
    queues: production.queues,
    durable_objects: { bindings: [{ name: 'AUTH_STATE', class_name: 'AuthState' }] },
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
        { name: 'MIKAKI_ISSUER', type: 'plain_text', text: config.vars.MIKAKI_ISSUER },
        { name: 'OP_PRIVATE_JWK', type: 'secret_text' },
        { name: 'LOGOUT_QUEUE', type: 'queue', queue_name: 'mikaki-logout-wakeups' },
        {
          name: 'AUTH_STATE',
          type: 'durable_object_namespace',
          class_name: 'AuthState',
          namespace_id: 'e'.repeat(32),
        },
      ] as Record<string, unknown>[],
    },
  };
  const versions = new Map([[original.id, original]]);
  let latest = original.id;
  const deployment = {
    id: baseline.deployment_id,
    strategy: 'percentage',
    versions: [{ version_id: original.id, percentage: 100 }],
  };
  const exposure = { enabled: false, previews_enabled: false };
  const writes: string[] = [];
  const reports: Record<string, unknown>[] = [];
  let verified = 0;
  const io = {
    get: async (path: string) => {
      if (path === `${base}/deployments?page=1&per_page=1`)
        return { success: true, result: { deployments: [deployment] } };
      if (path === `${base}/versions?page=1&per_page=1`)
        return { success: true, result: { items: [{ id: latest }] } };
      if (path === `${base}/subdomain`) return { success: true, result: exposure };
      const version = versions.get(path.slice(`${base}/versions/`.length));
      assert.ok(version);
      return { success: true, result: version };
    },
    current: async () => {},
    verifyBytes: async () => {
      verified++;
    },
    version: async (versionId: string) => {
      const v = versions.get(versionId);
      assert.ok(v);
      return structuredClone(v);
    },
    upload: async (message: string) => {
      writes.push('upload');
      const next = structuredClone(original);
      next.id = id(3);
      next.resources.script.etag = 'c'.repeat(64);
      next.annotations = {
        'workers/tag': `chat-beta-${source.commit.slice(0, 12)}`,
        'workers/message': message,
      };
      next.resources.bindings.push(
        { name: 'MESSAGING_BETA_ENABLED', type: 'plain_text', text: 'true' },
        { name: 'MESSAGING_ISSUER_KEY', type: 'secret_text' },
      );
      versions.set(next.id, next);
      latest = next.id;
      return `Worker Version ID: ${next.id}`;
    },
    clearKey: async (message: string) => {
      writes.push('delete');
      const next = structuredClone(versions.get(id(3))!);
      next.id = id(4);
      next.annotations['workers/message'] = message;
      next.resources.bindings = next.resources.bindings.filter(
        (b) => b.name !== 'MESSAGING_ISSUER_KEY',
      );
      versions.set(next.id, next);
      latest = next.id;
      return `Created version ${next.id} with 0 secrets created and 1 secret deleted.`;
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
    deployment,
    exposure,
    writes,
    reports,
    io,
    setLatest: (value: string) => {
      latest = value;
    },
    verified: () => verified,
  };
}
const run = (f: ReturnType<typeof fixture>) =>
  stageChatRelease(source, f.config, f.baseline, f.raw, f.x, f.io);

test('an inactive keyed release and a key-free tail preserve active traffic, code and data bindings', async () => {
  const f = fixture();
  const report = await run(f);
  assert.deepEqual(f.writes, ['upload', 'delete']);
  assert.equal(f.verified(), 2);
  assert.equal(report.status, 'passed');
  assert.equal(report.version_id, id(3));
  assert.equal(report.clean_tail_version_id, id(4));
  assert.equal(report.active_change_requested, false);
  assert.equal(report.promotion_ready, false);
  assert.equal(report.remote_public_key_verified, false);
  assert.equal(report.remote_runtime_profile_verified, false);
  assert.deepEqual(f.deployment.versions, [{ version_id: id(1), percentage: 100 }]);
  assert.equal(f.original.resources.script.etag, 'b'.repeat(64));
  assert.equal(f.versions.get(id(3))!.resources.script.etag, 'c'.repeat(64));
  assert.equal(f.versions.get(id(4))!.resources.script.etag, 'c'.repeat(64));
  assert.ok(
    f.versions.get(id(3))!.resources.bindings.some((b) => b.name === 'MESSAGING_ISSUER_KEY'),
  );
  assert.ok(
    !f.versions.get(id(4))!.resources.bindings.some((b) => b.name === 'MESSAGING_ISSUER_KEY'),
  );
  assert.ok(!JSON.stringify(f.reports).includes(f.d));
});

test('custody, candidate bytes, active baseline, exposure and source are required before writing', async () => {
  const changes = [
    (f: ReturnType<typeof fixture>) => {
      f.x = 'A'.repeat(43);
    },
    (f: ReturnType<typeof fixture>) => {
      f.io.verifyBytes = async () => {
        throw new Error('tampered archive');
      };
    },
    (f: ReturnType<typeof fixture>) => {
      f.exposure.enabled = true;
    },
    (f: ReturnType<typeof fixture>) => {
      f.exposure.previews_enabled = true;
    },
    (f: ReturnType<typeof fixture>) => {
      f.setLatest(id(9));
    },
    (f: ReturnType<typeof fixture>) => {
      f.deployment.versions[0]!.percentage = 99;
    },
    (f: ReturnType<typeof fixture>) => {
      f.io.current = async () => {
        throw new Error('source advanced');
      };
    },
    (f: ReturnType<typeof fixture>) => {
      f.original.resources.script.etag = '';
    },
  ];
  for (const change of changes) {
    const f = fixture();
    change(f);
    await assert.rejects(run(f));
    assert.equal(f.writes.length, 0);
    assert.equal(f.reports.at(-1)!.writes_attempted, false);
  }
});

test('configuration changes are limited to the beta flag and required key', () => {
  const f = fixture();
  const before = structuredClone(f.config);
  const config = chatReleaseConfig(f.config);
  assert.deepEqual(f.config, before);
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.deepEqual(config.vars, { ...f.config.vars, MESSAGING_BETA_ENABLED: 'true' });
  assert.deepEqual(config.secrets.required, ['OP_PRIVATE_JWK', 'MESSAGING_ISSUER_KEY']);
  for (const change of [
    () => {
      f.config.name = 'other';
    },
    () => {
      f.config.account_id = '0'.repeat(32);
    },
    () => {
      f.config.secrets.required.push('MESSAGING_ISSUER_KEY');
    },
  ]) {
    const saved = structuredClone(f.config);
    change();
    assert.throws(() => chatReleaseConfig(f.config));
    Object.assign(f.config, saved);
  }
});

test('wrong uploaded code, bindings, runtime, IDs or annotations stop before key-tail mutation', async () => {
  for (const change of [
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.script.etag = 'b'.repeat(64);
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.bindings[0]!.database_id = id(9);
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.bindings.find((b) => b.name === 'AUTH_STATE')!.namespace_id = 'f'.repeat(32);
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.bindings.push({ name: 'UNREVIEWED_SECRET', type: 'secret_text' });
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.script_runtime.compatibility_date = '2026-10-26';
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.annotations['workers/message'] = 'other';
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.id = id(9);
    },
  ]) {
    const f = fixture(),
      upload = f.io.upload;
    f.io.upload = async (message) => {
      const output = await upload(message);
      change(f.versions.get(id(3))!);
      return output;
    };
    await assert.rejects(run(f));
    assert.deepEqual(f.writes, ['upload']);
    assert.equal(f.reports.at(-1)!.version_id, id(3));
  }
});

test('active or latest upload changes after staging stop further writes', async () => {
  for (const change of [
    (f: ReturnType<typeof fixture>) => {
      f.deployment.id = id(9);
    },
    (f: ReturnType<typeof fixture>) => {
      f.setLatest(id(9));
    },
    (f: ReturnType<typeof fixture>) => {
      f.exposure.previews_enabled = true;
    },
  ]) {
    const f = fixture(),
      upload = f.io.upload;
    f.io.upload = async (message) => {
      const output = await upload(message);
      change(f);
      return output;
    };
    await assert.rejects(run(f));
    assert.deepEqual(f.writes, ['upload']);
  }
});

test('uncertain writes are never retried or followed by automatic cleanup', async () => {
  for (const operation of ['upload', 'delete']) {
    const f = fixture();
    if (operation === 'upload')
      f.io.upload = async () => {
        f.writes.push('upload');
        throw new Error('uncertain write');
      };
    else
      f.io.clearKey = async () => {
        f.writes.push('delete');
        throw new Error('uncertain write');
      };
    await assert.rejects(run(f));
    assert.deepEqual(f.writes, operation === 'upload' ? ['upload'] : ['upload', 'delete']);
    assert.equal(f.reports.at(-1)!.status, 'failed');
    assert.equal(f.reports.at(-1)!.writes_attempted, true);
    assert.equal(f.reports.at(-1)!.clean_tail_version_id, undefined);
  }
});

test('key-free tail must preserve staged code and every other binding', async () => {
  for (const change of [
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.script.etag = 'd'.repeat(64);
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.bindings.push({ name: 'MESSAGING_ISSUER_KEY', type: 'secret_text' });
    },
    (v: ReturnType<typeof fixture>['original']) => {
      v.resources.bindings[0]!.database_id = id(9);
    },
  ]) {
    const f = fixture(),
      clear = f.io.clearKey;
    f.io.clearKey = async (message) => {
      const output = await clear(message);
      change(f.versions.get(id(4))!);
      return output;
    };
    await assert.rejects(run(f));
    assert.deepEqual(f.writes, ['upload', 'delete']);
    assert.equal(f.reports.at(-1)!.clean_tail_version_id, id(4));
    assert.equal(f.reports.at(-1)!.status, 'failed');
  }
});

test('temporary secret files are private, removed after failure and never overwrite custody', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'chat-stage-secret-')),
    path = join(directory, 'secret.json');
  try {
    await assert.rejects(
      withChatReleaseSecret(path, 'fixture-key', async () => {
        assert.equal(statSync(path).mode & 0o777, 0o600);
        assert.equal(JSON.parse(readFileSync(path, 'utf8')).MESSAGING_ISSUER_KEY, 'fixture-key');
        throw new Error('operation failed');
      }),
    );
    assert.equal(existsSync(path), false);
    assert.equal(await withChatReleaseSecret(path, 'fixture-key', async () => 42), 42);
    assert.equal(existsSync(path), false);
    writeFileSync(path, 'existing custody', { mode: 0o600 });
    await assert.rejects(withChatReleaseSecret(path, 'fixture-key', async () => {}));
    assert.equal(readFileSync(path, 'utf8'), 'existing custody');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('release staging has its own protected dispatch identity', () => {
  const env = {
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REF: 'refs/heads/main',
    GITHUB_REPOSITORY: 'masanork/mikaki',
    GITHUB_SHA: source.commit,
    GITHUB_WORKFLOW_REF:
      'masanork/mikaki/.github/workflows/chat-beta-stage-release.yml@refs/heads/main',
  };
  assertChatPreflightContext(env, source, 'release-stage');
  assert.throws(() => assertChatPreflightContext(env, source));
  assert.throws(() => assertChatPreflightContext(env, source, true));
  assert.throws(() =>
    assertChatPreflightContext(
      { ...env, GITHUB_EVENT_NAME: 'pull_request' },
      source,
      'release-stage',
    ),
  );
});

test('missing write confirmations retain known IDs without guessing or retrying', async () => {
  for (const operation of ['upload', 'delete']) {
    const f = fixture();
    if (operation === 'upload') {
      const upload = f.io.upload;
      f.io.upload = async (message) => {
        await upload(message);
        return 'Unconfirmed upload';
      };
    } else {
      const clear = f.io.clearKey;
      f.io.clearKey = async (message) => {
        await clear(message);
        return 'Unconfirmed deletion';
      };
    }
    await assert.rejects(run(f));
    assert.deepEqual(f.writes, operation === 'upload' ? ['upload'] : ['upload', 'delete']);
    assert.equal(f.reports.at(-1)!.version_id, operation === 'upload' ? undefined : id(3));
    assert.equal(f.reports.at(-1)!.clean_tail_version_id, undefined);
    assert.equal(f.reports.at(-1)!.promotion_ready, false);
  }
});
