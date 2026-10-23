import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  assertChatPreflightContext,
  chatPreflightReport,
  chatPreflightRunId,
  inspectChatCandidate,
  inspectChatDisabledBaseline,
  inspectChatQualityGate,
} from './prepare-chat-beta-promotion.ts';
import { PRODUCTION_WORK_TARGET } from './production-work-adoption.ts';

const source = { commit: 'a'.repeat(40), clean: true };
const runId = 39709189220;
const versionId = '00000000-0000-4000-8000-000000000001';
const deploymentId = '00000000-0000-4000-8000-000000000002';
const repository = { full_name: 'masanork/mikaki', id: 1382561545 };

test('key staging uses its own exact main workflow identity, never a generic override', () => {
  const env = {
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REF: 'refs/heads/main',
    GITHUB_REPOSITORY: 'masanork/mikaki',
    GITHUB_SHA: source.commit,
    GITHUB_WORKFLOW_REF:
      'masanork/mikaki/.github/workflows/chat-beta-stage-key.yml@refs/heads/main',
  };
  assertChatPreflightContext(env, source, true);
  assert.throws(() => assertChatPreflightContext(env, source));
  assert.throws(() =>
    assertChatPreflightContext({ ...env, GITHUB_EVENT_NAME: 'pull_request' }, source, true),
  );
  assert.throws(() =>
    assertChatPreflightContext(
      { ...env, GITHUB_WORKFLOW_REF: env.GITHUB_WORKFLOW_REF.replace('main', 'feature') },
      source,
      true,
    ),
  );
});
function candidateFixture() {
  const run = {
    id: runId,
    repository,
    head_repository: repository,
    path: '.github/workflows/ci.yml',
    event: 'push',
    head_branch: 'main',
    head_sha: source.commit,
    status: 'completed',
    conclusion: 'success',
    run_attempt: 2,
  };
  const artifact = {
    id: 12399964039,
    name: `attested-worker-messaging-beta-${source.commit}`,
    digest: `sha256:${'b'.repeat(64)}`,
    expired: false,
    workflow_run: {
      id: runId,
      head_sha: source.commit,
      head_branch: 'main',
      repository_id: repository.id,
      head_repository_id: repository.id,
    },
  };
  const listing = { total_count: 1, artifacts: [artifact] };
  const paths: string[] = [];
  const get = async (path: string) => {
    paths.push(path);
    const base = `/repos/masanork/mikaki/actions/runs/${runId}`;
    if (path === base) return run;
    assert.equal(path, `${base}/artifacts?name=${artifact.name}&per_page=100`);
    return listing;
  };
  return { run, artifact, listing, get, paths };
}

test('dispatch inputs cannot select a shell option, fork, PR workflow or dirty checkout', () => {
  assert.equal(chatPreflightRunId(String(runId)), runId);
  for (const value of [undefined, '', '01', '0', '-1', '1; true', '--help', '9007199254740992', 1])
    assert.throws(() => chatPreflightRunId(value));
  const context = {
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REF: 'refs/heads/main',
    GITHUB_REPOSITORY: repository.full_name,
    GITHUB_SHA: source.commit,
    GITHUB_WORKFLOW_REF:
      'masanork/mikaki/.github/workflows/chat-beta-preflight.yml@refs/heads/main',
  };
  assertChatPreflightContext(context, source);
  for (const [name, value] of Object.entries({
    GITHUB_EVENT_NAME: 'pull_request_target',
    GITHUB_REF: 'refs/heads/feature',
    GITHUB_REPOSITORY: 'fork/mikaki',
    GITHUB_SHA: 'b'.repeat(40),
    GITHUB_WORKFLOW_REF: 'masanork/mikaki/.github/workflows/other.yml@refs/heads/main',
  }))
    assert.throws(() => assertChatPreflightContext({ ...context, [name]: value }, source));
  assert.throws(() => assertChatPreflightContext(context, { ...source, clean: false }));
});

test('successful main CI selects one source-bound, unexpired attested beta artifact', async () => {
  const f = candidateFixture();
  const candidate = await inspectChatCandidate(f.get, runId, source);
  assert.equal(candidate.run_attempt, 2);
  assert.equal(candidate.artifact_id, f.artifact.id);
  assert.equal(candidate.artifact_digest, f.artifact.digest);
  assert.equal(f.paths.length, 2);
});

test('PRs, forks, wrong workflows, stale sources and reruns in progress fail before artifact access', async () => {
  const invalid = {
    id: runId + 1,
    path: '.github/workflows/other.yml',
    event: 'pull_request',
    head_branch: 'feature',
    head_sha: 'b'.repeat(40),
    status: 'in_progress',
    conclusion: 'failure',
    run_attempt: 0,
    repository: { ...repository, full_name: 'fork/mikaki' },
    head_repository: { ...repository, id: repository.id + 1 },
  };
  for (const [name, value] of Object.entries(invalid)) {
    const f = candidateFixture();
    Object.assign(f.run, { [name]: value });
    await assert.rejects(inspectChatCandidate(f.get, runId, source));
    assert.equal(f.paths.length, 1);
  }
});

test('missing, duplicate, expired, malformed-digest or mismatched-origin artifacts are rejected', async () => {
  for (const [name, value] of Object.entries({
    name: 'attested-worker-default',
    id: 0,
    digest: 'missing',
    expired: true,
    workflow_run: { id: runId + 1 },
  })) {
    const f = candidateFixture();
    Object.assign(f.artifact, { [name]: value });
    // Keep the endpoint fixed even when the returned artifact name is malicious.
    await assert.rejects(
      inspectChatCandidate(
        async (path) => (path.includes('/artifacts?') ? f.listing : f.run),
        runId,
        source,
      ),
    );
  }
  for (const count of [0, 2, 101]) {
    const f = candidateFixture();
    f.listing.total_count = count;
    await assert.rejects(inspectChatCandidate(f.get, runId, source));
  }
  for (const [name, value] of Object.entries({
    head_sha: 'b'.repeat(40),
    head_branch: 'feature',
    repository_id: 1,
    head_repository_id: 1,
  })) {
    const f = candidateFixture();
    Object.assign(f.artifact.workflow_run, { [name]: value });
    await assert.rejects(inspectChatCandidate(f.get, runId, source));
  }
});

test('quality gate must be OK for the latest exact-source main analysis, independent of CI success', async () => {
  const analysis = { key: versionId, date: '2026-10-22T10:00:00+0000', revision: source.commit };
  const listing = { analyses: [analysis] };
  const status = { projectStatus: { status: 'OK' } };
  const get = async (path: string) => {
    if (path === 'project_analyses/search?project=masanork_mikaki&branch=main&ps=1') return listing;
    assert.equal(path, `qualitygates/project_status?analysisId=${versionId}`);
    return status;
  };
  assert.equal((await inspectChatQualityGate(get, source)).quality_gate, 'OK');
  for (const invalid of ['ERROR', 'NONE', 'WARN', '']) {
    status.projectStatus.status = invalid;
    await assert.rejects(inspectChatQualityGate(get, source));
  }
  status.projectStatus.status = 'OK';
  analysis.revision = 'b'.repeat(40);
  await assert.rejects(inspectChatQualityGate(get, source));
  analysis.revision = source.commit;
  analysis.key = 'other?analysisId=untrusted';
  await assert.rejects(inspectChatQualityGate(get, source));
  listing.analyses = [];
  await assert.rejects(inspectChatQualityGate(get, source));
});

function baselineFixture() {
  const production = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
  const config = {
    account_id: String(PRODUCTION_WORK_TARGET.account),
    name: 'mikaki-auth',
    compatibility_date: '2026-09-23',
    compatibility_flags: ['nodejs_compat'],
    vars: { ISSUER: 'https://auth.mikaki.org' },
    secrets: { required: ['OP_PRIVATE_JWK'] },
    d1_databases: [{ binding: 'DB', database_id: PRODUCTION_WORK_TARGET.database }],
    queues: production.queues,
  };
  const deployment = {
    id: deploymentId,
    strategy: 'percentage',
    versions: [{ version_id: versionId, percentage: 100 }],
  };
  const version = {
    id: versionId,
    annotations: {
      'workers/tag': source.commit.slice(0, 12),
      'workers/message': `main CI ${source.commit}`,
    },
    resources: {
      script_runtime: {
        compatibility_date: config.compatibility_date,
        compatibility_flags: config.compatibility_flags,
      },
      bindings: [
        { name: 'DB', type: 'd1', database_id: String(PRODUCTION_WORK_TARGET.database) },
        { name: 'ISSUER', type: 'plain_text', text: config.vars.ISSUER },
        { name: 'OP_PRIVATE_JWK', type: 'secret_text' },
        { name: 'LOGOUT_QUEUE', type: 'queue', queue_name: 'mikaki-logout-wakeups' },
      ],
    },
  };
  const paths: string[] = [];
  const get = async (path: string) => {
    paths.push(path);
    const base = `/accounts/${PRODUCTION_WORK_TARGET.account}/workers/scripts/mikaki-auth`;
    if (path === `${base}/deployments?page=1&per_page=1`)
      return { success: true, result: { deployments: [deployment] } };
    assert.equal(path, `${base}/versions/${versionId}`);
    return { success: true, result: version };
  };
  return { config, deployment, version, get, paths };
}

test('disabled baseline retains the qualified 100% version without reading secret values', async () => {
  const f = baselineFixture();
  assert.deepEqual(await inspectChatDisabledBaseline(f.get, source, f.config), {
    deployment_id: deploymentId,
    version_id: versionId,
    chat: 'disabled',
  });
  assert.equal(f.paths.length, 2);
  assert.ok(f.paths.every((path) => !/secrets|content|settings/.test(path)));
});

test('split traffic, unexpected keys/flags, D1 substitutions and different live source fail closed', async () => {
  const changes = [
    (f: ReturnType<typeof baselineFixture>) => {
      f.deployment.versions[0]!.percentage = 99;
    },
    (f: ReturnType<typeof baselineFixture>) => {
      f.deployment.versions.push({ version_id: deploymentId, percentage: 1 });
    },
    (f: ReturnType<typeof baselineFixture>) => {
      f.version.annotations['workers/message'] = 'different';
    },
    (f: ReturnType<typeof baselineFixture>) => {
      f.version.id = deploymentId;
    },
    (f: ReturnType<typeof baselineFixture>) => {
      f.version.resources.bindings[0]!.database_id = deploymentId;
    },
    (f: ReturnType<typeof baselineFixture>) => {
      f.version.resources.bindings.push({ name: 'MESSAGING_ISSUER_KEY', type: 'secret_text' });
    },
    (f: ReturnType<typeof baselineFixture>) => {
      f.version.resources.bindings.push({
        name: 'MESSAGING_BETA_ENABLED',
        type: 'plain_text',
        text: 'true',
      });
    },
    (f: ReturnType<typeof baselineFixture>) => {
      f.config.account_id = 'b'.repeat(32);
    },
  ];
  for (const change of changes) {
    const f = baselineFixture();
    change(f);
    await assert.rejects(inspectChatDisabledBaseline(f.get, source, f.config));
  }
});

test('passing preflight cannot be mistaken for activation permission or remote/device evidence', async () => {
  const candidate = await inspectChatCandidate(candidateFixture().get, runId, source);
  const f = baselineFixture();
  const baseline = await inspectChatDisabledBaseline(f.get, source, f.config);
  const report = chatPreflightReport(
    source,
    candidate,
    baseline,
    {
      analysis_id: versionId,
      analysis_date: '2026-10-22T10:00:00Z',
      quality_gate: 'OK',
    },
    [],
  );
  assert.equal(report.promotion_ready, false);
  assert.equal(report.mutations, false);
  assert.ok(report.remaining.includes('remote_populated_disable_and_code_rollback'));
  assert.ok(report.remaining.includes('physical_passkey_prf_and_two_owner_qualification'));
  assert.ok(report.remaining.includes('protected_signing_key_staging_and_public_key_verification'));
  assert.equal(JSON.stringify(report).includes('OP_PRIVATE_JWK'), false);
});
