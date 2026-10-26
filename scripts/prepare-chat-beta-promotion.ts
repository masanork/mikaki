/** Read-only, protected Chat candidate preflight. Never upload, migrate or activate. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { releaseSource, type ReleaseSource } from './release-inventory.ts';
import { promotionDirectory, verifyPreparedUpload } from './prepare-release-upload.ts';
import { checkBindings, sourceIsCurrent } from './deploy-production.ts';
import { checkProductionChatSchema } from './check-production-chat-schema.ts';
import {
  assertMessagingMigrationConfig,
  MESSAGING_MIGRATION_CONFIG,
  MESSAGING_MIGRATIONS,
} from './production-messaging-schema.ts';
import { cloudflareMetadataGet, type MetadataGet } from './production-worker-inventory.ts';
import { PRODUCTION_WORK_TARGET } from './production-work-adoption.ts';

const REPOSITORY = 'masanork/mikaki';
const WORKFLOW = '.github/workflows/chat-beta-preflight.yml';
const KEY_WORKFLOW = '.github/workflows/chat-beta-stage-key.yml';
const RELEASE_WORKFLOW = '.github/workflows/chat-beta-stage-release.yml';
const OP_CONFIG = 'crates/worker/wrangler.production.jsonc';
type Row = Record<string, unknown>;
type GithubGet = (path: string) => Promise<unknown>;
const row = (value: unknown): value is Row =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
function object(value: unknown): Row {
  assert.ok(row(value), 'Missing metadata object');
  return value;
}

export function chatPreflightRunId(value: unknown): number {
  assert.ok(typeof value === 'string' && /^[1-9][0-9]{0,14}$/.test(value), 'Invalid CI run ID');
  const id = Number(value);
  assert.ok(Number.isSafeInteger(id), 'Invalid CI run ID');
  return id;
}

export function assertChatPreflightContext(
  env: NodeJS.ProcessEnv,
  source: ReleaseSource,
  stage: boolean | 'release-stage' = false,
) {
  assert.ok(stage === false || stage === true || stage === 'release-stage');
  assert.equal(env.GITHUB_EVENT_NAME, 'workflow_dispatch');
  assert.equal(env.GITHUB_REF, 'refs/heads/main');
  assert.equal(env.GITHUB_REPOSITORY, REPOSITORY);
  assert.equal(
    env.GITHUB_WORKFLOW_REF,
    `${REPOSITORY}/${stage === true ? KEY_WORKFLOW : stage === 'release-stage' ? RELEASE_WORKFLOW : WORKFLOW}@refs/heads/main`,
  );
  assert.equal(source.commit, env.GITHUB_SHA);
  assert.match(source.commit, /^[a-f0-9]{40}$/);
  assert.equal(source.clean, true, 'Clean source required');
}

/** A PR, fork, manual CI run, incomplete rerun or differently sourced artifact cannot qualify. */
export async function inspectChatCandidate(get: GithubGet, runId: number, source: ReleaseSource) {
  assert.equal(source.clean, true);
  assert.match(source.commit, /^[a-f0-9]{40}$/);
  assert.ok(Number.isSafeInteger(runId) && runId > 0);
  const base = `/repos/${REPOSITORY}/actions/runs/${runId}`;
  const run = object(await get(base));
  assert.equal(run.id, runId);
  const repository = object(run.repository);
  const headRepository = object(run.head_repository);
  assert.equal(repository.full_name, REPOSITORY);
  assert.equal(headRepository.full_name, REPOSITORY);
  assert.ok(Number.isSafeInteger(repository.id) && Number(repository.id) > 0);
  assert.equal(headRepository.id, repository.id);
  assert.equal(run.path, '.github/workflows/ci.yml');
  assert.equal(run.event, 'push');
  assert.equal(run.head_branch, 'main');
  assert.equal(run.head_sha, source.commit);
  assert.equal(run.status, 'completed');
  assert.equal(run.conclusion, 'success');
  assert.ok(Number.isSafeInteger(run.run_attempt) && Number(run.run_attempt) > 0);
  const name = `attested-worker-messaging-beta-${source.commit}`;
  const listing = object(await get(`${base}/artifacts?name=${name}&per_page=100`));
  assert.equal(listing.total_count, 1, 'Exactly one unambiguous beta artifact required');
  assert.ok(Array.isArray(listing.artifacts) && listing.artifacts.length === 1);
  const artifact = object(listing.artifacts[0]);
  assert.equal(artifact.name, name);
  assert.equal(artifact.expired, false);
  assert.ok(Number.isSafeInteger(artifact.id) && Number(artifact.id) > 0);
  assert.ok(typeof artifact.digest === 'string' && /^sha256:[a-f0-9]{64}$/.test(artifact.digest));
  const origin = object(artifact.workflow_run);
  assert.equal(origin.id, runId);
  assert.equal(origin.head_sha, source.commit);
  assert.equal(origin.head_branch, 'main');
  assert.equal(origin.repository_id, repository.id);
  assert.equal(origin.head_repository_id, repository.id);
  return {
    run_id: runId,
    run_attempt: Number(run.run_attempt),
    artifact_id: Number(artifact.id),
    artifact_name: name,
    artifact_digest: artifact.digest,
  };
}

/** Main CI's scanner is advisory; require the actual main analysis and quality gate separately. */
export async function inspectChatQualityGate(get: GithubGet, source: ReleaseSource) {
  const listing = object(
    await get('project_analyses/search?project=masanork_mikaki&branch=main&ps=1'),
  );
  assert.ok(Array.isArray(listing.analyses) && listing.analyses.length === 1);
  const analysis = object(listing.analyses[0]);
  assert.equal(analysis.revision, source.commit, 'Latest main Sonar analysis has another source');
  assert.ok(typeof analysis.key === 'string' && /^[a-f0-9-]{36}$/.test(analysis.key));
  assert.ok(typeof analysis.date === 'string' && Number.isFinite(Date.parse(analysis.date)));
  const gate = object(
    object(await get(`qualitygates/project_status?analysisId=${encodeURIComponent(analysis.key)}`))
      .projectStatus,
  );
  assert.equal(gate.status, 'OK', 'Main Sonar quality gate is not OK');
  return { analysis_id: analysis.key, analysis_date: analysis.date, quality_gate: 'OK' as const };
}

/** Inspect only deployment/version metadata. Secret values and Worker content are never fetched. */
export async function inspectChatDisabledBaseline(
  get: MetadataGet,
  source: ReleaseSource,
  config: Parameters<typeof checkBindings>[1] & { account_id: string },
) {
  assert.match(source.commit, /^[a-f0-9]{40}$/);
  assert.equal(source.clean, true);
  assert.equal(config.account_id, PRODUCTION_WORK_TARGET.account);
  assert.equal(config.name, 'mikaki-auth');
  assert.equal(
    config.d1_databases?.find(({ binding }) => binding === 'DB')?.database_id,
    PRODUCTION_WORK_TARGET.database,
  );
  assert.ok(!Object.keys(config.vars).some((name) => name.startsWith('MESSAGING_')));
  assert.ok(!config.secrets?.required.some((name) => name.startsWith('MESSAGING_')));
  const base = `/accounts/${config.account_id}/workers/scripts/${config.name}`;
  const envelope = object(await get(`${base}/deployments?page=1&per_page=1`));
  assert.equal(envelope.success, true);
  const deployments = object(envelope.result).deployments;
  assert.ok(Array.isArray(deployments) && deployments.length === 1);
  const deployment = object(deployments[0]);
  assert.equal(deployment.strategy, 'percentage');
  assert.ok(Array.isArray(deployment.versions) && deployment.versions.length === 1);
  const version = object(deployment.versions[0]);
  assert.equal(version.percentage, 100);
  assert.ok(
    typeof version.version_id === 'string' &&
      /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(version.version_id),
  );
  const uploaded = object(await get(`${base}/versions/${version.version_id}`));
  assert.equal(uploaded.success, true);
  const details = object(uploaded.result);
  assert.equal(details.id, version.version_id);
  const annotations = object(details.annotations);
  assert.equal(annotations['workers/tag'], source.commit.slice(0, 12));
  assert.equal(annotations['workers/message'], `main CI ${source.commit}`);
  const resources = object(details.resources);
  assert.ok(Array.isArray(resources.bindings));
  const runtime = object(resources.script_runtime);
  assert.ok(typeof runtime.compatibility_date === 'string');
  const flags = runtime.compatibility_flags;
  assert.ok(
    flags === undefined ||
      (Array.isArray(flags) && flags.every((flag) => typeof flag === 'string')),
  );
  // This existing exhaustive checker rejects added Chat flags/keys and any storage drift.
  checkBindings(
    {
      resources: {
        bindings: resources.bindings.map(object),
        script_runtime: {
          compatibility_date: runtime.compatibility_date,
          compatibility_flags: flags,
        },
      },
    },
    config,
  );
  assert.ok(typeof deployment.id === 'string' && /^[a-f0-9-]{36}$/.test(deployment.id));
  return {
    deployment_id: deployment.id,
    version_id: version.version_id,
    chat: 'disabled' as const,
  };
}

export function chatPreflightReport(
  source: ReleaseSource,
  candidate: Awaited<ReturnType<typeof inspectChatCandidate>>,
  baseline: Awaited<ReturnType<typeof inspectChatDisabledBaseline>>,
  quality: Awaited<ReturnType<typeof inspectChatQualityGate>>,
  subjects: { path: string; sha256: string }[],
) {
  return {
    schema: 'mikaki-chat-beta-preflight-v1',
    status: 'passed',
    checked_at: new Date().toISOString(),
    source,
    candidate,
    baseline,
    target: {
      account: PRODUCTION_WORK_TARGET.account,
      worker: 'mikaki-auth',
      database: PRODUCTION_WORK_TARGET.database,
    },
    sonar: quality,
    attested_subjects: subjects,
    candidate_bytes: 'verified',
    production_chat_schema: 'complete',
    messaging_migrations: MESSAGING_MIGRATIONS,
    mutations: false,
    promotion_ready: false,
    remaining: [
      'protected_signing_key_staging_and_public_key_verification',
      'remote_populated_disable_and_code_rollback',
      'physical_passkey_prf_and_two_owner_qualification',
      'protected_beta_activation_path',
    ],
  };
}

async function main() {
  assert.ok(
    process.argv.length === 3 ||
      (process.argv.length === 4 && ['--key-stage', '--release-stage'].includes(process.argv[3]!)),
    'Usage: prepare-chat-beta-promotion.ts <main-ci-run-id> [--key-stage|--release-stage]',
  );
  const runId = chatPreflightRunId(process.argv[2]);
  const root = fileURLToPath(new URL('../', import.meta.url));
  const source = releaseSource(root);
  assertChatPreflightContext(
    process.env,
    source,
    process.argv[3] === '--release-stage' ? 'release-stage' : process.argv[3] === '--key-stage',
  );
  const reportDirectory = join(root, 'artifacts/chat-beta-preflight');
  // Refuse old artifacts/reports rather than treating a previous run as fresh proof.
  assert.equal(existsSync(join(root, 'artifacts')), false, 'Fresh artifact directory required');
  mkdirSync(reportDirectory, { recursive: true, mode: 0o700 });
  const reportPath = join(reportDirectory, 'report.json');
  let stage = 'source_and_ci';
  const save = (value: unknown) =>
    writeFileSync(reportPath, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  const command = (binary: string, args: string[]) =>
    execFileSync(binary, args, {
      cwd: root,
      encoding: 'utf8',
      timeout: 120_000,
      maxBuffer: 4 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  const current = () => {
    command('git', ['fetch', 'origin', 'main']);
    command('git', ['merge-base', '--is-ancestor', source.commit, 'origin/main']);
    const paths = command('git', ['diff', '--name-only', source.commit, 'origin/main']).trim();
    assert.ok(sourceIsCurrent(paths ? paths.split('\n') : []), 'Application source advanced');
    assert.deepEqual(releaseSource(root), source);
  };
  const githubGet: GithubGet = async (path) => JSON.parse(command('gh', ['api', path]));
  try {
    current();
    const candidate = await inspectChatCandidate(githubGet, runId, source);
    stage = 'main_quality_gate';
    const sonarGet: GithubGet = async (path) =>
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
    const quality = await inspectChatQualityGate(sonarGet, source);
    stage = 'candidate_authenticity';
    command('gh', [
      'run',
      'download',
      String(runId),
      '--repo',
      REPOSITORY,
      '--name',
      candidate.artifact_name,
      '--dir',
      'artifacts',
    ]);
    const promotionNames = readdirSync(join(root, 'artifacts')).filter((name) =>
      name.startsWith('promotion-'),
    );
    assert.equal(promotionNames.length, 1);
    const destination = await promotionDirectory(root, join(root, 'artifacts', promotionNames[0]!));
    const subjects = [
      'artifacts/release-manifest.json',
      'artifacts/login-assets.json',
      'artifacts/mikaki-worker.tar.gz',
      'artifacts/mikaki-userinfo-claim-worker.tar.gz',
      'artifacts/mikaki-work-checkpoint.tar.gz',
      `artifacts/${promotionNames[0]}/upload-manifest.json`,
    ];
    const verified = [];
    for (const subject of subjects) {
      command('gh', [
        'attestation',
        'verify',
        subject,
        '--repo',
        REPOSITORY,
        '--signer-workflow',
        `${REPOSITORY}/.github/workflows/supply-chain-build.yml`,
        '--source-digest',
        source.commit,
        '--source-ref',
        'refs/heads/main',
        '--deny-self-hosted-runners',
      ]);
      verified.push({
        path: subject,
        sha256: createHash('sha256')
          .update(readFileSync(join(root, subject)))
          .digest('hex'),
      });
    }
    stage = 'candidate_bytes';
    const manifest = JSON.parse(readFileSync(join(destination, 'upload-manifest.json'), 'utf8'));
    assert.deepEqual(
      manifest.release_inventory,
      JSON.parse(readFileSync(join(root, 'artifacts/release-manifest.json'), 'utf8')),
    );
    const login = JSON.parse(readFileSync(join(root, 'artifacts/login-assets.json'), 'utf8'));
    assert.deepEqual(login.source, source);
    assert.equal(login.profile, 'messaging-beta');
    mkdirSync(join(root, 'assets/chat'), { recursive: true, mode: 0o700 });
    for (const file of ['client.js', 'crypto.wasm'])
      copyFileSync(join(destination, 'op/assets/chat', file), join(root, 'assets/chat', file));
    await verifyPreparedUpload(root, destination, manifest, source, false, 'messaging-beta');
    stage = 'production_baseline';
    const config = JSON.parse(readFileSync(join(root, OP_CONFIG), 'utf8'));
    assertMessagingMigrationConfig(
      JSON.parse(readFileSync(join(root, MESSAGING_MIGRATION_CONFIG), 'utf8')),
      config,
    );
    const get = cloudflareMetadataGet(
      PRODUCTION_WORK_TARGET.account,
      process.env.CLOUDFLARE_API_TOKEN!,
    );
    const baseline = await inspectChatDisabledBaseline(get, source, config);
    stage = 'production_schema';
    const schema = await checkProductionChatSchema(root, async (sql) => {
      const result = JSON.parse(
        command(join(root, 'node_modules/.bin/wrangler'), [
          'd1',
          'execute',
          'mikaki-auth-owner',
          '--remote',
          '--config',
          MESSAGING_MIGRATION_CONFIG,
          '--command',
          sql,
          '--json',
        ]),
      );
      assert.ok(Array.isArray(result) && result.length === 1 && result[0].success === true);
      return result[0].results;
    });
    assert.equal(schema.complete, true, 'All three Chat migrations required');
    stage = 'stability_recheck';
    assert.deepEqual(await inspectChatDisabledBaseline(get, source, config), baseline);
    assert.deepEqual(await inspectChatCandidate(githubGet, runId, source), candidate);
    assert.deepEqual(await inspectChatQualityGate(sonarGet, source), quality);
    current();
    save(chatPreflightReport(source, candidate, baseline, quality, verified));
    console.log(
      'Chat candidate preflight passed. Promotion remains blocked; no production changes made.',
    );
  } catch {
    // Do not serialize assertion diffs, API bodies, subprocess output or binding values.
    save({
      schema: 'mikaki-chat-beta-preflight-v1',
      source,
      checked_at: new Date().toISOString(),
      status: 'failed',
      stage,
      mutations: false,
      promotion_ready: false,
    });
    throw new Error(`Chat preflight failed at ${stage}; no production changes made.`);
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await main();
  } catch {
    console.error('Chat beta preflight failed; inspect its sanitized report.');
    process.exitCode = 1;
  }
}
