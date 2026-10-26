/** Upload an attested Chat release without activating it or changing application data. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkBindings } from './deploy-production.ts';
import { messagingIssuerPublicKey } from './messaging-issuer-key.ts';
import { promotionDirectory, verifyPreparedUpload } from './prepare-release-upload.ts';
import {
  assertChatPreflightContext,
  chatPreflightRunId,
  inspectChatDisabledBaseline,
} from './prepare-chat-beta-promotion.ts';
import { releaseSource, type ReleaseSource } from './release-inventory.ts';
import { type MetadataGet } from './production-worker-inventory.ts';
import { PRODUCTION_WORK_TARGET } from './production-work-adoption.ts';
import { uploadedVersionView } from './production-wrangler.ts';
import { assertChatStageStable, assertKeyClone, chatStageContext } from './stage-chat-beta-key.ts';

const CONFIG = 'crates/worker/wrangler.production.jsonc';
const KEY = 'MESSAGING_ISSUER_KEY';
const FLAG = 'MESSAGING_BETA_ENABLED';
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
type Row = Record<string, unknown>;
type Config = Parameters<typeof inspectChatDisabledBaseline>[2];
type Baseline = Awaited<ReturnType<typeof inspectChatDisabledBaseline>>;
type Version = Parameters<typeof checkBindings>[0] & {
  id: string;
  annotations: Row;
  resources: { script: { etag: string } };
};
type StageIO = {
  get: MetadataGet;
  current(): Promise<void>;
  verifyBytes(): Promise<void>;
  version(id: string): Promise<Version>;
  upload(message: string): string | Promise<string>;
  clearKey(message: string): string | Promise<string>;
  save(report: Row): void;
};
export async function withChatReleaseSecret<T>(
  path: string,
  raw: string,
  action: () => Promise<T>,
) {
  writeFileSync(path, JSON.stringify({ [KEY]: raw }), { flag: 'wx', mode: 0o600 });
  try {
    return await action();
  } finally {
    rmSync(path);
  }
}

/** Preserve every reviewed binding; only the explicit beta flag and required key differ. */
export function chatReleaseConfig(config: Config) {
  assert.equal(config.name, 'mikaki-auth');
  assert.equal(config.account_id, PRODUCTION_WORK_TARGET.account);
  assert.ok(!('build' in config), 'Staging cannot run a build command');
  assert.ok(!(FLAG in config.vars) && !(KEY in config.vars));
  assert.ok(config.secrets && !config.secrets.required.includes(KEY));
  return {
    ...config,
    workers_dev: false,
    preview_urls: false,
    vars: { ...config.vars, [FLAG]: 'true' },
    secrets: { ...config.secrets, required: [...config.secrets.required, KEY] },
  };
}

function annotations(version: Version, source: ReleaseSource, message: string) {
  assert.match(version.id, uuid);
  assert.equal(version.annotations['workers/tag'], `chat-beta-${source.commit.slice(0, 12)}`);
  assert.equal(version.annotations['workers/message'], message);
  assert.match(version.resources.script.etag, /^[a-f0-9]{32,128}$/);
}

export function assertChatReleaseVersion(
  version: Version,
  original: Version,
  config: Config,
  source: ReleaseSource,
  message: string,
) {
  annotations(version, source, message);
  assert.notEqual(version.id, original.id);
  assert.notEqual(version.resources.script.etag, original.resources.script.etag);
  checkBindings(version, chatReleaseConfig(config));
  const order = (a: Row, b: Row) => String(a.name).localeCompare(String(b.name));
  assert.deepEqual(
    version.resources.bindings
      .filter((b) => b.type !== 'assets' && b.name !== FLAG && b.name !== KEY)
      .sort(order),
    original.resources.bindings.filter((b) => b.type !== 'assets').sort(order),
    'Existing data and authority bindings must retain their exact identities',
  );
}

export function assertChatReleaseTail(
  tail: Version,
  staged: Version,
  source: ReleaseSource,
  message: string,
) {
  const keyFree = {
    ...staged,
    resources: {
      ...staged.resources,
      bindings: staged.resources.bindings.filter((b) => b.name !== KEY),
    },
  };
  assertKeyClone(tail, keyFree, message, source, false, 'chat-beta');
}

/** Exactly one upload and one key deletion. Ambiguous writes require operator inspection. */
export async function stageChatRelease(
  source: ReleaseSource,
  config: Config,
  baseline: Baseline,
  raw: string,
  expectedPublicKey: string,
  io: StageIO,
) {
  const report: Row = {
    schema: 'mikaki-chat-release-stage-v1',
    source,
    baseline,
    status: 'failed',
    stage: 'custody_and_artifacts',
    writes_attempted: false,
    active_change_requested: false,
    promotion_ready: false,
    remote_public_key_verified: false,
    remote_runtime_profile_verified: false,
  };
  try {
    assert.equal(source.clean, true);
    assert.match(source.commit, /^[a-f0-9]{40}$/);
    assert.match(baseline.version_id, uuid);
    chatReleaseConfig(config);
    report.key = messagingIssuerPublicKey(raw, expectedPublicKey);
    await io.verifyBytes();
    const stable = (latestId: string) =>
      assertChatStageStable(source, config, baseline, latestId, io);
    report.stage = 'baseline';
    await stable(baseline.version_id);
    const original = await io.version(baseline.version_id);
    assert.equal(original.id, baseline.version_id);
    assert.match(original.resources.script.etag, /^[a-f0-9]{32,128}$/);
    await io.verifyBytes();
    await stable(baseline.version_id);
    report.stage = 'upload';
    report.writes_attempted = true;
    io.save({ ...report });
    const message = `Chat beta stage ${source.commit}`;
    const output = await io.upload(message);
    const id = /Worker Version ID:\s*([a-f0-9-]{36})/.exec(output)?.[1];
    assert.ok(id && uuid.test(id), 'Unconfirmed upload; inspect before retrying');
    report.version_id = id;
    report.stage = 'inspect_uploaded';
    io.save({ ...report });
    const staged = await io.version(id);
    assert.equal(staged.id, id);
    assertChatReleaseVersion(staged, original, config, source, message);
    report.script_etag = staged.resources.script.etag;
    await stable(id);
    report.stage = 'clear_inheritance_tail';
    io.save({ ...report });
    const tailMessage = `Chat beta key-free tail ${source.commit}`;
    const cleared = await io.clearKey(tailMessage);
    const tailId =
      /Created version ([a-f0-9-]{36}) with 0 secrets? created and 1 secrets? deleted\./.exec(
        cleared,
      )?.[1];
    assert.ok(tailId && uuid.test(tailId), 'Unconfirmed key removal; inspect before retrying');
    report.clean_tail_version_id = tailId;
    report.stage = 'inspect_tail';
    io.save({ ...report });
    const tail = await io.version(tailId);
    assert.equal(tail.id, tailId);
    assertChatReleaseTail(tail, staged, source, tailMessage);
    await stable(tailId);
    report.status = 'passed';
    report.stage = 'complete';
    report.checked_at = new Date().toISOString();
    report.remaining = [
      'remote_public_key_and_runtime_profile_verification',
      'remote_populated_disable_and_code_rollback',
      'physical_passkey_prf_and_two_owner_qualification',
      'protected_beta_activation_path',
    ];
    io.save({ ...report });
    return report;
  } catch {
    report.status = 'failed';
    io.save({ ...report });
    throw new Error('Chat release staging failed; inspect the sanitized report before retrying.');
  }
}

async function main() {
  assert.equal(process.argv.length, 3);
  const raw = process.env.MESSAGING_ISSUER_KEY ?? '';
  delete process.env.MESSAGING_ISSUER_KEY;
  const runId = chatPreflightRunId(process.argv[2]);
  const root = fileURLToPath(new URL('../', import.meta.url));
  const source = releaseSource(root);
  assertChatPreflightContext(process.env, source, 'release-stage');
  const directory = join(root, 'artifacts/chat-release-stage');
  const reportPath = join(directory, 'report.json');
  assert.equal(existsSync(directory), false, 'Fresh stage directory required');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeFileSync(
    reportPath,
    JSON.stringify({
      schema: 'mikaki-chat-release-stage-v1',
      source,
      status: 'failed',
      stage: 'preflight',
      writes_attempted: false,
      active_change_requested: false,
      promotion_ready: false,
      remote_public_key_verified: false,
      remote_runtime_profile_verified: false,
    }),
    { mode: 0o600, flag: 'wx' },
  );
  const expected = process.env.EXPECTED_CHAT_PUBLIC_KEY ?? '';
  messagingIssuerPublicKey(raw, expected);
  const preflight = JSON.parse(
    readFileSync(join(root, 'artifacts/chat-beta-preflight/report.json'), 'utf8'),
  );
  const { config, get, current, fresh, wrangler } = chatStageContext(
    root,
    source,
    runId,
    preflight,
  );
  const names = readdirSync(join(root, 'artifacts')).filter((name) =>
    name.startsWith('promotion-'),
  );
  assert.equal(names.length, 1);
  const destination = await promotionDirectory(root, join(root, 'artifacts', names[0]!));
  const manifestBytes = readFileSync(join(destination, 'upload-manifest.json'));
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const provenance = {
    main_ci_run_id: runId,
    candidate: preflight.candidate,
    attested_subjects: preflight.attested_subjects,
    prepared_upload_manifest_sha256: createHash('sha256').update(manifestBytes).digest('hex'),
  };
  const stagedConfig = {
    ...chatReleaseConfig(config),
    main: join(destination, 'op/bundle/service.js'),
    assets: { ...config.assets, directory: join(destination, 'op/assets') },
  };
  const configPath = join(directory, 'wrangler.json');
  writeFileSync(configPath, JSON.stringify(stagedConfig), { flag: 'wx', mode: 0o600 });
  const secretPath = join(directory, 'secrets.json');
  const tag = `chat-beta-${source.commit.slice(0, 12)}`;
  await withChatReleaseSecret(secretPath, raw, async () => {
    await stageChatRelease(source, config, preflight.baseline, raw, expected, {
      get,
      current,
      verifyBytes: async () => {
        fresh();
        await verifyPreparedUpload(root, destination, manifest, source, false, 'messaging-beta');
      },
      version: async (id) => JSON.parse(await uploadedVersionView(id, CONFIG, wrangler)),
      upload: (message) =>
        wrangler([
          'versions',
          'upload',
          stagedConfig.main,
          '--no-bundle',
          '--config',
          configPath,
          '--assets',
          stagedConfig.assets.directory,
          '--secrets-file',
          secretPath,
          '--tag',
          tag,
          '--message',
          message,
        ]),
      clearKey: (message) =>
        wrangler(
          ['versions', 'secret', 'bulk', '--config', CONFIG, '--tag', tag, '--message', message],
          JSON.stringify({ [KEY]: null }),
        ),
      save: (report) =>
        writeFileSync(reportPath, JSON.stringify({ ...report, ...provenance }, null, 2) + '\n', {
          mode: 0o600,
        }),
    });
  });
  console.log('Chat release staged with a key-free inheritance tail; active deployment unchanged.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await main();
  } catch {
    console.error('Chat release stage failed; inspect its sanitized report before retrying.');
    process.exitCode = 1;
  }
}
