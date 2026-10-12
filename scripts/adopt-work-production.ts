/** Fixed-target, journaled production adoption. Inspect never retries either enrollment. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdir, open, readFile, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getPlatformProxy } from 'wrangler';
import type { D1Database } from '@cloudflare/workers-types';
import { OWNER_MIGRATIONS } from './production-owner-schema.ts';
import { WORK_MIGRATIONS } from './production-work-schema.ts';
import {
  productionWorkMigrationStore,
  previewProductionWorkSnapshot,
} from './production-work-migration.ts';
import {
  captureProductionWorkSnapshot,
  captureProductionOwnerSnapshot,
  productionBootstrapStore,
  productionWorkInitialTip,
  PRODUCTION_WORK_TARGET,
  releaseProductionWorkFence,
  validateProductionBootstrapPlan,
} from './production-work-adoption.ts';
import {
  bootstrapAuthorityForScope,
  bootstrapRpcData,
  inspectBootstrapForScope,
  type BootstrapIO,
  type PrimarySnapshot,
} from './work-authority-bootstrap.ts';
import type {
  BootstrapInspection,
  BootstrapPlan,
} from '../crates/work-checkpoint-worker/bootstrap.ts';
import { productionWorkPacketDigest } from './production-work-packet.ts';
import {
  assertWorkAdministrationPolicy,
  PRODUCTION_WORK_ADMINISTRATION,
} from './work-administration-policy.ts';
import { cloudflareMetadataGet } from './production-worker-inventory.ts';
import { releaseSource } from './release-inventory.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const journalDirectory =
  '/Users/masanork/repo/mikaki/local/generated/work-production-activation-v1';
const sha256 = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
async function privateWrite(directory: string, name: string, value: unknown) {
  const file = await open(
    join(directory, name),
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await file.writeFile(JSON.stringify(value) + '\n');
    await file.sync();
  } finally {
    await file.close();
  }
  const parent = await open(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    await parent.sync();
  } finally {
    await parent.close();
  }
}
export function productionWorkOperatorConfig() {
  return {
    name: 'mikaki-production-work-local-operator',
    account_id: PRODUCTION_WORK_TARGET.account,
    compatibility_date: '2026-10-11',
    workers_dev: false,
    preview_urls: false,
    d1_databases: [
      {
        binding: 'DB',
        database_name: 'mikaki-auth-owner',
        database_id: PRODUCTION_WORK_TARGET.database,
        remote: true,
      },
    ],
    services: [
      {
        binding: 'CHECKPOINT_BOOTSTRAP',
        service: PRODUCTION_WORK_TARGET.checkpoint,
        entrypoint: 'WorkCheckpointBootstrap',
        remote: true,
      },
    ],
  };
}
async function main() {
  const [mode, runValue, directoryValue] = process.argv.slice(2);
  assert.ok(
    ['inspect', 'adopt', 'open-unenrolled'].includes(mode ?? '') &&
      /^\d{1,14}$/.test(runValue ?? '') &&
      directoryValue &&
      process.argv.length === 5,
    'Usage: adopt-work-production.ts inspect|adopt|open-unenrolled <successful-main-run-id> <release-directory>',
  );
  const release = resolve(directoryValue);
  assert.equal(await realpath(release), release, 'Production release symlinks denied');
  const gh = (args: string[]) =>
    execFileSync('gh', args, {
      cwd: root,
      encoding: 'utf8',
      maxBuffer: 2_000_000,
      timeout: 60_000,
    });
  const run = JSON.parse(gh(['api', `repos/masanork/mikaki/actions/runs/${runValue}`]));
  assert.ok(
    run.status === 'completed' &&
      run.conclusion === 'success' &&
      run.head_branch === 'main' &&
      run.event === 'push',
    'A successful full main qualification is required',
  );
  const deployment = JSON.parse(
    await readFile(join(release, 'production-deployment.json'), 'utf8'),
  );
  assert.deepEqual(deployment.source, { commit: run.head_sha, clean: true });
  assert.deepEqual(
    releaseSource(root),
    deployment.source,
    'Adoption must execute the exact clean qualified source',
  );
  const cp = deployment.workers.checkpoint;
  assert.ok(
    cp?.activated &&
      /^[a-f0-9-]{36}$/.test(cp.version_id) &&
      /^[a-f0-9]{32}$/.test(cp.namespace_id),
  );
  // The downloaded archive has workflow/source provenance, not merely a local digest.
  gh([
    'attestation',
    'verify',
    join(release, 'mikaki-work-checkpoint.tar.gz'),
    '-R',
    'masanork/mikaki',
    '--signer-workflow',
    'masanork/mikaki/.github/workflows/supply-chain-build.yml',
    '--source-digest',
    run.head_sha,
    '--source-ref',
    'refs/heads/main',
    '--deny-self-hosted-runners',
  ]);
  const token = process.env.CLOUDFLARE_API_TOKEN;
  assert.ok(token, 'Production credentials unavailable');
  const get = cloudflareMetadataGet(PRODUCTION_WORK_TARGET.account, token);
  const prefix = `/accounts/${PRODUCTION_WORK_TARGET.account}/workers/scripts/${PRODUCTION_WORK_TARGET.checkpoint}`;
  const versions = (await get(prefix + '/deployments?page=1&per_page=1')) as {
    result: { deployments: { versions: { version_id: string; percentage: number }[] }[] };
  };
  const live = versions.result.deployments[0]?.versions;
  assert.deepEqual(
    live,
    [{ version_id: cp.version_id, percentage: 100 }],
    'Checkpoint version changed since qualification',
  );
  const metadata = (await get(prefix + '/versions/' + cp.version_id)) as {
    result: {
      resources: {
        bindings: { name: string; type: string; namespace_id?: string; text?: string }[];
      };
    };
  };
  const bindings = metadata.result.resources.bindings;
  assert.equal(bindings.find(({ name }) => name === 'CHECKPOINTS')?.namespace_id, cp.namespace_id);
  assert.equal(
    bindings.find(({ name }) => name === 'WORK_AUTHORITY_ID')?.text,
    PRODUCTION_WORK_TARGET.authority,
  );
  assert.equal(
    bindings.find(({ name }) => name === 'WORK_BOOTSTRAP_PACKET_SHA256')?.text,
    productionWorkPacketDigest(),
  );
  const owner = await Promise.all(
    OWNER_MIGRATIONS.map(async ({ name }) => ({
      name,
      sql: await readFile(join(root, 'crates/worker/migrations', name), 'utf8'),
    })),
  );
  const work = await Promise.all(
    WORK_MIGRATIONS.map(async ({ name }) => ({
      name,
      sql: await readFile(join(root, 'crates/worker/work-migrations', name), 'utf8'),
    })),
  );
  const operator = 'current-cloudflare-credential';
  const administration = assertWorkAdministrationPolicy(PRODUCTION_WORK_ADMINISTRATION, {
    primary: operator,
    checkpoint: operator,
  });
  if (mode === 'adopt') {
    // Global fixed authority reservation: a different checkout cannot remint a journal.
    await mkdir(journalDirectory, { mode: 0o700 });
    assert.equal(
      await realpath(journalDirectory),
      journalDirectory,
      'Production journal symlinks denied',
    );
    await privateWrite(journalDirectory, 'selection.json', {
      source: run.head_sha,
      run_id: Number(runValue),
      target: PRODUCTION_WORK_TARGET,
      checkpoint: cp,
      administration,
    });
    await privateWrite(journalDirectory, 'operator.json', productionWorkOperatorConfig());
  } else {
    assert.equal(await realpath(journalDirectory), journalDirectory);
  }
  const platform = await getPlatformProxy<{
    DB: D1Database;
    CHECKPOINT_BOOTSTRAP: BootstrapIO['checkpoint'];
  }>({ configPath: join(journalDirectory, 'operator.json'), remoteBindings: true });
  try {
    const { DB, CHECKPOINT_BOOTSTRAP: checkpoint } = platform.env;
    const migration = productionWorkMigrationStore(DB, owner, work);
    const current = await migration.inspect();
    if (mode === 'open-unenrolled') {
      const events = (await readFile(join(journalDirectory, 'events.jsonl'), 'utf8'))
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      assert.ok(
        !events.some(({ event }) => event === 'checkpoint-intent'),
        'Checkpoint write was attempted; absence cannot authorize reopening',
      );
      const cpState = (await bootstrapRpcData(checkpoint.inspect())) as BootstrapInspection;
      assert.ok(
        cpState.state === null && cpState.enrollment === null && cpState.ledger_entries === 0,
        'An initialized checkpoint cannot be reopened this way',
      );
      await privateWrite(journalDirectory, 'unenrolled-open-intent.json', {
        source: run.head_sha,
        checkpoint: cp,
        action: 'open-existing-unenrolled-fence-no-enrollment-or-migration-replay',
      });
      await migration.openUnenrolledFence();
      await privateWrite(journalDirectory, 'unenrolled-open-acknowledged.json', {
        phase: (await migration.inspect()).phase,
      });
      console.log(JSON.stringify({ writers_opened: true, enrolled: false, work_enabled: false }));
      return;
    }
    if (mode === 'inspect') {
      const checkpointState = (await bootstrapRpcData(checkpoint.inspect())) as BootstrapInspection;
      const marker =
        current.phase === 'owner'
          ? null
          : await DB.prepare(
              'SELECT authority,epoch,sequence,tip FROM work_authority_checkpoint WHERE id=1',
            ).first();
      console.log(
        JSON.stringify({
          target: PRODUCTION_WORK_TARGET,
          phase: current.phase,
          marker,
          checkpoint: checkpointState.state,
          enrolled: checkpointState.enrollment !== null,
          administration,
        }),
      );
      return;
    }
    const log = await open(join(journalDirectory, 'events.jsonl'), 'wx', 0o600);
    const record = async (event: Record<string, unknown>) => {
      await log.writeFile(
        JSON.stringify({ recorded_at: new Date().toISOString(), ...event }) + '\n',
      );
      await log.sync();
    };
    try {
      assert.equal(current.phase, 'owner', 'Only an unattempted Owner target can enter adoption');
      const pristine = (await bootstrapRpcData(checkpoint.inspect())) as BootstrapInspection;
      assert.equal(pristine.authority, PRODUCTION_WORK_TARGET.authority);
      assert.ok(
        pristine.enrollment === null && pristine.state === null && pristine.ledger_entries === 0,
        'Checkpoint already used',
      );
      // Refuse overlarge owner data before closing ordinary writers.
      const ownerSnapshot = await captureProductionOwnerSnapshot(DB, owner);
      const preview = previewProductionWorkSnapshot(ownerSnapshot, owner, work);
      // Compile the actual SQL and snapshot bounds without performing provider I/O.
      productionBootstrapStore(DB, preview, owner, work, { fenced: true });
      await record({ event: 'migration-intent' });
      await migration.apply();
      await record({ event: 'migration-acknowledged', writers_closed: true });
      const snapshot = await captureProductionWorkSnapshot(DB, owner, work, { fenced: true });
      await privateWrite(journalDirectory, 'snapshot.json', snapshot);
      const inventory = {
        source: run.head_sha,
        target: PRODUCTION_WORK_TARGET,
        checkpoint: cp,
        object_id: pristine.object_id,
      };
      await privateWrite(journalDirectory, 'ownership.json', {
        administration,
        operator,
        inventory,
        independent_operator: false,
        privileged_control_plane_outside_guarantee: true,
      });
      await privateWrite(journalDirectory, 'quiescence.json', {
        mechanism: 'exact-application-table-write-triggers',
        snapshot_sha256: productionWorkInitialTip(snapshot),
        excluded: [
          'privileged-ddl-and-direct-operator-sql',
          'atomic_guard',
          'work_authority_checkpoint',
          'provider-runtime-metadata',
        ],
      });
      const plan: BootstrapPlan = {
        format_version: 1,
        packet_sha256: productionWorkPacketDigest(),
        allocation_sha256: sha256(inventory),
        ownership_review_sha256: sha256(
          JSON.parse(await readFile(join(journalDirectory, 'ownership.json'), 'utf8')),
        ),
        quiescence_review_sha256: sha256(
          JSON.parse(await readFile(join(journalDirectory, 'quiescence.json'), 'utf8')),
        ),
        account_id: PRODUCTION_WORK_TARGET.account,
        database_id: PRODUCTION_WORK_TARGET.database,
        checkpoint_namespace_id: cp.namespace_id,
        checkpoint_object_id: pristine.object_id,
        checkpoint_version_id: cp.version_id,
        initial: {
          authority: PRODUCTION_WORK_TARGET.authority,
          epoch: randomBytes(32).toString('hex'),
          sequence: 0,
          tip: productionWorkInitialTip(snapshot),
        },
        release_floor: 1,
      };
      await privateWrite(journalDirectory, 'plan.json', plan);
      const primary = productionBootstrapStore(DB, snapshot, owner, work, { fenced: true });
      const validate = (value: unknown): asserts value is BootstrapPlan =>
        validateProductionBootstrapPlan(value, snapshot);
      await bootstrapAuthorityForScope(plan, { checkpoint, primary, record }, validate);
      await record({ event: 'fence-open-intent' });
      await releaseProductionWorkFence(DB, snapshot, plan, owner, work, checkpoint);
      await record({ event: 'fence-open-acknowledged', phase: (await migration.inspect()).phase });
      console.log(
        JSON.stringify({
          adopted: true,
          work_enabled: false,
          target: PRODUCTION_WORK_TARGET,
          journal: journalDirectory,
        }),
      );
    } catch {
      await record({ event: 'stopped', recovery: 'inspect-same-identities-no-write-replay' });
      throw new Error('Production adoption stopped; inspect the retained journal without replay');
    } finally {
      await log.close();
    }
  } finally {
    await platform.dispose();
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
