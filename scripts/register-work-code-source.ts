/** Fixed production metadata registration. No Artifacts/provider writes or owner consent. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { constants } from 'node:fs';
import { mkdir, open } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getPlatformProxy } from 'wrangler';
import type { D1Database, Fetcher } from '@cloudflare/workers-types';
import { PRODUCTION_WORK_TARGET } from './production-work-adoption.ts';
import { releaseSource } from './release-inventory.ts';
import { cloudflareMetadataGet } from './production-worker-inventory.ts';
import { verifyWorkCodeSource } from './prepare-work-code-source.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const opName = 'mikaki-auth';
const journal =
  '/Users/masanork/repo/mikaki/local/generated/work-production-source-registration-v1';
async function deadline<T>(call: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      call,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('source_operation_timeout')), 30000);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
async function retain(name: string, value: unknown) {
  const fd = await open(
    join(journal, name),
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await fd.writeFile(JSON.stringify(value) + '\n');
    await fd.sync();
  } finally {
    await fd.close();
  }
  const parent = await open(
    journal,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    await parent.sync();
  } finally {
    await parent.close();
  }
}
async function main() {
  const [mode, directoryValue, runId] = process.argv.slice(2);
  assert.ok(
    ['inspect', 'register'].includes(mode ?? '') &&
      directoryValue &&
      /^\d{1,14}$/.test(runId ?? '') &&
      process.argv.length === 5,
    'Usage: register-work-code-source.ts inspect|register PACKET SUCCESSFUL_MAIN_RUN',
  );
  const directory = resolve(directoryValue);
  const packet = await verifyWorkCodeSource(directory, join(root, '.git'));
  assert.equal(packet.source.source_id, 'mikaki-code-snapshot');
  assert.equal(packet.source.repo_name, 'mikaki-work-source');
  const run = JSON.parse(
    execFileSync('gh', ['api', `repos/masanork/mikaki/actions/runs/${runId}`], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 30000,
    }),
  );
  assert.ok(
    run.status === 'completed' &&
      run.conclusion === 'success' &&
      run.head_branch === 'main' &&
      run.event === 'push',
  );
  assert.deepEqual(
    releaseSource(root),
    { commit: run.head_sha, clean: true },
    'Use the exact qualified clean source',
  );
  const get = cloudflareMetadataGet(
    PRODUCTION_WORK_TARGET.account,
    process.env.CLOUDFLARE_API_TOKEN ?? '',
  );
  const path = `/accounts/${PRODUCTION_WORK_TARGET.account}/workers/scripts/${opName}`;
  const deployment = (await get(`${path}/deployments?page=1&per_page=1`)) as {
    result: { deployments: { versions: { version_id: string; percentage: number }[] }[] };
  };
  const active = deployment.result.deployments[0]?.versions;
  assert.ok(active?.length === 1 && active[0]!.percentage === 100);
  const version = (await get(`${path}/versions/${active[0]!.version_id}`)) as {
    result: {
      metadata: { annotations: Record<string, string> };
      resources: {
        bindings: {
          name: string;
          type: string;
          text?: string;
          service?: string;
          entrypoint?: string;
          database_id?: string;
        }[];
      };
    };
  };
  assert.equal(version.result.metadata.annotations['workers/message'], `main CI ${run.head_sha}`);
  const bindings = version.result.resources.bindings;
  assert.ok(
    bindings.some(
      (b) =>
        b.name === 'WORK_AUTHORITY_CHECKPOINT' &&
        b.type === 'service' &&
        b.service === PRODUCTION_WORK_TARGET.checkpoint &&
        b.entrypoint === 'WorkCheckpointService',
    ),
  );
  assert.ok(
    bindings.some(
      (b) =>
        b.name === 'DB' && b.type === 'd1' && b.database_id === PRODUCTION_WORK_TARGET.database,
    ),
  );
  assert.ok(
    bindings.some(
      (b) =>
        b.name === 'WORK_CHECKPOINT_NAMESPACE_ID' &&
        b.type === 'plain_text' &&
        b.text === '37be6d239cd4460f92eff179f72ad792',
    ),
  );
  const config = {
    name: 'mikaki-work-source-local-operator',
    account_id: PRODUCTION_WORK_TARGET.account,
    compatibility_date: '2026-10-12',
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
        binding: 'SOURCE_ADMIN',
        service: opName,
        entrypoint: 'OpAuthorityAdmin',
        remote: true,
      },
    ],
  };
  // This config carries resource identities only. Native owns every mutation.
  const { mkdtemp, writeFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const temporary = await mkdtemp(join(tmpdir(), 'mikaki-source-operator-'));
  let proxy:
    | Awaited<ReturnType<typeof getPlatformProxy<{ DB: D1Database; SOURCE_ADMIN: Fetcher }>>>
    | undefined;
  try {
    const configPath = join(temporary, 'operator.json');
    await writeFile(configPath, JSON.stringify(config), { flag: 'wx', mode: 0o600 });
    proxy = await getPlatformProxy<{ DB: D1Database; SOURCE_ADMIN: Fetcher }>({
      configPath,
      remoteBindings: true,
      persist: false,
    });
    const accounts = await proxy.env.DB.prepare(
      "SELECT a.account_id,a.epoch FROM account_security a JOIN account_role r ON r.account_id=a.account_id WHERE a.active=1 AND r.role='admin' AND r.active=1 ORDER BY a.account_id LIMIT 2",
    ).all<{ account_id: string; epoch: number }>();
    assert.equal(accounts.results.length, 1, 'Select one active production administrator');
    const account = accounts.results[0]!;
    const inspect = async () => {
      const response = await deadline(
        proxy!.env.SOURCE_ADMIN.fetch('https://private.invalid/authority', {
          method: 'POST',
          body: JSON.stringify({
            action: 'inspect-source',
            source_id: packet.source.source_id,
            account: account.account_id,
          }),
        }),
      );
      assert.equal(response.status, 200, 'Native source inspection refused');
      return response.json() as Promise<{
        source: {
          body: string;
          source_revision: number;
          source_active: number;
          owner_epoch: number;
          access_revision: number;
          access_active: number;
        } | null;
      }>;
    };
    if (mode === 'register') {
      assert.equal(
        (await inspect()).source,
        null,
        'Registration already exists; inspect the retained outcome',
      );
      await mkdir(journal, { mode: 0o700 });
      await retain('selection.json', {
        source: releaseSource(root),
        run_id: runId,
        packet: directory,
        source_sha256: packet.provenance.source_sha256,
        account_id: account.account_id,
        owner_epoch: account.epoch,
        target: PRODUCTION_WORK_TARGET,
      });
      await retain('intent.json', {
        action: 'register-source',
        recorded_at: new Date().toISOString(),
      });
      const response = await deadline(
        proxy.env.SOURCE_ADMIN.fetch('https://private.invalid/authority', {
          method: 'POST',
          body: JSON.stringify({
            action: 'register-source',
            source: packet.source,
            account: account.account_id,
            expected_epoch: account.epoch,
            actor: 'work-code-source-operator',
            reason: `Verified code snapshot of ${packet.provenance.source_commit}; original history excluded`,
          }),
        }),
      );
      assert.equal(response.status, 200, 'Registration refused; inspect without replay');
      const result = await response.json();
      assert.deepEqual(result, {
        registered: true,
        source_id: packet.source.source_id,
        source_revision: 1,
        access_revision: 1,
      });
      await retain('ack.json', result);
    }
    const observed = (await inspect()).source;
    if (mode === 'register') assert.ok(observed, 'Registered source is no longer current');
    if (observed) {
      assert.deepEqual(JSON.parse(observed.body), {
        version: 1,
        kind: 'source',
        data: { data: packet.source },
      });
      assert.ok(
        observed.source_revision === 1 &&
          observed.source_active === 1 &&
          observed.owner_epoch === account.epoch &&
          observed.access_revision === 1 &&
          observed.access_active === 1,
      );
      if (mode === 'register')
        await retain('verified.json', {
          registered: true,
          source_sha256: packet.provenance.source_sha256,
          recorded_at: new Date().toISOString(),
        });
    }
    console.log(
      JSON.stringify({
        registered: !!observed,
        source_id: packet.source.source_id,
        original_history_included: false,
        commits: 1,
        object_bytes: packet.source.code.object_bytes,
        preparations_created: 0,
        consent_recorded: false,
        external_effects: 0,
      }),
    );
  } finally {
    await proxy?.dispose();
    await rm(temporary, { recursive: true, force: true });
  }
}
main().catch(() => {
  console.error(
    'Source operation stopped. Inspect retained metadata; do not recreate or replay registration.',
  );
  process.exitCode = 1;
});
