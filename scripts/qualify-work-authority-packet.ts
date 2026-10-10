/** Load only frozen product/checkpoint modules in local workerd. No remote enrollment. */
import assert from 'node:assert/strict';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createTestHarness } from 'wrangler';
import {
  AUTHORITY_TARGET,
  authorityTemplates,
  packetFile,
  digest,
  verifyAuthorityPacket,
} from './work-authority-packet.ts';

export async function qualifyAuthorityPacket(directory: string) {
  const manifest = await verifyAuthorityPacket(directory);
  const templates = authorityTemplates(manifest.account_id);
  const opConfig = {
    ...templates.op,
    main: join(directory, 'op/build/worker/service.mjs'),
    base_dir: join(directory, 'op/build'),
    vars: { ...templates.op.vars, MIKAKI_ISSUER: 'https://authority.test' },
    secrets: undefined,
    triggers: undefined,
    queues: undefined,
    d1_databases: [
      {
        binding: 'DB',
        database_name: 'authority-packet-local',
        database_id: '00000000-0000-4000-8000-000000000001',
        migrations_dir: join(directory, 'migrations'),
        remote: false,
      },
    ],
  };
  const harness = createTestHarness({
    root: fileURLToPath(new URL('../', import.meta.url)),
    workers: [
      { config: opConfig },
      { config: { ...templates.checkpoint, main: join(directory, 'checkpoint/worker.mjs') } },
    ],
  });
  try {
    await harness.listen();
    const op = harness.getWorker(AUTHORITY_TARGET.op);
    const checkpoint = harness.getWorker(AUTHORITY_TARGET.checkpoint);
    await op.applyD1Migrations('DB');
    const env = await op.getEnv();
    for (const table of [
      'account_security',
      'credential',
      'sso_session',
      'work_authority_checkpoint',
      'work_source_version',
      'work_copy_consent',
      'work_copy_job',
    ])
      assert.equal(await env.DB.prepare(`SELECT count(*) AS n FROM ${table}`).first('n'), 0, table);
    for (const path of [
      '/fixture',
      '/checkpoint-fixture',
      '/authority-fixture',
      '/authority',
      '/effect',
      '/mint-effect',
      '/git-effect',
      '/copy-job',
    ])
      assert.equal(
        (await op.fetch(`https://authority.test${path}`, { method: 'POST', body: '{}' })).status,
        404,
        path,
      );
    assert.equal((await op.fetch('https://authority.test/enroll')).status, 200);
    assert.equal((await op.fetch('https://authority.test/work/session')).status, 401);
    assert.equal(
      (
        await checkpoint.fetch('https://private.invalid/checkpoint', {
          method: 'POST',
          body: JSON.stringify({ action: 'status', release: 1 }),
        })
      ).status,
      404,
    );
    assert.equal(
      (
        await env.WORK_AUTHORITY_CHECKPOINT.fetch('https://private.invalid/checkpoint', {
          method: 'POST',
          body: JSON.stringify({ action: 'status', release: 1 }),
        })
      ).status,
      409,
    );
    assert.equal(
      (
        await env.WORK_AUTHORITY_CHECKPOINT.fetch('https://private.invalid/checkpoint', {
          method: 'POST',
          body: JSON.stringify({ action: 'bootstrap', release: 1 }),
        })
      ).status,
      400,
    );
    assert.equal((await env.DB.prepare('PRAGMA foreign_key_check').all()).results.length, 0);
    await verifyAuthorityPacket(directory);
    return {
      format_version: 1,
      source: manifest.source,
      manifest_sha256: digest(await packetFile(join(directory, 'manifest.json'))).sha256,
      runtime: 'local-workerd-frozen-product-and-checkpoint',
      migrations: 14,
      empty_authority: true,
      public_fixture_admin_routes: 'refused',
      actual_enrollment_page: 'served',
      owner_session_without_login: 'refused',
      checkpoint_default_http: 'refused',
      checkpoint_service_uninitialized: 'refused',
      checkpoint_service_bootstrap: 'refused',
      remote_operations: 0,
      actual_owner_enrollment: false,
    };
  } finally {
    await harness.close();
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [directory, ...rest] = process.argv.slice(2);
  assert.ok(
    directory && !rest.length,
    'Usage: node scripts/qualify-work-authority-packet.ts PACKET',
  );
  console.log(JSON.stringify(await qualifyAuthorityPacket(resolve(directory)), null, 2));
}
