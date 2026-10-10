/** Load only frozen product/checkpoint modules in local workerd. No remote enrollment. */
import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { releaseSource } from './release-inventory.ts';
import {
  AUTHORITY_TARGET,
  authorityTemplates,
  packetFile,
  digest,
  verifyAuthorityPacket,
  packetJson,
} from './work-authority-packet.ts';

export async function qualifyAuthorityPacket(directory: string) {
  const manifest = await verifyAuthorityPacket(directory);
  const templates = authorityTemplates(manifest.account_id);
  const modulesRoot = join(directory, 'op/build');
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: AUTHORITY_TARGET.op,
          modulesRoot,
          modules: [
            ...['worker/service.mjs', 'worker/shim.mjs', 'index.js'].map((path) => ({
              type: 'ESModule' as const,
              path: join(modulesRoot, path),
            })),
            { type: 'CompiledWasm', path: join(modulesRoot, 'index_bg.wasm') },
          ],
          compatibilityDate: templates.op.compatibility_date,
          bindings: { ...templates.op.vars, MIKAKI_ISSUER: 'https://authority.test' },
          d1Databases: { DB: 'authority-packet-local' },
          r2Buckets: { VAULT_BLOBS: 'authority-packet-local-vault' },
          serviceBindings: {
            WORK_AUTHORITY_CHECKPOINT: {
              name: AUTHORITY_TARGET.checkpoint,
              entrypoint: 'WorkCheckpointService',
            },
          },
        },
        {
          name: AUTHORITY_TARGET.checkpoint,
          modules: true,
          scriptPath: join(directory, 'checkpoint/worker.mjs'),
          compatibilityDate: templates.checkpoint.compatibility_date,
          bindings: templates.checkpoint.vars,
          durableObjects: { CHECKPOINTS: { className: 'WorkCheckpoint', useSQLite: true } },
        },
      ],
    }),
  );
  try {
    const op = await mf.getWorker(AUTHORITY_TARGET.op);
    const checkpoint = await mf.getWorker(AUTHORITY_TARGET.checkpoint);
    const DB = await mf.getD1Database('DB');
    const env = await mf.getBindings(AUTHORITY_TARGET.op);
    const checkpointService = env.WORK_AUTHORITY_CHECKPOINT as {
      fetch(input: string, init: RequestInit): Promise<{ status: number }>;
    };
    for (const name of (await readdir(join(directory, 'migrations'))).sort()) {
      const statements = splitSqlQuery(
        (await packetFile(join(directory, 'migrations', name))).toString('utf8'),
      );
      await DB.batch(statements.map((sql) => DB.prepare(sql)));
    }
    for (const table of [
      'account_security',
      'credential',
      'sso_session',
      'work_authority_checkpoint',
      'work_source_version',
      'work_copy_consent',
      'work_copy_job',
    ])
      assert.equal(await DB.prepare(`SELECT count(*) AS n FROM ${table}`).first('n'), 0, table);
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
        (
          await op.fetch(`https://authority.test${path}`, {
            method: 'POST',
            body: '{}',
            redirect: 'manual',
          })
        ).status,
        404,
        path,
      );
    const enrollment = await op.fetch('https://authority.test/enroll', { redirect: 'manual' });
    assert.equal(enrollment.status, 302);
    const login = new URL(enrollment.headers.get('Location')!);
    assert.equal(login.origin, 'https://authority.test');
    assert.equal(login.pathname, '/login');
    assert.equal(
      (
        await op.fetch(login.toString(), {
          redirect: 'manual',
          headers: { Cookie: enrollment.headers.get('Set-Cookie')!.split(';')[0]! },
        })
      ).status,
      200,
    );
    assert.equal(
      (await op.fetch('https://authority.test/work/session', { redirect: 'manual' })).status,
      401,
    );
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
        await checkpointService.fetch('https://private.invalid/checkpoint', {
          method: 'POST',
          body: JSON.stringify({ action: 'status', release: 1 }),
        })
      ).status,
      409,
    );
    assert.equal(
      (
        await checkpointService.fetch('https://private.invalid/checkpoint', {
          method: 'POST',
          body: JSON.stringify({ action: 'bootstrap', release: 1 }),
        })
      ).status,
      400,
    );
    assert.equal((await DB.prepare('PRAGMA foreign_key_check').all()).results.length, 0);
    await verifyAuthorityPacket(directory);
    return {
      format_version: 1,
      source: manifest.source,
      qualifier_source: releaseSource(fileURLToPath(new URL('../', import.meta.url))),
      qualifier_sha256: digest(await packetFile(fileURLToPath(import.meta.url))).sha256,
      manifest_sha256: digest(await packetFile(join(directory, 'manifest.json'))).sha256,
      runtime: 'local-workerd-frozen-product-and-checkpoint',
      migrations: 14,
      empty_authority: true,
      public_fixture_admin_routes: 'refused',
      actual_enrollment_page: 'same-origin-redirect-and-login-served',
      owner_session_without_login: 'refused',
      checkpoint_default_http: 'refused',
      checkpoint_service_uninitialized: 'refused',
      checkpoint_service_bootstrap: 'refused',
      remote_operations: 0,
      actual_owner_enrollment: false,
    };
  } finally {
    await mf.dispose();
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [directory, receipt, ...rest] = process.argv.slice(2);
  assert.ok(
    directory && !rest.length,
    'Usage: node scripts/qualify-work-authority-packet.ts PACKET [NEW_RECEIPT_FILE]',
  );
  if (receipt) {
    const path = relative(resolve(directory), resolve(receipt));
    assert.ok(
      path === '..' || path.startsWith(`..${sep}`) || isAbsolute(path),
      'Receipt must stay outside the frozen packet',
    );
  }
  const result = await qualifyAuthorityPacket(resolve(directory));
  if (receipt) await packetJson(resolve(receipt), result);
  console.log(JSON.stringify(result, null, 2));
}
