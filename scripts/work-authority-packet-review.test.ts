import assert from 'node:assert/strict';
import { cp, mkdtemp, mkdir, readFile, rm, symlink, appendFile, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  AUTHORITY_ACCOUNT,
  authorityPlan,
  authoritySchema,
  authorityTemplates,
  packetFile,
} from './work-authority-packet.ts';
const root = new URL('../', import.meta.url).pathname;
async function migrationFixture() {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-authority-schema-review-'));
  const path = join(dir, 'migrations');
  await mkdir(path);
  await cp(join(root, 'crates/worker/migrations'), path, {
    recursive: true,
    filter: (source) => !source.endsWith('.md'),
  });
  await cp(join(root, 'crates/worker/work-migrations'), path, {
    recursive: true,
    filter: (source) => !source.endsWith('.md'),
  });
  return { path, close: () => rm(dir, { recursive: true, force: true }) };
}
test('preparation fixes isolated identities and keeps browser/resource/operator prerequisites unresolved', () => {
  const plan = authorityPlan(AUTHORITY_ACCOUNT),
    templates = authorityTemplates(AUTHORITY_ACCOUNT);
  assert.equal(plan.stage, 'prepared-not-allocated-or-enrolled');
  assert.ok(Object.values(plan.unresolved).every((v) => v === null));
  assert.equal(plan.capabilities.external_effects, false);
  assert.equal(plan.capabilities.imported_authority, false);
  assert.ok(!('artifacts' in templates.op));
  for (const key of [
    'WORK_COPY_EXECUTION_ENABLED',
    'WORK_EFFECT_STORE_ENABLED',
    'WORK_MINT_STORE_ENABLED',
    'WORK_GIT_STORE_ENABLED',
  ] as const)
    assert.equal(templates.op.vars[key], 'false');
  assert.equal(templates.op.workers_dev, false);
  assert.equal(templates.op.preview_urls, false);
  assert.ok(templates.op.d1_databases[0]!.database_id.startsWith('__'));
  assert.ok(templates.op.vars.MIKAKI_ISSUER.startsWith('__'));
  assert.deepEqual(
    templates.op.services.map((s) => s.entrypoint),
    ['WorkCheckpointService'],
  );
  assert.throws(() => authorityTemplates('a'.repeat(32)), /account_denied/);
});
test('the packaged fifteen-migration chain preserves the exact empty Owner/work authority boundary', async () => {
  const f = await migrationFixture();
  try {
    const schema = await authoritySchema(f.path);
    assert.equal(schema.migrations.length, 15);
    assert.ok(schema.schema.objects > 0);
  } finally {
    await f.close();
  }
});
test('changed immutable Owner baseline bytes and missing migrations refuse preparation', async () => {
  const f = await migrationFixture();
  try {
    await appendFile(join(f.path, '0001_owner_vault_initial.sql'), '\n-- substituted baseline\n');
    await assert.rejects(authoritySchema(f.path));
    await unlink(join(f.path, '0001_owner_vault_initial.sql'));
    await assert.rejects(authoritySchema(f.path), /migrations_denied/);
  } finally {
    await f.close();
  }
});
test('a migration that silently enrolls an authority cannot be packaged as an empty target', async () => {
  const f = await migrationFixture();
  try {
    await appendFile(
      join(f.path, '0014_work_copy_job.sql'),
      `\nINSERT INTO work_authority_checkpoint VALUES(1,'imported-authority','${'a'.repeat(64)}',0,'${'b'.repeat(64)}');\n`,
    );
    await assert.rejects(authoritySchema(f.path));
  } finally {
    await f.close();
  }
});
test('packet member reads reject symlinks and bounded-file overflow', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-authority-file-review-'));
  try {
    const target = join(root, 'docs/work-authority-checkpoint.md');
    await symlink(target, join(dir, 'substitution'));
    await assert.rejects(packetFile(join(dir, 'substitution')));
    await assert.rejects(packetFile(target, 1));
    assert.deepEqual(await packetFile(target), await readFile(target));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
