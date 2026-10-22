import assert from 'node:assert/strict';
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import {
  AUTHORITY_ACCOUNT,
  AUTHORITY_INPUTS,
  OP_MEMBERS,
  authorityInventory,
  authorityPlan,
  authoritySchema,
  authorityTemplates,
  packetJson,
  verifyAuthorityPacket,
} from './work-authority-packet.ts';

import { OWNER_MIGRATIONS } from './production-owner-schema.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const source = { commit: 'a'.repeat(40), clean: true as const };
/** Synthetic bytes qualify inventory rejection, never a product deployment. */
async function fixture(
  baseline: 'current' | 'wrap' | 'review' | 'age' | 'waitlist' | 'retained' = 'current',
) {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-authority-packet-'));
  const write = async (name: string, bytes: string | Buffer) => {
    await mkdir(dirname(join(directory, name)), { recursive: true });
    await writeFile(join(directory, name), bytes);
  };
  for (const name of OP_MEMBERS) await write(`op/build/${name}`, 'synthetic member');
  await write(
    'op/build/index_bg.wasm',
    Buffer.concat([
      Buffer.from([0, 97, 115, 109, 1, 0, 0, 0, 0, 41, 0]),
      Buffer.from(source.commit),
    ]),
  );
  await write('checkpoint/worker.mjs', 'synthetic checkpoint');
  for (const name of ['build.json', 'build-1.log', 'build-2.log', 'build-3.log'])
    await write(name, 'synthetic build evidence');
  for (const name of AUTHORITY_INPUTS) await write(`inputs/${name.replaceAll('/', '__')}`, 'input');
  const ownerCount = {
    current: OWNER_MIGRATIONS.length,
    wrap: 6,
    review: 5,
    age: 4,
    waitlist: 3,
    retained: 2,
  }[baseline];
  const ownerNames = new Set<string>(OWNER_MIGRATIONS.slice(0, ownerCount).map(({ name }) => name));
  for (const location of ['migrations', 'work-migrations']) {
    const parent = join(root, 'crates/worker', location);
    for (const name of (await readdir(parent)).filter(
      (name) => name.endsWith('.sql') && (location === 'work-migrations' || ownerNames.has(name)),
    ))
      await write(`migrations/${name}`, await readFile(join(parent, name)));
  }
  for (const [name, config] of Object.entries(authorityTemplates(AUTHORITY_ACCOUNT)))
    await packetJson(join(directory, name, 'wrangler.template.json'), config);
  await packetJson(join(directory, 'plan.json'), authorityPlan(AUTHORITY_ACCOUNT, baseline));
  await packetJson(join(directory, 'manifest.json'), await authorityInventory(directory, source));
  return { directory, write, close: () => rm(directory, { recursive: true, force: true }) };
}

test('isolated preparation fixes service capability and leaves resource/owner authority unresolved', () => {
  const { op, checkpoint } = authorityTemplates(AUTHORITY_ACCOUNT);
  assert.deepEqual(
    op.services.map(({ entrypoint }) => entrypoint),
    ['WorkCheckpointService'],
  );
  assert.equal(op.workers_dev, false);
  assert.equal(checkpoint.preview_urls, false);
  for (const flag of [
    'WORK_COPY_EXECUTION_ENABLED',
    'WORK_PREPARATION_COMPOSE_ENABLED',
    'WORK_EFFECT_STORE_ENABLED',
    'WORK_MINT_STORE_ENABLED',
    'WORK_GIT_STORE_ENABLED',
  ] as const)
    assert.equal(op.vars[flag], 'false');
  assert.equal('artifacts' in op, false);
  assert.equal('d1_databases' in checkpoint, false);
  const plan = authorityPlan(AUTHORITY_ACCOUNT);
  assert.ok(Object.values(plan.unresolved).every((v) => v === null));
  assert.equal(plan.capabilities.imported_authority, false);
  assert.throws(() => authorityTemplates('b'.repeat(32)), /account_denied/);
});

test('frozen inventory detects bundle/schema substitution and extra or missing members', async () => {
  const f = await fixture();
  try {
    const manifest = await verifyAuthorityPacket(f.directory);
    assert.equal(manifest.migrations.length, 19);
    assert.ok(manifest.schema.objects > 100);
    const wasm = await readFile(join(f.directory, 'op/build/index_bg.wasm'));
    await f.write('op/build/index_bg.wasm', Buffer.concat([wasm, Buffer.from([0, 1, 0])]));
    await assert.rejects(verifyAuthorityPacket(f.directory), /inventory_changed/);
    await f.write('op/build/index_bg.wasm', wasm);
    await f.write('checkpoint/worker.mjs', 'changed');
    await assert.rejects(verifyAuthorityPacket(f.directory), /inventory_changed/);
    await f.write('checkpoint/worker.mjs', 'synthetic checkpoint');
    await f.write('credentials.json', 'unexpected secret');
    await assert.rejects(verifyAuthorityPacket(f.directory), /members_changed/);
    await unlink(join(f.directory, 'credentials.json'));
    const migration = manifest.migrations[13].path;
    const bytes = await readFile(join(f.directory, migration));
    await f.write(migration, Buffer.concat([bytes, Buffer.from('\n-- substituted\n')]));
    await assert.rejects(verifyAuthorityPacket(f.directory), /inventory_changed/);
    await unlink(join(f.directory, migration));
    await assert.rejects(authoritySchema(join(f.directory, 'migrations')), /migrations_denied/);
  } finally {
    await f.close();
  }
});

test('retained fourteen-file packets remain verifiable and cannot acquire the current baseline', async () => {
  const f = await fixture('retained');
  try {
    assert.equal((await verifyAuthorityPacket(f.directory)).migrations.length, 14);
    await f.write(
      'migrations/0003_enrollment_waitlist.sql',
      await readFile(join(root, 'crates/worker/migrations/0003_enrollment_waitlist.sql')),
    );
    await assert.rejects(verifyAuthorityPacket(f.directory), /plan_changed/);
  } finally {
    await f.close();
  }
});

test('current packets refuse a missing waiting-list migration and changed immutable baseline bytes', async () => {
  const f = await fixture();
  try {
    const path = 'migrations/0003_enrollment_waitlist.sql';
    const bytes = await readFile(join(f.directory, path));
    await unlink(join(f.directory, path));
    await assert.rejects(verifyAuthorityPacket(f.directory), /migrations_denied/);
    await f.write(path, Buffer.concat([bytes, Buffer.from('\n-- substituted baseline\n')]));
    await assert.rejects(verifyAuthorityPacket(f.directory));
  } finally {
    await f.close();
  }
});

test('retained fifteen-file packets preserve their plan and refuse an additive age migration', async () => {
  const f = await fixture('waitlist');
  try {
    assert.equal((await verifyAuthorityPacket(f.directory)).migrations.length, 15);
    await f.write(
      'migrations/0004_identity_age_requests.sql',
      await readFile(join(root, 'crates/worker/migrations/0004_identity_age_requests.sql')),
    );
    await assert.rejects(verifyAuthorityPacket(f.directory), /plan_changed/);
  } finally {
    await f.close();
  }
});

test('preparation refuses changed source identity, production resource and symlink replacement', async () => {
  const f = await fixture();
  try {
    await assert.rejects(
      authorityInventory(f.directory, { ...source, clean: false } as never),
      /source_dirty/,
    );
    await assert.rejects(
      authorityInventory(f.directory, { ...source, commit: 'b'.repeat(40) }),
      /embedded_source/,
    );
    const templates = authorityTemplates(AUTHORITY_ACCOUNT);
    templates.op.d1_databases[0]!.database_id = 'd0258938-0d27-4110-8aa9-c82e20f3885b';
    await f.write('op/wrangler.template.json', JSON.stringify(templates.op));
    await assert.rejects(verifyAuthorityPacket(f.directory), /config_changed/);
    await f.write(
      'op/wrangler.template.json',
      JSON.stringify(authorityTemplates(AUTHORITY_ACCOUNT).op),
    );
    await unlink(join(f.directory, 'checkpoint/worker.mjs'));
    await symlink(join(f.directory, 'build-1.log'), join(f.directory, 'checkpoint/worker.mjs'));
    await assert.rejects(verifyAuthorityPacket(f.directory), /member_denied/);
  } finally {
    await f.close();
  }
});

test('retained sixteen-file packets keep their plan and reject the additive login review migration', async () => {
  const f = await fixture('age');
  try {
    assert.equal((await verifyAuthorityPacket(f.directory)).migrations.length, 16);
    await f.write(
      'migrations/0005_login_connection_review.sql',
      await readFile(join(root, 'crates/worker/migrations/0005_login_connection_review.sql')),
    );
    await assert.rejects(verifyAuthorityPacket(f.directory), /plan_changed/);
  } finally {
    await f.close();
  }
});

test('retained seventeen-file packets keep their plan and reject the additive login wrapper migration', async () => {
  const f = await fixture('review');
  try {
    assert.equal((await verifyAuthorityPacket(f.directory)).migrations.length, 17);
    await f.write(
      'migrations/0006_owner_login_wrap.sql',
      await readFile(join(root, 'crates/worker/migrations/0006_owner_login_wrap.sql')),
    );
    await assert.rejects(verifyAuthorityPacket(f.directory), /plan_changed/);
  } finally {
    await f.close();
  }
});

test('retained eighteen-file packets keep their plan and reject the additive passport migration', async () => {
  const f = await fixture('wrap');
  try {
    assert.equal((await verifyAuthorityPacket(f.directory)).migrations.length, 18);
    await f.write(
      'migrations/0007_passport_issuance.sql',
      await readFile(join(root, 'crates/worker/migrations/0007_passport_issuance.sql')),
    );
    await assert.rejects(verifyAuthorityPacket(f.directory), /plan_changed/);
  } finally {
    await f.close();
  }
});
