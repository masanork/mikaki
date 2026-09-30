/** Disposable SQLite/filesystem rehearsal, not a D1/R2 production restore tool. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync, backup } from 'node:sqlite';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readdir, readFile, writeFile, mkdir, copyFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  sealAttribute,
  openAttribute,
  type SealedAttribute,
} from '../crates/worker/ui/vault-crypto.ts';
import { releaseSource } from './release-inventory.ts';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const sha256 = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const objectDigest = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('base64url');
function migrate(db: DatabaseSync, name: string, sql: string) {
  db.exec('BEGIN IMMEDIATE');
  try {
    db.exec(sql);
    db.prepare('INSERT INTO drill_migration(name,digest) VALUES(?,?)').run(name, sha256(sql));
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}
function integrity(db: DatabaseSync) {
  assert.equal(db.prepare('PRAGMA integrity_check').get()!.integrity_check, 'ok');
  assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
}
test('upgrade recorded schema, restore a real backup, reject incomplete objects and expose historical revocation rollback', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'mikaki-recovery-drill-'));
  let source: DatabaseSync | undefined;
  let restored: DatabaseSync | undefined;
  try {
    const names = (await readdir(join(root, 'crates/worker/migrations')))
      .filter((name) => name.endsWith('.sql'))
      .slice()
      .sort();
    assert.ok(names.length >= 20);
    const migrations = await Promise.all(
      names.map(async (name) => ({
        name,
        sql: await readFile(join(root, 'crates/worker/migrations', name), 'utf8'),
      })),
    );
    source = new DatabaseSync(join(temporary, 'source.sqlite'));
    source.exec('CREATE TABLE drill_migration(name TEXT PRIMARY KEY, digest TEXT NOT NULL) STRICT');
    for (const item of migrations.slice(0, 13)) migrate(source, item.name, item.sql);
    const credential = new Uint8Array(randomBytes(32));
    const prf = new Uint8Array(randomBytes(32));
    const credentialId = Buffer.from(credential).toString('base64url');
    const origin = 'https://recovery-fixture.test';
    const plaintext = 'Disposable encrypted restore fixture 🗾';
    const sealed = await sealAttribute(
      new TextEncoder().encode(plaintext),
      prf,
      credential,
      new Uint8Array(randomBytes(32)),
      origin,
      'name',
      1,
    );
    const objectPath = join(temporary, 'ciphertext-object');
    const objectKey = `vault-attribute/${randomBytes(32).toString('base64url')}`;
    const ciphertextBytes = Buffer.from(sealed.ciphertext, 'base64url');
    await writeFile(objectPath, ciphertextBytes);
    source.exec(
      "INSERT INTO account_security VALUES('fixture-owner',1,1); UPDATE bootstrap_state SET closed=1;",
    );
    source.prepare("INSERT INTO credential VALUES(?,'fixture-owner',1)").run(credentialId);
    source
      .prepare(
        "INSERT INTO passkey_credential VALUES(?,'synthetic-public-key','synthetic-handle',0,0,0,1)",
      )
      .run(credentialId);
    source
      .prepare("INSERT INTO sso_session VALUES('fixture-sso','fixture-owner',?,1,2000000000,0)")
      .run(credentialId);
    source.exec(
      "INSERT INTO sso_context VALUES('fixture-sso','synthetic-cookie-verifier',1); INSERT INTO account_role VALUES('fixture-owner','admin',1);",
    );
    source
      .prepare("INSERT INTO vault_attribute_head VALUES('fixture-owner','name',1,1,?,?,?,0,1)")
      .run(objectKey, objectDigest(ciphertextBytes), sealed.owner_envelope);
    source.exec(
      "INSERT INTO client_admin_audit VALUES('fixture-audit','mikaki-internal-enrollment','register','fixture-operator','rehearsal',1)",
    );
    const original = source.prepare('SELECT * FROM vault_attribute_head').get();
    integrity(source);
    await backup(source, join(temporary, 'before.sqlite'));
    await copyFile(objectPath, join(temporary, 'before-object'));
    for (const item of migrations.slice(13)) migrate(source, item.name, item.sql);
    integrity(source);
    assert.deepEqual(source.prepare('SELECT * FROM vault_attribute_head').get(), original);
    assert.equal(source.prepare('SELECT closed FROM bootstrap_state').get()!.closed, 1);
    assert.equal(source.prepare('SELECT COUNT(*) AS n FROM client_admin_audit').get()!.n, 1);
    assert.equal(
      source.prepare('SELECT COUNT(*) AS n FROM drill_migration').get()!.n,
      names.length,
    );
    assert.ok(
      source
        .prepare('PRAGMA table_info(token_issue)')
        .all()
        .some((column) => column.name === 'dpop_jkt'),
    );
    assert.equal(source.prepare('SELECT COUNT(*) AS n FROM dpop_proof_use').get()!.n, 0);
    // A later failing statement must undo its preceding DDL and preserve the ledger.
    assert.throws(() =>
      migrate(
        source!,
        'fixture-failure',
        'CREATE TABLE partial_upgrade(id INTEGER); INSERT INTO absent_table VALUES(1);',
      ),
    );
    assert.equal(
      source.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name='partial_upgrade'").get()!
        .n,
      0,
    );
    assert.equal(
      source.prepare('SELECT COUNT(*) AS n FROM drill_migration').get()!.n,
      names.length,
    );
    source.exec('UPDATE sso_session SET revoked=1; UPDATE credential SET active=0;');
    await copyFile(join(temporary, 'before.sqlite'), join(temporary, 'restored.sqlite'));
    restored = new DatabaseSync(join(temporary, 'restored.sqlite'));
    integrity(restored);
    assert.equal(restored.prepare('SELECT COUNT(*) AS n FROM drill_migration').get()!.n, 13);
    // Restoring old bytes faithfully restores unsafe historical authority too.
    assert.equal(restored.prepare('SELECT revoked FROM sso_session').get()!.revoked, 0);
    assert.equal(restored.prepare('SELECT active FROM credential').get()!.active, 1);
    assert.equal(restored.prepare('SELECT closed FROM bootstrap_state').get()!.closed, 1);
    for (const item of migrations.slice(13)) migrate(restored, item.name, item.sql);
    integrity(restored);
    assert.deepEqual(restored.prepare('SELECT * FROM vault_attribute_head').get(), original);
    await rm(objectPath);
    await assert.rejects(readFile(objectPath), { code: 'ENOENT' });
    await copyFile(join(temporary, 'before-object'), objectPath);
    const bytes = await readFile(objectPath);
    assert.equal(objectDigest(bytes), original!.ciphertext_sha256);
    const reopened: SealedAttribute = {
      format_version: 1,
      ciphertext: bytes.toString('base64url'),
      owner_envelope: sealed.owner_envelope,
    };
    const opened = await openAttribute(reopened, prf, credential, origin, 'name', 1);
    assert.equal(new TextDecoder().decode(opened), plaintext);
    opened.fill(0);
    const corrupt = Buffer.from(bytes);
    corrupt[0] = corrupt[0] === 65 ? 66 : 65;
    assert.notEqual(objectDigest(corrupt), original!.ciphertext_sha256);
    await assert.rejects(
      openAttribute(
        { ...reopened, ciphertext: corrupt.toString('base64url') },
        prf,
        credential,
        origin,
        'name',
        1,
      ),
    );
    prf.fill(0);
    await mkdir(join(root, 'artifacts'), { recursive: true });
    await writeFile(
      join(root, 'artifacts/migration-recovery.json'),
      JSON.stringify(
        {
          schema_version: 1,
          measured_at: new Date().toISOString(),
          source: releaseSource(root),
          environment: 'disposable-node-sqlite-and-filesystem',
          migrations: migrations.map(({ name, sql }) => ({ name, sha256: sha256(sql) })),
          baseline_migrations: 13,
          verified: [
            'existing-encrypted-head-and-audit-preserved',
            'closed-bootstrap-preserved',
            'failed-migration-rolled-back',
            'backup-restored-and-upgraded',
            'matching-object-reopened',
            'missing-and-corrupt-object-rejected',
            'historical-restore-revives-revoked-state',
          ],
          production_restore_ready: false,
          remaining: [
            'D1-Time-Travel',
            'R2-backup-and-retention',
            'external-recovery-generation',
            'security-state-reconciliation',
            'RP-invalidation',
            'secret-and-service-binding-restoration',
          ],
        },
        null,
        2,
      ) + '\n',
    );
  } finally {
    restored?.close();
    source?.close();
    await rm(temporary, { recursive: true, force: true });
  }
});
