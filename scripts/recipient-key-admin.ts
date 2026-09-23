import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getPlatformProxy } from 'wrangler';

export function validatePublicRecord(record) {
  const expected = ['algorithm', 'generation', 'key_id', 'public_key', 'secret_ref', 'service_id'];
  if (
    !record ||
    typeof record !== 'object' ||
    Array.isArray(record) ||
    JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(expected) ||
    record.algorithm !== 'ML-KEM-768' ||
    record.service_id !== 'userinfo' ||
    !Number.isSafeInteger(record.generation) ||
    record.generation < 1 ||
    typeof record.public_key !== 'string' ||
    typeof record.key_id !== 'string' ||
    typeof record.secret_ref !== 'string' ||
    !/^VAULT_USERINFO_MLKEM_[A-Z0-9_]{1,104}$/.test(record.secret_ref)
  ) {
    throw new Error('invalid recipient public record');
  }
  const publicKey = Buffer.from(record.public_key, 'base64url');
  if (
    publicKey.length !== 1184 ||
    publicKey.toString('base64url') !== record.public_key ||
    createHash('sha256').update(publicKey).digest('base64url') !== record.key_id
  ) {
    throw new Error('recipient public key ID or encoding mismatch');
  }
  return publicKey;
}

function parseOptions(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    if (!key?.startsWith('--') || index + 1 >= args.length || Object.hasOwn(options, key)) {
      throw new Error('invalid arguments');
    }
    options[key] = args[index + 1];
  }
  const allowed = new Set([
    '--config',
    '--remote',
    '--action',
    '--input',
    '--key-id',
    '--actor',
    '--reason',
    '--apply',
  ]);
  if (
    Object.keys(options).some((key) => !allowed.has(key)) ||
    !options['--config'] ||
    !['yes', 'no'].includes(options['--remote']) ||
    !['stage', 'verify', 'activate', 'rotate', 'disable'].includes(options['--action']) ||
    !['yes', 'no'].includes(options['--apply']) ||
    !options['--actor'] ||
    options['--actor'].length > 128 ||
    !options['--reason'] ||
    options['--reason'].length > 512 ||
    (options['--action'] === 'stage' && !options['--input']) ||
    (options['--action'] !== 'stage' && !options['--key-id'])
  ) {
    throw new Error(
      'usage: node scripts/recipient-key-admin.ts --config CONFIG --remote yes|no --action stage|verify|activate|rotate|disable --input PUBLIC_JSON --key-id KEY_ID --actor NAME --reason TEXT --apply yes|no',
    );
  }
  return options;
}

export async function stageKey(db, record, actor, reason, now) {
  const publicKey = validatePublicRecord(record);
  await db.batch([
    db
      .prepare(
        `INSERT INTO vault_recipient_key
      (key_id,service_id,algorithm,public_key,secret_ref,generation,state,revision,created_at)
      VALUES(?,'userinfo','ML-KEM-768',?,?,?,'staged',1,?)`,
      )
      .bind(record.key_id, publicKey, record.secret_ref, record.generation, now),
    db
      .prepare(
        `INSERT INTO vault_recipient_key_audit
      (operation_id,key_id,action,actor,reason,revision,occurred_at)
      VALUES(?,?,'stage',?,?,1,?)`,
      )
      .bind(randomUUID(), record.key_id, actor, reason, now),
  ]);
}

export async function disableKey(db, keyId, actor, reason, now) {
  const row = await db
    .prepare('SELECT revision,state FROM vault_recipient_key WHERE key_id=?')
    .bind(keyId)
    .first();
  if (!row || row.state === 'disabled' || !Number.isSafeInteger(row.revision)) {
    throw new Error('key missing or already disabled');
  }
  const nextRevision = row.revision + 1;
  const results = await db.batch([
    db
      .prepare(
        `UPDATE vault_recipient_key SET state='disabled',revision=?,retired_at=COALESCE(retired_at,?)
      WHERE key_id=? AND revision=? AND state!='disabled'`,
      )
      .bind(nextRevision, now, keyId, row.revision),
    db
      .prepare(
        `INSERT INTO vault_recipient_key_audit
      (operation_id,key_id,action,actor,reason,revision,occurred_at)
      SELECT ?,?,'disable',?,?,?,? FROM vault_recipient_key
      WHERE key_id=? AND state='disabled' AND revision=?`,
      )
      .bind(randomUUID(), keyId, actor, reason, nextRevision, now, keyId, nextRevision),
  ]);
  if (results[0].meta.changes !== 1 || results[1].meta.changes !== 1) {
    throw new Error('concurrent recipient key update; inspect the database');
  }
}

async function verifyBinding(claims, keyId) {
  const response = await claims.fetch(
    `https://userinfo.internal/internal/recipient-keys/${keyId}/verify`,
    { method: 'GET' },
  );
  if (response.status !== 204)
    throw new Error(
      `recipient key binding verification failed for ${keyId}: HTTP ${response.status}`,
    );
}

function requiredService(config) {
  const binding = config.services?.find((item) => item.binding === 'USERINFO_CLAIMS');
  if (binding?.service !== 'mikaki-userinfo-claim-worker' || binding.remote !== true) {
    throw new Error('USERINFO_CLAIMS must remotely bind the dedicated claim Worker');
  }
}

export async function activateKey(db, claims, keyId, actor, reason, now) {
  const row = await db
    .prepare('SELECT state,revision FROM vault_recipient_key WHERE key_id=?')
    .bind(keyId)
    .first();
  if (!row || row.state !== 'staged' || !Number.isSafeInteger(row.revision)) {
    throw new Error('target key is not staged');
  }
  const active = await db
    .prepare("SELECT key_id FROM vault_recipient_key WHERE state='active'")
    .first();
  if (active) throw new Error('an active recipient key already exists; use rotate');
  await verifyBinding(claims, keyId);
  const guard = randomUUID();
  await db.batch([
    db
      .prepare(
        `UPDATE vault_recipient_key SET state='active',revision=revision+1,activated_at=?
      WHERE key_id=? AND state='staged' AND revision=? AND NOT EXISTS
      (SELECT 1 FROM vault_recipient_key WHERE state='active')`,
      )
      .bind(now, keyId, row.revision),
    db
      .prepare(
        'INSERT INTO vault_recipient_atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      )
      .bind(guard),
    db
      .prepare(
        `INSERT INTO vault_recipient_key_audit
      (operation_id,key_id,action,actor,reason,revision,occurred_at)
      VALUES(?,?,'activate',?,?,?,?)`,
      )
      .bind(randomUUID(), keyId, actor, reason, row.revision + 1, now),
    db.prepare('DELETE FROM vault_recipient_atomic_guard WHERE operation_id=?').bind(guard),
  ]);
}

export async function rotateKey(db, claims, newKeyId, actor, reason, now) {
  const old = await db
    .prepare("SELECT key_id,revision FROM vault_recipient_key WHERE state='active'")
    .first();
  const next = await db
    .prepare('SELECT state,revision FROM vault_recipient_key WHERE key_id=?')
    .bind(newKeyId)
    .first();
  if (
    !old ||
    !Number.isSafeInteger(old.revision) ||
    !next ||
    next.state !== 'staged' ||
    !Number.isSafeInteger(next.revision)
  ) {
    throw new Error('rotation requires one active and one staged key');
  }
  await verifyBinding(claims, old.key_id);
  await verifyBinding(claims, newKeyId);
  const oldGuard = randomUUID();
  const newGuard = randomUUID();
  await db.batch([
    db
      .prepare(
        `UPDATE vault_recipient_key SET state='decrypt_only',revision=revision+1,retired_at=?
      WHERE key_id=? AND state='active' AND revision=?`,
      )
      .bind(now, old.key_id, old.revision),
    db
      .prepare(
        'INSERT INTO vault_recipient_atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      )
      .bind(oldGuard),
    db
      .prepare(
        `UPDATE vault_recipient_key SET state='active',revision=revision+1,activated_at=?
      WHERE key_id=? AND state='staged' AND revision=?`,
      )
      .bind(now, newKeyId, next.revision),
    db
      .prepare(
        'INSERT INTO vault_recipient_atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      )
      .bind(newGuard),
    db
      .prepare(
        `INSERT INTO vault_recipient_key_audit
      (operation_id,key_id,action,actor,reason,revision,occurred_at)
      VALUES(?,?,'rotate',?,?,?,?)`,
      )
      .bind(randomUUID(), old.key_id, actor, reason, old.revision + 1, now),
    db
      .prepare(
        `INSERT INTO vault_recipient_key_audit
      (operation_id,key_id,action,actor,reason,revision,occurred_at)
      VALUES(?,?,'rotate',?,?,?,?)`,
      )
      .bind(randomUUID(), newKeyId, actor, reason, next.revision + 1, now),
    db.prepare('DELETE FROM vault_recipient_atomic_guard WHERE operation_id=?').bind(oldGuard),
    db.prepare('DELETE FROM vault_recipient_atomic_guard WHERE operation_id=?').bind(newGuard),
  ]);
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  const configPath = resolve(options['--config']);
  const config = JSON.parse(await readFile(configPath, 'utf8'));
  const remote = options['--remote'] === 'yes';
  const binding = config.d1_databases?.find((item) => item.binding === 'DB');
  if (!binding || Boolean(binding.remote) !== remote || (remote && !binding.database_id)) {
    throw new Error('DB binding and --remote do not identify the same database');
  }
  const action = options['--action'];
  if (action === 'verify' || action === 'activate' || action === 'rotate') requiredService(config);
  const record =
    action === 'stage' ? JSON.parse(await readFile(resolve(options['--input']), 'utf8')) : null;
  if (record) validatePublicRecord(record);
  const keyId = record?.key_id ?? options['--key-id'];
  if (!/^[A-Za-z0-9_-]{43}$/.test(keyId)) throw new Error('invalid key ID');
  console.log(JSON.stringify({ action, key_id: keyId, remote, apply: options['--apply'] }));
  if (options['--apply'] !== 'yes') return;

  const platform = await getPlatformProxy({ configPath, remoteBindings: remote });
  try {
    const db = platform.env.DB;
    const now = Math.floor(Date.now() / 1000);
    if (action === 'verify') {
      const claims = platform.env.USERINFO_CLAIMS as { fetch: typeof fetch } | undefined;
      if (!claims?.fetch) throw new Error('USERINFO_CLAIMS binding is unavailable');
      await verifyBinding(claims, keyId);
    } else if (action === 'stage') {
      await stageKey(db, record, options['--actor'], options['--reason'], now);
    } else if (action === 'activate' || action === 'rotate') {
      const claims = platform.env.USERINFO_CLAIMS as { fetch: typeof fetch } | undefined;
      if (!claims?.fetch) throw new Error('USERINFO_CLAIMS binding is unavailable');
      if (action === 'activate') {
        await activateKey(db, claims, keyId, options['--actor'], options['--reason'], now);
      } else {
        await rotateKey(db, claims, keyId, options['--actor'], options['--reason'], now);
      }
    } else {
      await disableKey(db, keyId, options['--actor'], options['--reason'], now);
    }
    console.log(JSON.stringify({ key_id: keyId, action, completed: true }));
  } finally {
    await platform.dispose();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
