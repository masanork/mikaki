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
    !['stage', 'disable'].includes(options['--action']) ||
    !['yes', 'no'].includes(options['--apply']) ||
    !options['--actor'] ||
    options['--actor'].length > 128 ||
    !options['--reason'] ||
    options['--reason'].length > 512 ||
    (options['--action'] === 'stage' && !options['--input']) ||
    (options['--action'] === 'disable' && !options['--key-id'])
  ) {
    throw new Error(
      'usage: node scripts/recipient-key-admin.mjs --config CONFIG --remote yes|no --action stage|disable --input PUBLIC_JSON --key-id KEY_ID --actor NAME --reason TEXT --apply yes|no',
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
    if (action === 'stage') {
      await stageKey(db, record, options['--actor'], options['--reason'], now);
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
