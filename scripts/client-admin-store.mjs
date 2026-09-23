import { createPublicKey, randomUUID } from 'node:crypto';

function exactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid input');
  if (Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) {
    throw new Error('unexpected or missing fields');
  }
}

function httpsUri(value) {
  if (typeof value !== 'string' || value.length > 2048 || value.length === 0) {
    throw new Error('invalid URI');
  }
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.href !== value) {
    throw new Error('URI must be canonical HTTPS without credentials or fragment');
  }
  return url;
}

export function validateRegistration(input) {
  exactKeys(input, ['client_id', 'sector_identifier', 'redirect_uris', 'key']);
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(input.client_id)
  ) {
    throw new Error('client_id must be UUIDv4');
  }
  if (
    !Array.isArray(input.redirect_uris) ||
    input.redirect_uris.length < 1 ||
    input.redirect_uris.length > 8
  ) {
    throw new Error('invalid redirect URI count');
  }
  const uris = input.redirect_uris.map(httpsUri);
  const hosts = new Set(uris.map((uri) => uri.hostname));
  if (
    new Set(input.redirect_uris).size !== uris.length ||
    hosts.size !== 1 ||
    !hosts.has(input.sector_identifier)
  ) {
    throw new Error('redirect host and sector must match');
  }
  return { ...input, key: validateKey(input.key) };
}

export function validateKey(input) {
  exactKeys(input, ['kid', 'jwk']);
  if (typeof input.kid !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(input.kid)) {
    throw new Error('invalid key ID');
  }
  exactKeys(input.jwk, ['kty', 'crv', 'x', 'y']);
  if (input.jwk.kty !== 'EC' || input.jwk.crv !== 'P-256') throw new Error('ES256 key required');
  const x = Buffer.from(input.jwk.x, 'base64url');
  const y = Buffer.from(input.jwk.y, 'base64url');
  if (
    x.length !== 32 ||
    y.length !== 32 ||
    x.toString('base64url') !== input.jwk.x ||
    y.toString('base64url') !== input.jwk.y
  ) {
    throw new Error('invalid P-256 coordinates');
  }
  createPublicKey({ key: input.jwk, format: 'jwk' });
  return { kid: input.kid, sec1: new Uint8Array(Buffer.concat([Buffer.from([4]), x, y])) };
}

export function validateRedirect(input) {
  exactKeys(input, ['redirect_uri']);
  const uri = httpsUri(input.redirect_uri);
  return { uri: uri.href, sector: uri.hostname };
}

function metadata(actor, reason) {
  if (
    typeof actor !== 'string' ||
    actor.length < 1 ||
    actor.length > 128 ||
    typeof reason !== 'string' ||
    reason.length < 1 ||
    reason.length > 512
  ) {
    throw new Error('invalid audit metadata');
  }
  return { operation: randomUUID(), now: Math.floor(Date.now() / 1000), actor, reason };
}

function audit(db, meta, clientId, action) {
  return db
    .prepare(
      'INSERT INTO client_admin_audit(operation_id,client_id,action,actor,reason,occurred_at) VALUES(?,?,?,?,?,?)',
    )
    .bind(meta.operation, clientId, action, meta.actor, meta.reason, meta.now);
}

export async function registerClient(db, input, actor, reason) {
  const value = validateRegistration(input);
  const meta = metadata(actor, reason);
  await db.batch([
    db
      .prepare(
        "INSERT INTO client(client_id,revision,active,auth_method,allow_missing_pkce,sector_identifier) VALUES(?,1,1,'private_key_jwt',0,?)",
      )
      .bind(value.client_id, value.sector_identifier),
    ...value.redirect_uris.map((uri) =>
      db
        .prepare('INSERT INTO client_redirect_uri(client_id,redirect_uri) VALUES(?,?)')
        .bind(value.client_id, uri),
    ),
    db
      .prepare(
        "INSERT INTO client_key(client_id,kid,revision,active,algorithm,public_key_sec1) VALUES(?,?,1,1,'ES256',?)",
      )
      .bind(value.client_id, value.key.kid, value.key.sec1),
    audit(db, meta, value.client_id, 'register'),
  ]);
  return { clientId: value.client_id, operation: meta.operation };
}

export async function addKey(db, clientId, input, actor, reason) {
  const key = validateKey(input);
  const meta = metadata(actor, reason);
  await db.batch([
    db
      .prepare(
        "INSERT INTO client_key(client_id,kid,revision,active,algorithm,public_key_sec1) SELECT client_id,?,1,1,'ES256',? FROM client WHERE client_id=? AND active=1",
      )
      .bind(key.kid, key.sec1, clientId),
    db
      .prepare(
        'INSERT INTO atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      )
      .bind(meta.operation),
    audit(db, meta, clientId, 'add-key'),
    db.prepare('DELETE FROM atomic_guard WHERE operation_id=?').bind(meta.operation),
  ]);
  return { clientId, kid: key.kid };
}

export async function retireKey(db, clientId, kid, actor, reason) {
  const meta = metadata(actor, reason);
  await db.batch([
    db
      .prepare(
        'UPDATE client_key SET active=0,revision=revision+1 WHERE client_id=? AND kid=? AND active=1 AND (SELECT COUNT(*) FROM client_key WHERE client_id=? AND active=1)>1',
      )
      .bind(clientId, kid, clientId),
    db
      .prepare(
        'INSERT INTO atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      )
      .bind(meta.operation),
    audit(db, meta, clientId, 'retire-key'),
    db.prepare('DELETE FROM atomic_guard WHERE operation_id=?').bind(meta.operation),
  ]);
  return { clientId, kid };
}

export async function addRedirect(db, clientId, input, actor, reason) {
  const redirect = validateRedirect(input);
  const meta = metadata(actor, reason);
  await db.batch([
    db
      .prepare(
        'INSERT INTO client_redirect_uri(client_id,redirect_uri,active) SELECT c.client_id,?,1 FROM client c WHERE c.client_id=? AND c.active=1 AND c.sector_identifier=? AND (SELECT COUNT(*) FROM client_redirect_uri WHERE client_id=c.client_id AND active=1)<8 ON CONFLICT(client_id,redirect_uri) DO UPDATE SET active=1 WHERE active=0',
      )
      .bind(redirect.uri, clientId, redirect.sector),
    db
      .prepare(
        'INSERT INTO atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      )
      .bind(meta.operation),
    db
      .prepare('UPDATE client SET revision=revision+1 WHERE client_id=? AND active=1')
      .bind(clientId),
    audit(db, meta, clientId, 'add-redirect'),
    db.prepare('DELETE FROM atomic_guard WHERE operation_id=?').bind(meta.operation),
  ]);
  return { clientId, redirectUri: redirect.uri };
}

export async function retireRedirect(db, clientId, input, actor, reason) {
  const redirect = validateRedirect(input);
  const meta = metadata(actor, reason);
  await db.batch([
    db
      .prepare(
        'UPDATE client_redirect_uri SET active=0 WHERE client_id=? AND redirect_uri=? AND active=1 AND EXISTS(SELECT 1 FROM client WHERE client_id=? AND active=1) AND (SELECT COUNT(*) FROM client_redirect_uri WHERE client_id=? AND active=1)>1',
      )
      .bind(clientId, redirect.uri, clientId, clientId),
    db
      .prepare(
        'INSERT INTO atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      )
      .bind(meta.operation),
    db
      .prepare('UPDATE client SET revision=revision+1 WHERE client_id=? AND active=1')
      .bind(clientId),
    audit(db, meta, clientId, 'retire-redirect'),
    db.prepare('DELETE FROM atomic_guard WHERE operation_id=?').bind(meta.operation),
  ]);
  return { clientId, redirectUri: redirect.uri };
}

export async function disableClient(db, clientId, actor, reason) {
  const meta = metadata(actor, reason);
  await db.batch([
    db
      .prepare('UPDATE client SET active=0,revision=revision+1 WHERE client_id=? AND active=1')
      .bind(clientId),
    db
      .prepare(
        'INSERT INTO atomic_guard(operation_id,passed) VALUES(?,CASE WHEN changes()=1 THEN 1 ELSE 0 END)',
      )
      .bind(meta.operation),
    audit(db, meta, clientId, 'disable'),
    db.prepare('DELETE FROM atomic_guard WHERE operation_id=?').bind(meta.operation),
  ]);
  return { clientId };
}

export async function listClients(db) {
  return db
    .prepare(
      "SELECT c.client_id,c.revision,c.active,c.auth_method,c.sector_identifier,(SELECT json_group_array(json_object('uri',redirect_uri,'active',active)) FROM client_redirect_uri WHERE client_id=c.client_id) AS redirect_uris,(SELECT json_group_array(json_object('kid',kid,'revision',revision,'active',active,'algorithm',algorithm,'public_key_sec1_hex',hex(public_key_sec1))) FROM client_key WHERE client_id=c.client_id) AS keys FROM client c ORDER BY c.client_id",
    )
    .all();
}
