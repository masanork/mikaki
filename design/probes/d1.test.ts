import assert from 'node:assert/strict';
import { after, before, beforeEach, test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { getPlatformProxy } from 'wrangler';

let proxy;
let db;
const sql = (name) =>
  readFileSync(new URL(`../sql/${name}`, import.meta.url), 'utf8')
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('--'))
    .join('\n')
    .split(';')
    .map((statement) => statement.trim())
    .filter(Boolean);

function prepared(name, parameters) {
  return sql(name).map((statement) => {
    const values = [];
    const positional = statement.replace(/:([a-z_]+)/g, (_, key) => {
      assert.ok(Object.hasOwn(parameters, key), `missing parameter ${key}`);
      values.push(parameters[key]);
      return '?';
    });
    return db.prepare(positional).bind(...values);
  });
}
const batch = (name, parameters) => db.batch(prepared(name, parameters));
const scalar = async (statement) => (await db.prepare(statement).raw())[0][0];
const parameters = (id = 'one') => ({
  client_id: 'c',
  client_kid: 'ck',
  client_key_revision: 1,
  jti: `jti-${id}`,
  endpoint: 'https://login.example/token',
  operation_id: `exchange-${id}`,
  assertion_operation_id: `assertion-${id}`,
  retain_until: Math.floor(Date.now() / 1000) + 300,
  code_hash: 'codehash',
  redirect_uri: 'https://app.example/cb',
  pkce_challenge: 'challenge',
  signing_kid: 'opk',
  signing_generation: 1,
  access_hash: `access-${id}`,
  access_expires_at: Math.floor(Date.now() / 1000) + 300,
});

before(async () => {
  proxy = await getPlatformProxy({
    configPath: fileURLToPath(new URL('wrangler.jsonc', import.meta.url)),
    persist: false,
    remoteBindings: false,
    envFiles: [],
  });
  db = proxy.env.DB;
  for (const statement of sql('oidc-critical-schema.sql')) {
    await db.prepare(statement).run();
  }
});
after(async () => {
  await proxy?.dispose();
});

beforeEach(async () => {
  const tables = [
    'atomic_guard',
    'revocation_event',
    'token_issue',
    'assertion_use',
    'authorization_code',
    'client_session',
    'sso_session',
    'app_connection',
    'signing_key',
    'client_key',
    'client',
    'credential',
    'account_security',
  ];
  await db.batch(tables.map((table) => db.prepare(`DELETE FROM ${table}`)));
  const expiry = Math.floor(Date.now() / 1000) + 3600;
  await db.batch([
    db.prepare("INSERT INTO account_security VALUES('a',0,1)"),
    db.prepare("INSERT INTO credential VALUES('cred','a',1)"),
    db.prepare("INSERT INTO client VALUES('c',1,1)"),
    db.prepare("INSERT INTO client_key VALUES('c','ck',1,1)"),
    db.prepare("INSERT INTO signing_key VALUES('opk',1,1)"),
    db.prepare("INSERT INTO app_connection VALUES('a','c',1,1)"),
    db.prepare("INSERT INTO sso_session VALUES('sso','a','cred',0,?,0)").bind(expiry),
    db.prepare("INSERT INTO client_session VALUES('c','sid','sso','a','sub',1,0)"),
    db
      .prepare(
        "INSERT INTO authorization_code VALUES('codehash','c','sid',1,'https://app.example/cb','challenge',?,NULL,NULL)",
      )
      .bind(expiry),
  ]);
});

test('successful exchange activates sid; session API first-primary query runs', async () => {
  const p = parameters();
  assert.equal(await scalar('SELECT count(*) FROM valid_client_session'), 0);
  await batch('accept-assertion.sql', p);
  await batch('exchange-code.sql', p);
  const result = await db
    .withSession('first-primary')
    .prepare('SELECT sub FROM valid_client_session')
    .first();
  assert.equal(result.sub, 'sub');
});

test('parallel D1 batches exchange one code only once', async () => {
  const a = parameters('a');
  const b = parameters('b');
  await batch('accept-assertion.sql', a);
  await batch('accept-assertion.sql', b);
  const results = await Promise.allSettled([
    batch('exchange-code.sql', a),
    batch('exchange-code.sql', b),
  ]);
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(await scalar('SELECT count(*) FROM token_issue'), 1);
});

test('zero-row update rolls back while separately consumed assertion remains', async () => {
  const p = parameters();
  await batch('accept-assertion.sql', p);
  p.pkce_challenge = 'wrong';
  await assert.rejects(batch('exchange-code.sql', p), /CHECK/);
  assert.equal(await scalar('SELECT consumed_by FROM authorization_code'), null);
  assert.equal(await scalar('SELECT count(*) FROM assertion_use'), 1);
  assert.equal(await scalar('SELECT count(*) FROM token_issue'), 0);
});

test('constraint error at every SQL boundary rolls back the whole batch', async () => {
  const p = parameters();
  await batch('accept-assertion.sql', p);
  for (let index = 0; index < sql('exchange-code.sql').length; index++) {
    const statements = prepared('exchange-code.sql', p);
    statements.splice(index + 1, 0, db.prepare("INSERT INTO atomic_guard VALUES('failure',0)"));
    await assert.rejects(db.batch(statements), /CHECK/);
    assert.equal(await scalar('SELECT consumed_by FROM authorization_code'), null);
    assert.equal(await scalar('SELECT count(*) FROM token_issue'), 0);
  }
});

test('changes() guards stale epoch; revocation event and epoch are atomic', async () => {
  const p = parameters();
  await batch('accept-assertion.sql', p);
  await batch('exchange-code.sql', p);
  await batch('revoke-all.sql', { account_id: 'a', expected_epoch: 0, operation_id: 'logout' });
  assert.equal(await scalar('SELECT count(*) FROM valid_client_session'), 0);
  await assert.rejects(
    batch('revoke-all.sql', { account_id: 'a', expected_epoch: 0, operation_id: 'stale' }),
    /CHECK/,
  );
  assert.equal(await scalar('SELECT epoch FROM account_security'), 1);
  assert.equal(await scalar('SELECT count(*) FROM revocation_event'), 1);
});

test('expiry, grant change and key stop cannot consume code', async () => {
  const p = parameters();
  await batch('accept-assertion.sql', p);
  for (const [mutation, restore] of [
    [
      'UPDATE authorization_code SET expires_at=0',
      "UPDATE authorization_code SET expires_at=CAST(strftime('%s','now') AS INTEGER)+600",
    ],
    ['UPDATE app_connection SET grant_version=2', 'UPDATE app_connection SET grant_version=1'],
    ['UPDATE signing_key SET active=0', 'UPDATE signing_key SET active=1'],
  ]) {
    await db.prepare(mutation).run();
    await assert.rejects(batch('exchange-code.sql', p), /CHECK/);
    assert.equal(await scalar('SELECT consumed_by FROM authorization_code'), null);
    await db.prepare(restore).run();
  }
});
