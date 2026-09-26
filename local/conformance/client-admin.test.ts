import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { createTestHarness } from 'wrangler';
import {
  addRedirect,
  addPostLogoutRedirect,
  addKey,
  disableClient,
  listClients,
  registerClient,
  retireRedirect,
  retirePostLogoutRedirect,
  retireBackchannelLogout,
  retireKey,
  setBackchannelLogout,
  validateRegistration,
} from '../../scripts/client-admin-store.ts';

function key(kid: string) {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const { kty, crv, x, y } = publicKey.export({ format: 'jwk' });
  return { kid, jwk: { kty, crv, x, y } };
}

test('managed RP registration and key changes are audited and constrained', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      { configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    const client_id = randomUUID();
    const registration = {
      client_id,
      sector_identifier: 'rp.example',
      redirect_uris: ['https://rp.example/callback'],
      key: key('first'),
    };
    assert.throws(() =>
      validateRegistration({
        ...registration,
        redirect_uris: ['https://rp.example.evil/callback'],
      }),
    );
    assert.throws(() =>
      validateRegistration({
        ...registration,
        redirect_uris: ['https://rp.example/callback#fragment'],
      }),
    );
    await registerClient(DB, registration, 'operator', 'first RP');
    await assert.rejects(registerClient(DB, registration, 'operator', 'duplicate'));
    assert.equal((await listClients(DB)).results[0].client_id, client_id);
    await assert.rejects(
      retireRedirect(
        DB,
        client_id,
        { redirect_uri: 'https://rp.example/callback' },
        'operator',
        'last URI',
      ),
    );
    await assert.rejects(
      addRedirect(
        DB,
        client_id,
        { redirect_uri: 'https://other.example/callback' },
        'operator',
        'wrong sector',
      ),
    );
    await addRedirect(
      DB,
      client_id,
      { redirect_uri: 'https://rp.example/next-callback' },
      'operator',
      'callback rotation',
    );
    await retireRedirect(
      DB,
      client_id,
      { redirect_uri: 'https://rp.example/callback' },
      'operator',
      'callback rotation complete',
    );
    assert.deepEqual(
      (
        await DB.prepare(
          'SELECT redirect_uri,active FROM client_redirect_uri WHERE client_id=? ORDER BY redirect_uri',
        )
          .bind(client_id)
          .all()
      ).results.map(({ redirect_uri, active }: { redirect_uri: string; active: number }) => [
        redirect_uri,
        active,
      ]),
      [
        ['https://rp.example/callback', 0],
        ['https://rp.example/next-callback', 1],
      ],
    );
    await assert.rejects(
      addPostLogoutRedirect(
        DB,
        client_id,
        { post_logout_redirect_uri: 'https://other.example/logout' },
        'operator',
        'wrong sector',
      ),
    );
    await assert.rejects(
      setBackchannelLogout(
        DB,
        client_id,
        { backchannel_logout_uri: 'https://rp.example.evil/backchannel' },
        'operator',
        'wrong sector',
      ),
    );
    await assert.rejects(
      addPostLogoutRedirect(
        DB,
        client_id,
        { post_logout_redirect_uri: 'https://rp.example/logout#fragment' },
        'operator',
        'fragment',
      ),
    );
    await addPostLogoutRedirect(
      DB,
      client_id,
      { post_logout_redirect_uri: 'https://rp.example/logout/callback' },
      'operator',
      'logout callback',
    );
    await assert.rejects(
      addPostLogoutRedirect(
        DB,
        client_id,
        { post_logout_redirect_uri: 'https://rp.example/logout/callback' },
        'operator',
        'duplicate',
      ),
    );
    await setBackchannelLogout(
      DB,
      client_id,
      { backchannel_logout_uri: 'https://rp.example/backchannel' },
      'operator',
      'notifications',
    );
    await setBackchannelLogout(
      DB,
      client_id,
      { backchannel_logout_uri: 'https://rp.example/next-backchannel' },
      'operator',
      'rotation',
    );
    assert.equal(
      (
        await DB.prepare(
          'SELECT logout_uri FROM client_backchannel_logout_uri WHERE client_id=? AND active=1',
        )
          .bind(client_id)
          .first()
      ).logout_uri,
      'https://rp.example/next-backchannel',
    );
    await retirePostLogoutRedirect(
      DB,
      client_id,
      { post_logout_redirect_uri: 'https://rp.example/logout/callback' },
      'operator',
      'retire callback',
    );
    await retireBackchannelLogout(DB, client_id, 'operator', 'retire notifications');
    assert.equal(
      (
        await DB.prepare('SELECT active FROM client_backchannel_logout_uri WHERE client_id=?')
          .bind(client_id)
          .first()
      ).active,
      0,
    );
    await assert.rejects(retireKey(DB, client_id, 'first', 'operator', 'would remove last key'));
    await addKey(DB, client_id, key('second'), 'operator', 'rotation overlap');
    await retireKey(DB, client_id, 'first', 'operator', 'rotation complete');
    const keys = await DB.prepare(
      'SELECT kid,active FROM client_key WHERE client_id=? ORDER BY kid',
    )
      .bind(client_id)
      .all();
    assert.deepEqual(
      keys.results.map(({ kid, active }: { kid: string; active: number }) => [kid, active]),
      [
        ['first', 0],
        ['second', 1],
      ],
    );
    await disableClient(DB, client_id, 'operator', 'incident');
    assert.equal(
      (await DB.prepare('SELECT active FROM client WHERE client_id=?').bind(client_id).first())
        .active,
      0,
    );
    assert.equal(
      (await DB.prepare('SELECT COUNT(*) AS count FROM client_admin_audit').first()).count,
      11,
    );
  } finally {
    await harness.close();
  }
});
