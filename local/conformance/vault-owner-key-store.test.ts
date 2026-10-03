import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { createTestHarness } from 'wrangler';
import { VaultScope } from '../../crates/worker/ui/vault-lifecycle.ts';
import { openOwnerVault } from '../../crates/worker/ui/vault-owner-store.ts';
import {
  createOwnerKey,
  openOwnerKey,
  sealOwnerRecord,
  openOwnerRecord,
} from '../../crates/worker/ui/vault-owner-crypto.ts';

test('new owner-key bootstrap persists only wrappers; owner/credential scope, exact retries, races and atomic failures', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        vars: { MIKAKI_ISSUER: 'https://mikaki.test' },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const env = await worker.getEnv();
    const future = Math.floor(Date.now() / 1000) + 3600;
    const seed = async (account: string) => {
      const secret = randomBytes(32).toString('base64url'),
        credential = randomBytes(32).toString('base64url');
      await env.DB.batch([
        env.DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account),
        env.DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(credential, account),
        env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,?,0)').bind(
          account,
          account,
          credential,
          future,
        ),
        env.DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(
          account,
          createHash('sha256').update(secret).digest('base64url'),
          future - 3600,
        ),
      ]);
      return { secret, credential };
    };
    const primary = await seed('owner'),
      other = await seed('other');
    const url = 'https://mikaki.test/vault/owner-key';
    const operation = () => randomBytes(32).toString('base64url');
    const headers = (op: string, cookie = primary.secret) => ({
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: 'https://mikaki.test',
      'Content-Type': 'application/json',
      'If-None-Match': '*',
      'X-Operation-ID': op,
    });
    const context = {
      origin: 'https://mikaki.test',
      ownerId: 'owner',
      vaultId: 'vault',
      keyGeneration: 1,
    };
    const output = new Uint8Array(randomBytes(32)),
      credential = new Uint8Array(Buffer.from(primary.credential, 'base64url'));
    const created = await createOwnerKey(
      context,
      credential,
      new Uint8Array(randomBytes(32)),
      output.slice(),
    );
    const payload = {
      format_version: 2,
      suite: 'PRF-HKDF-SHA256-AES256GCM-v2',
      vault_id: 'vault',
      key_generation: 1,
      owner_envelope: created.envelope,
    };
    const body = JSON.stringify(payload),
      op = operation();
    assert.equal((await worker.fetch(url)).status, 401);
    assert.equal(
      (await worker.fetch(url, { headers: { Cookie: `__Host-op-sso=${primary.secret}` } })).status,
      404,
    );
    assert.equal(
      (
        await worker.fetch(url, {
          method: 'PUT',
          headers: { ...headers(op), Origin: 'https://evil.test' },
          body,
        })
      ).status,
      403,
    );
    assert.equal(
      (
        await worker.fetch(url, {
          method: 'PUT',
          headers: { Cookie: `__Host-op-sso=${primary.secret}`, Origin: 'https://mikaki.test' },
          body,
        })
      ).status,
      428,
    );
    for (const bad of [
      { ...payload, key_generation: 2 },
      { ...payload, suite: 'unknown' },
      { ...payload, extra: true },
      { ...payload, owner_envelope: { ...created.envelope, credential_id: other.credential } },
      { ...payload, owner_envelope: { ...created.envelope, nonce: 'a=' } },
    ]) {
      assert.equal(
        (
          await worker.fetch(url, {
            method: 'PUT',
            headers: headers(operation()),
            body: JSON.stringify(bad),
          })
        ).status,
        400,
      );
    }
    assert.equal(
      (
        await worker.fetch(url, {
          method: 'PUT',
          headers: headers(operation()),
          body: 'x'.repeat(4097),
        })
      ).status,
      413,
    );
    const first = await worker.fetch(url, { method: 'PUT', headers: headers(op), body });
    assert.equal(first.status, 200, await first.clone().text());
    assert.equal(first.headers.get('etag'), '"1"');
    const retry = await worker.fetch(url, { method: 'PUT', headers: headers(op), body });
    assert.equal(retry.status, 200);
    assert.equal(
      (
        await worker.fetch(url, {
          method: 'PUT',
          headers: headers(op),
          body: JSON.stringify({ ...payload, vault_id: 'changed' }),
        })
      ).status,
      409,
    );
    assert.equal(
      (await worker.fetch(url, { method: 'PUT', headers: headers(operation()), body })).status,
      409,
    );
    const read = await worker.fetch(url, {
      headers: { Cookie: `__Host-op-sso=${primary.secret}` },
    });
    assert.equal(read.headers.get('cache-control'), 'no-store');
    const result = (await read.json()) as {
      owner_id: string;
      origin: string;
      vault_id: string;
      key_generation: number;
      owner_envelope: unknown;
    };
    assert.equal(result.owner_id, 'owner');
    assert.equal(result.origin, context.origin);
    const reopened = await openOwnerKey(result.owner_envelope, context, credential, output.slice());
    const item = {
      collectionId: 'conversations',
      recordId: 'message',
      kind: 'message',
      revision: 1,
    };
    const record = await sealOwnerRecord(
      new TextEncoder().encode('新しいVaultの会話'),
      created.key,
      context,
      item,
    );
    assert.equal(
      new TextDecoder().decode(await openOwnerRecord(record, reopened, context, item)),
      '新しいVaultの会話',
    );
    const stored = await env.DB.prepare(
      "SELECT envelope FROM vault_owner_key_wrap WHERE account_id='owner'",
    ).first();
    assert.deepEqual(JSON.parse(stored.envelope), created.envelope);
    assert.equal((await env.VAULT_BLOBS.list()).objects.length, 0);
    assert.equal(
      (await worker.fetch(url, { headers: { Cookie: `__Host-op-sso=${other.secret}` } })).status,
      404,
    );
    const secondCredential = randomBytes(32).toString('base64url'),
      secondSecret = randomBytes(32).toString('base64url');
    await env.DB.batch([
      env.DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(secondCredential),
      env.DB.prepare("INSERT INTO sso_session VALUES('second','owner',?,1,?,0)").bind(
        secondCredential,
        future,
      ),
      env.DB.prepare("INSERT INTO sso_context VALUES('second',?,?)").bind(
        createHash('sha256').update(secondSecret).digest('base64url'),
        future - 3600,
      ),
    ]);
    const unwrapped = await worker.fetch(url, {
      headers: { Cookie: `__Host-op-sso=${secondSecret}` },
    });
    assert.equal(unwrapped.status, 409);
    assert.deepEqual(await unwrapped.json(), { error: 'credential_not_wrapped' });
    // Concurrent first creation: exactly one head and wrapper survive.
    const race = await seed('race');
    const raceContext = { ...context, ownerId: 'race' };
    const raceKey = await createOwnerKey(
      raceContext,
      new Uint8Array(Buffer.from(race.credential, 'base64url')),
      new Uint8Array(randomBytes(32)),
      new Uint8Array(randomBytes(32)),
    );
    const raceBody = JSON.stringify({ ...payload, owner_envelope: raceKey.envelope });
    const responses = await Promise.all(
      [1, 2].map(() =>
        worker.fetch(url, {
          method: 'PUT',
          headers: headers(operation(), race.secret),
          body: raceBody,
        }),
      ),
    );
    assert.deepEqual(responses.map((r) => r.status).sort(), [200, 409]);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT count(*) AS n FROM vault_owner_key_wrap WHERE account_id='race'",
        ).first()
      ).n,
      1,
    );
    // Failure of the second statement must roll back the newly inserted root head.
    const failed = await seed('failed');
    const failedKey = await createOwnerKey(
      { ...context, ownerId: 'failed' },
      new Uint8Array(Buffer.from(failed.credential, 'base64url')),
      new Uint8Array(randomBytes(32)),
      new Uint8Array(randomBytes(32)),
    );
    await env.DB.exec(
      "CREATE TRIGGER reject_wrap BEFORE INSERT ON vault_owner_key_wrap WHEN NEW.account_id='failed' BEGIN SELECT RAISE(ABORT,'injected failure'); END",
    );
    assert.equal(
      (
        await worker.fetch(url, {
          method: 'PUT',
          headers: headers(operation(), failed.secret),
          body: JSON.stringify({ ...payload, owner_envelope: failedKey.envelope }),
        })
      ).status,
      503,
    );
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT count(*) AS n FROM vault_owner_key_head WHERE account_id='failed'",
        ).first()
      ).n,
      0,
    );
    // A lost successful response does not produce another parent key/ceremony.
    const client = await seed('client');
    const clientOutput = new Uint8Array(randomBytes(32));
    const clientCredential = new Uint8Array(Buffer.from(client.credential, 'base64url'));
    let lost = true,
      ceremonies = 0;
    const transport: typeof fetch = async (input, init) => {
      const path =
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const h = new Headers(init?.headers);
      h.set('Cookie', `__Host-op-sso=${client.secret}`);
      if (init?.method === 'PUT') h.set('Origin', 'https://mikaki.test');
      const response = await worker.fetch(new URL(path, 'https://mikaki.test').href, {
        method: init?.method ?? 'GET',
        headers: Object.fromEntries(h),
        ...(typeof init?.body === 'string' ? { body: init.body } : {}),
      });
      if (lost && init?.method === 'PUT' && response.ok) {
        lost = false;
        throw new TypeError('simulated lost response');
      }
      return new Response(await response.arrayBuffer(), {
        status: response.status,
        headers: Object.fromEntries(response.headers),
      });
    };
    const makeScope = () => {
      const s = new VaultScope(() => {}, undefined, undefined, transport);
      s.observe({
        account_id: 'client',
        credential_id: client.credential,
        session_tag: 's'.repeat(43),
      });
      return s;
    };
    const evaluate = async () => {
      ceremonies++;
      return { credentialId: clientCredential, output: clientOutput.slice() };
    };
    const opened = await openOwnerVault(makeScope(), 'https://mikaki.test', evaluate);
    assert.equal(opened.created, true);
    assert.equal(ceremonies, 1);
    assert.equal(opened.session.opened, true);
    const retained = await opened.session.seal(new TextEncoder().encode('one unlock'), item);
    opened.session.dispose();
    const again = await openOwnerVault(makeScope(), 'https://mikaki.test', evaluate);
    assert.equal(again.created, false);
    assert.equal(ceremonies, 2);
    assert.equal(new TextDecoder().decode(await again.session.open(retained, item)), 'one unlock');
    again.session.dispose();
    await env.DB.prepare('UPDATE credential SET active=0 WHERE credential_id=?')
      .bind(primary.credential)
      .run();
    assert.equal(
      (await worker.fetch(url, { headers: { Cookie: `__Host-op-sso=${primary.secret}` } })).status,
      401,
    );
  } finally {
    await harness.close();
  }
});
