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
  rewrapOwnerKey,
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
    // Registering a login credential does not authorize it to decrypt this Vault.
    // Authorize an opaque rewrap of the SAME key, fenced by the current head revision.
    const wrapsUrl = url + '/wrappers';
    const targetOutput = new Uint8Array(randomBytes(32));
    const targetBytes = new Uint8Array(Buffer.from(secondCredential, 'base64url'));
    const targetEnvelope = await rewrapOwnerKey(
      created.envelope,
      context,
      credential,
      output.slice(),
      targetBytes,
      new Uint8Array(randomBytes(32)),
      targetOutput.slice(),
    );
    const wrapPayload = { ...payload, owner_envelope: targetEnvelope };
    const wrapBody = JSON.stringify(wrapPayload);
    const wrapHeaders = (id: string, revision: number, cookie = primary.secret) => {
      const { 'If-None-Match': _, ...rest } = headers(id, cookie);
      return { ...rest, 'If-Match': `"${revision}"` };
    };
    const change = (
      method: string,
      body: string,
      id = operation(),
      revision = 1,
      cookie = primary.secret,
    ) => worker.fetch(wrapsUrl, { method, headers: wrapHeaders(id, revision, cookie), body });
    assert.equal(
      (await change('PUT', wrapBody, operation(), 1, secondSecret)).status,
      409,
      'Login-only sources cannot grant access',
    );
    assert.equal(
      (
        await change(
          'DELETE',
          JSON.stringify({
            ...payload,
            owner_envelope: undefined,
            credential_id: primary.credential,
          }),
          operation(),
          1,
          secondSecret,
        )
      ).status,
      409,
      'Login-only sources cannot remove access',
    );
    const insert = async (table: string, row: Record<string, unknown>) => {
      const columns = Object.keys(row);
      await env.DB.prepare(
        `INSERT INTO ${table}(${columns.join(',')}) VALUES(${columns.map(() => '?').join(',')})`,
      )
        .bind(...Object.values(row))
        .run();
    };
    const recipientId = operation(),
      ciphertextHash = operation();
    const grantNow = Math.floor(Date.now() / 1000);
    const frame = new Uint8Array(1187);
    frame.set([0x4d, 0x4b, 0x56, 0x52, 2]);
    await insert('vault_recipient_key', {
      key_id: recipientId,
      service_id: 'userinfo',
      algorithm: 'ML-KEM-768',
      public_key: new Uint8Array(1184),
      secret_ref: 'fixture-recipient',
      generation: 1,
      state: 'staged',
      revision: 1,
      created_at: grantNow,
      activated_at: null,
      retired_at: null,
    });
    await env.DB.prepare(
      "UPDATE vault_recipient_key SET state='active',revision=2,activated_at=? WHERE key_id=?",
    )
      .bind(grantNow, recipientId)
      .run();
    await env.DB.prepare(
      'UPDATE vault_record_share_policy SET enabled=1,revision=revision+1 WHERE id=1',
    ).run();
    await insert('vault_owner_record_head', {
      account_id: 'owner',
      vault_id: 'vault',
      collection_id: 'personal',
      record_id: 'name',
      kind: 'name',
      revision: 1,
      key_generation: 1,
      format_version: 2,
      object_key: 'fixture/name',
      ciphertext_sha256: ciphertextHash,
      key_envelope: 'a'.repeat(82),
      deleted: 0,
      updated_at: grantNow,
    });
    const seedGrants = async (rootRevision: number) => {
      const id = operation(),
        envelopeId = operation();
      await insert('agent_grant', {
        grant_id: id,
        account_id: 'owner',
        owner_epoch: 1,
        credential_id: primary.credential,
        delegate: 'agent',
        provider: 'test',
        resource: 'https://agent.test/mcp',
        source_revision: 1,
        recipient_key_id: 'fixture-agent',
        operations: '["read"]',
        document_ids: '["name"]',
        encrypted_snapshot: 'opaque',
        token_hash: operation(),
        request_hash: operation(),
        created_at: grantNow,
        expires_at: grantNow + 3600,
        storage_version: 2,
        source_origin: context.origin,
        source_vault_id: 'vault',
        source_collection_id: 'personal',
        source_record_id: 'name',
        source_kind: 'name',
        source_ciphertext_sha256: ciphertextHash,
        source_key_generation: 1,
        source_owner_key_revision: rootRevision,
      });
      const identity = {
        account_id: 'owner',
        origin: context.origin,
        vault_id: 'vault',
        collection_id: 'personal',
        record_id: 'name',
        kind: 'name',
        record_revision: 1,
        ciphertext_sha256: ciphertextHash,
        key_generation: 1,
        owner_key_revision: rootRevision,
        recipient_service: 'userinfo',
        purpose: 'oidc.userinfo.name',
        envelope_id: envelopeId,
      };
      await insert('vault_record_recipient_envelope', {
        ...identity,
        recipient_key_id: recipientId,
        recipient_generation: 1,
        directory_revision: 2,
        policy_revision: 2,
        suite: 'ML-KEM-768-HKDF-SHA256-AES-256-GCM-draft04-record-v2',
        frame,
        created_at: grantNow,
      });
      await env.DB.prepare("DELETE FROM vault_record_grant WHERE account_id='owner'").run();
      await insert('vault_record_grant', {
        ...identity,
        version: 1,
        status: 'active',
        expires_at: grantNow + 3600,
        updated_at: grantNow,
      });
      return id;
    };
    const initialGrant = await seedGrants(1);
    assert.equal((await worker.fetch(wrapsUrl)).status, 401);
    assert.equal(
      (await worker.fetch(wrapsUrl, { headers: { Cookie: `__Host-op-sso=${secondSecret}` } }))
        .status,
      409,
    );
    assert.equal(
      (
        await worker.fetch(wrapsUrl, {
          method: 'PUT',
          headers: headers(operation()),
          body: wrapBody,
        })
      ).status,
      428,
    );
    assert.equal(
      (
        await worker.fetch(wrapsUrl, {
          method: 'PUT',
          headers: { ...wrapHeaders(operation(), 1), Origin: 'https://evil.test' },
          body: wrapBody,
        })
      ).status,
      403,
    );
    for (const [bad, status] of [
      [{ ...wrapPayload, key_generation: 2 }, 409],
      [{ ...wrapPayload, vault_id: 'other-vault' }, 409],
      [{ ...wrapPayload, suite: 'unknown' }, 400],
      [{ ...wrapPayload, extra: true }, 400],
      [{ ...wrapPayload, owner_envelope: { ...targetEnvelope, nonce: 'a=' } }, 400],
      [
        { ...wrapPayload, owner_envelope: { ...targetEnvelope, credential_id: other.credential } },
        409,
      ],
    ] as const)
      assert.equal((await change('PUT', JSON.stringify(bad))).status, status);
    assert.equal((await change('PUT', 'x'.repeat(4097))).status, 413);
    await env.DB.prepare('UPDATE credential SET active=0 WHERE credential_id=?')
      .bind(secondCredential)
      .run();
    assert.equal((await change('PUT', wrapBody)).status, 409);
    await env.DB.prepare('UPDATE credential SET active=1 WHERE credential_id=?')
      .bind(secondCredential)
      .run();
    assert.equal((await change('PUT', wrapBody, operation(), 2)).status, 409);
    const wrapOp = operation();
    const wrapResult = await change('PUT', wrapBody, wrapOp);
    assert.equal(wrapResult.status, 200, await wrapResult.clone().text());
    assert.equal(wrapResult.headers.get('etag'), '"2"');
    const wrapReceipt = await wrapResult.json();
    assert.equal(
      (
        await env.DB.prepare('SELECT revoked FROM agent_grant WHERE grant_id=?')
          .bind(initialGrant)
          .first()
      ).revoked,
      1,
    );
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT status FROM vault_record_grant WHERE account_id='owner'",
        ).first()
      ).status,
      'revoked',
    );
    // A lost response can be retried with the original revision/body/operation id.
    assert.deepEqual(await (await change('PUT', wrapBody, wrapOp)).json(), wrapReceipt);
    assert.equal(
      (await change('PUT', wrapBody, wrapOp, 1, secondSecret)).status,
      409,
      'Retry is bound to its original source credential',
    );
    assert.equal(
      (
        await change(
          'PUT',
          JSON.stringify({
            ...wrapPayload,
            owner_envelope: { ...targetEnvelope, nonce: randomBytes(12).toString('base64url') },
          }),
          wrapOp,
        )
      ).status,
      409,
    );
    assert.equal((await change('PUT', wrapBody, operation(), 2)).status, 409);
    const wrappedRead = await worker.fetch(url, {
      headers: { Cookie: `__Host-op-sso=${secondSecret}` },
    });
    assert.equal(wrappedRead.status, 200);
    const targetRead = (await wrappedRead.json()) as { owner_envelope: unknown };
    const targetKey = await openOwnerKey(
      targetRead.owner_envelope,
      context,
      targetBytes,
      targetOutput.slice(),
    );
    assert.equal(
      new TextDecoder().decode(await openOwnerRecord(record, targetKey, context, item)),
      '新しいVaultの会話',
    );
    const list = await worker.fetch(wrapsUrl, {
      headers: { Cookie: `__Host-op-sso=${primary.secret}` },
    });
    assert.equal(list.headers.get('etag'), '"2"');
    assert.equal(((await list.json()) as { credentials: unknown[] }).credentials.length, 2);
    const removeBody = JSON.stringify({
      ...payload,
      owner_envelope: undefined,
      credential_id: secondCredential,
    });
    assert.equal(
      (
        await change(
          'DELETE',
          JSON.stringify({
            ...payload,
            owner_envelope: undefined,
            credential_id: primary.credential,
          }),
          operation(),
          2,
        )
      ).status,
      409,
      'Cannot remove the source/last usable wrapper',
    );
    const removeOp = operation();
    await env.DB.prepare('UPDATE credential SET active=0 WHERE credential_id=?')
      .bind(secondCredential)
      .run();
    const inactiveList = await worker.fetch(wrapsUrl, {
      headers: { Cookie: `__Host-op-sso=${primary.secret}` },
    });
    assert.equal(inactiveList.status, 200);
    const inactiveRegistry = (await inactiveList.json()) as {
      credentials: { credential_id: string; active: number }[];
    };
    assert.deepEqual(
      inactiveRegistry.credentials.find(
        (credential) => credential.credential_id === secondCredential,
      ),
      { credential_id: secondCredential, active: 0 },
    );
    assert.equal(
      (
        await change(
          'DELETE',
          JSON.stringify({ ...JSON.parse(removeBody), unexpected: true }),
          operation(),
          2,
        )
      ).status,
      400,
      'Removal rejects unknown fields before mutating the wrapper',
    );
    assert.equal((await change('DELETE', removeBody, removeOp, 2)).status, 200);
    assert.equal((await change('DELETE', removeBody, removeOp, 2)).status, 200);
    await env.DB.prepare('UPDATE credential SET active=1 WHERE credential_id=?')
      .bind(secondCredential)
      .run();
    assert.equal(
      (await worker.fetch(url, { headers: { Cookie: `__Host-op-sso=${secondSecret}` } })).status,
      409,
    );
    // Competing additions at one revision cannot both commit.
    const raceTargets = [
      randomBytes(32).toString('base64url'),
      randomBytes(32).toString('base64url'),
    ];
    for (const target of raceTargets)
      await env.DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(target).run();
    const wrapRace = await Promise.all(
      raceTargets.map((target) =>
        change(
          'PUT',
          JSON.stringify({
            ...wrapPayload,
            owner_envelope: { ...targetEnvelope, credential_id: target },
          }),
          operation(),
          3,
        ),
      ),
    );
    assert.deepEqual(wrapRace.map((r) => r.status).sort(), [200, 409]);
    const wrapperState = await env.DB.prepare(
      "SELECT revision FROM vault_owner_key_head WHERE account_id='owner'",
    ).first();
    assert.equal(wrapperState.revision, 4);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT count(*) AS n FROM vault_owner_key_wrap_operation WHERE account_id='owner'",
        ).first()
      ).n,
      3,
    );
    assert.equal((await env.DB.prepare('SELECT count(*) AS n FROM atomic_guard').first()).n, 0);
    for (const sql of [
      "UPDATE vault_owner_key_wrap_operation SET action='remove' WHERE account_id='owner'",
      "DELETE FROM vault_owner_key_wrap_operation WHERE account_id='owner'",
    ])
      await assert.rejects(() => env.DB.exec(sql), /immutable/);
    // Failure after head/wrapper updates rolls back both, including revocation triggers.
    const failedWrapOp = operation();
    const retainedGrant = await seedGrants(4);
    await env.DB.exec(
      `CREATE TRIGGER reject_owner_receipt BEFORE INSERT ON vault_owner_key_wrap_operation WHEN NEW.operation_id='${failedWrapOp}' BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END`,
    );
    assert.equal((await change('PUT', wrapBody, failedWrapOp, 4)).status, 503);
    assert.equal(
      (
        await env.DB.prepare('SELECT revoked FROM agent_grant WHERE grant_id=?')
          .bind(retainedGrant)
          .first()
      ).revoked,
      0,
    );
    assert.equal(
      (
        await env.DB.prepare('SELECT encrypted_snapshot FROM agent_grant WHERE grant_id=?')
          .bind(retainedGrant)
          .first()
      ).encrypted_snapshot,
      'opaque',
    );
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT status FROM vault_record_grant WHERE account_id='owner'",
        ).first()
      ).status,
      'active',
    );
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT revision FROM vault_owner_key_head WHERE account_id='owner'",
        ).first()
      ).revision,
      4,
    );
    assert.equal(
      (
        await env.DB.prepare('SELECT count(*) AS n FROM vault_owner_key_wrap WHERE credential_id=?')
          .bind(secondCredential)
          .first()
      ).n,
      0,
    );
    assert.equal(
      (
        await env.DB.prepare(
          'SELECT count(*) AS n FROM vault_owner_key_wrap_operation WHERE operation_id=?',
        )
          .bind(failedWrapOp)
          .first()
      ).n,
      0,
    );
    await env.DB.prepare("UPDATE account_security SET epoch=2 WHERE account_id='owner'").run();
    assert.equal((await change('PUT', wrapBody, operation(), 4)).status, 401);
    await env.DB.prepare("UPDATE account_security SET epoch=1 WHERE account_id='owner'").run();
    // The account-wide mutation limit is transactional, while exact retries remain usable.
    let lastRateOperation = '',
      lastRateRevision = 0;
    for (let index = 0; index < 17; index++) {
      lastRateOperation = operation();
      lastRateRevision = 4 + index;
      const result = await change(
        index % 2 === 0 ? 'PUT' : 'DELETE',
        index % 2 === 0 ? wrapBody : removeBody,
        lastRateOperation,
        lastRateRevision,
      );
      assert.equal(result.status, 200, await result.clone().text());
    }
    assert.equal((await change('DELETE', removeBody, operation(), 21)).status, 429);
    assert.equal((await change('PUT', wrapBody, lastRateOperation, lastRateRevision)).status, 200);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT revision FROM vault_owner_key_head WHERE account_id='owner'",
        ).first()
      ).revision,
      21,
    );
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
