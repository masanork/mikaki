import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, readdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createTestHarness } from 'wrangler';
import { chromium, expect } from '@playwright/test';
import {
  sealAttribute,
  withOpenedAttribute,
  openAttribute,
  encodeBase64Url,
} from '../../crates/worker/ui/vault-crypto.ts';
import {
  sealAgentValue,
  sealAgentSnapshot,
  agentKeyId,
} from '../../crates/worker/ui/agent-crypto.ts';
import {
  newOwnerNote,
  encodeOwnerNote,
  decodeOwnerNote,
} from '../../crates/worker/ui/vault-note.ts';

const origin = 'https://mikaki.test',
  resource = 'https://agent.mikaki.test/mcp';
const id = () => randomBytes(32).toString('base64url');
const hash = (s: string) => createHash('sha256').update(s).digest('base64url');

test('0017 preserves populated 0016 proposals and foreign keys', async () => {
  const db = new DatabaseSync(':memory:');
  const folder = new URL('../../crates/worker/migrations/', import.meta.url);
  try {
    db.exec('PRAGMA foreign_keys=ON');
    for (const file of (await readdir(folder))
      .filter((f) => f.endsWith('.sql') && f < '0017')
      .sort())
      db.exec(await readFile(new URL(file, folder), 'utf8'));
    db.exec(`INSERT INTO account_security VALUES('owner',1,1);
      INSERT INTO credential VALUES('key','owner',1);
      INSERT INTO agent_grant(grant_id,account_id,owner_epoch,credential_id,delegate,provider,resource,source_revision,recipient_key_id,operations,document_ids,token_hash,request_hash,created_at,expires_at)
      VALUES('grant','owner',1,'key','delegate','provider','https://agent.test/mcp',1,'recipient','["propose"]','["name"]','token','hash',1000,2000);`);
    for (const state of ['pending', 'approved', 'rejected', 'invalid'])
      db.prepare(
        `INSERT INTO agent_attribute_proposal VALUES(?,'grant',1,?,'owner_note',0,?,2000,1000,?)`,
      ).run(
        state,
        hash(state),
        state === 'pending' || state === 'approved' ? 'unchanged fixture' : null,
        state,
      );
    const before = db.prepare('SELECT * FROM agent_attribute_proposal ORDER BY proposal_id').all();
    db.exec(await readFile(new URL('0017_agent_attribute_commit.sql', folder), 'utf8'));
    assert.deepEqual(
      db.prepare('SELECT * FROM agent_attribute_proposal ORDER BY proposal_id').all(),
      before,
    );
    assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(), []);
    assert.throws(() =>
      db.exec("UPDATE agent_attribute_proposal SET state='pending' WHERE state='rejected'"),
    );
  } finally {
    db.close();
  }
});

test('approved note commits exact ciphertext once; proof, failures, retries, conflicts and browser recovery preserve authority', async () => {
  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey),
    publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey),
    keyId = await agentKeyId(publicJwk);
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-commit-'));
  // Fault injection wraps the real OP entrypoint, changing only R2.put for a test flag.
  const shim = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  await writeFile(
    `${directory}/op.mjs`,
    `import Op from ${JSON.stringify(shim)};
    export default {async fetch(request,env,ctx){
      const row=await env.DB.prepare('SELECT enabled FROM commit_test_fault').first();
      const bucket=new Proxy(env.VAULT_BLOBS,{get(target,key){
        if(key==='constructor') return target.constructor;
        if(key==='put' && row?.enabled===1) return ()=>Promise.reject(new Error('injected R2 upload failure'));
        const value=Reflect.get(target,key,target);return typeof value==='function'?value.bind(target):value;
      }});
      return new Op(ctx,{...env,VAULT_BLOBS:bucket}).fetch(request);
    }};`,
  );
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        config: {
          name: 'mikaki-op-agent-local',
          main: `${directory}/op.mjs`,
          compatibility_date: '2026-09-28',
          d1_databases: [
            {
              binding: 'DB',
              database_name: 'mikaki-op-dev',
              database_id: '00000000-0000-0000-0000-000000000000',
              migrations_dir: new URL('../../crates/worker/migrations/', import.meta.url).pathname,
            },
          ],
          r2_buckets: [{ binding: 'VAULT_BLOBS', bucket_name: 'mikaki-vault-dev' }],
          services: [
            { binding: 'AGENT_ACCESS', service: 'mikaki-agent-local', entrypoint: 'OwnerAgents' },
          ],
        },
      },
      {
        configPath: new URL('../../crates/agent-worker/wrangler.local.jsonc', import.meta.url)
          .pathname,
        secrets: { AGENT_PRIVATE_JWK: JSON.stringify(privateJwk) },
      },
    ],
  });
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-agent-local'),
      agent = harness.getWorker('mikaki-agent-local');
    await op.applyD1Migrations('DB');
    const env = await op.getEnv();
    await env.DB.exec(
      'CREATE TABLE commit_test_fault(enabled INTEGER); INSERT INTO commit_test_fault VALUES(0)',
    );
    await env.DB.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").bind(keyId).run();
    const time = Math.floor(Date.now() / 1000),
      cookie = id(),
      otherCookie = id(),
      credential = new Uint8Array(randomBytes(32)),
      prf = new Uint8Array(32).fill(0x34);
    for (const [account, secret] of [
      ['owner', cookie],
      ['other', otherCookie],
    ])
      await env.DB.batch([
        env.DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account),
        env.DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(
          account === 'owner' ? encodeBase64Url(credential) : 'other-key',
          account,
        ),
        env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,?,0)').bind(
          account,
          account,
          account === 'owner' ? encodeBase64Url(credential) : 'other-key',
          time + 3600,
        ),
        env.DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(account, hash(secret), time),
      ]);
    const headers = {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: origin,
      'Content-Type': 'application/json',
    };
    const ownerCall = (path: string, body: unknown) =>
      op.fetch(`${origin}/vault/agents/${path}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      });
    const write = async (attribute: string, bytes: Uint8Array<ArrayBuffer>, revision: number) => {
      const sealed = await sealAttribute(
        bytes,
        prf,
        credential,
        new Uint8Array(32).fill(0x27),
        origin,
        attribute,
        revision,
      );
      const response = await op.fetch(`${origin}/vault/attributes/${attribute}`, {
        method: 'PUT',
        headers: {
          ...headers,
          'X-Operation-ID': id(),
          ...(revision === 1 ? { 'If-None-Match': '*' } : { 'If-Match': `"${revision - 1}"` }),
        },
        body: JSON.stringify(sealed),
      });
      assert.equal(response.status, 200, await response.clone().text());
    };
    await write('name', new TextEncoder().encode('Owner name'), 1);
    const note = async () =>
      (await (
        await op.fetch(`${origin}/vault/attributes/owner_note`, { headers })
      ).json()) as Awaited<ReturnType<typeof sealAttribute>> & { revision: number };
    const propose = async (base: number) => {
      const grantId = id(),
        token = `mag_${id()}`,
        expiry = time + 1200;
      const envelope = await sealAgentSnapshot(
        [{ id: 'name', title: 'Name', source: 'vault:name:1', text: 'Owner name' }],
        { key_id: keyId, public_jwk: publicJwk, resource },
        {
          owner: 'owner',
          grant_id: grantId,
          key_id: keyId,
          resource,
          expires_at: time + 1800,
          source_revision: 1,
        },
      );
      assert.equal(
        (
          await ownerCall('grants', {
            grant_id: grantId,
            delegate: 'synthetic-agent',
            provider: 'fixture',
            resource,
            source_revision: 1,
            recipient_key_id: keyId,
            operations: ['read', 'propose', 'execute'],
            document_ids: ['name'],
            envelope,
            token_hash: hash(token),
            expires_at: time + 1800,
          })
        ).status,
        200,
      );
      assert.equal(
        (
          await ownerCall('attribute-capability', {
            grant_id: grantId,
            attribute_id: 'owner_note',
            base_revision: base,
          })
        ).status,
        200,
      );
      const value = newOwnerNote(`Proposed ${base}`, 'Exact approved value 🗾');
      const proposalId = id();
      const response = await agent.fetch('https://agent.mikaki.test/attribute-proposals', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proposal_id: proposalId,
          attribute_id: 'owner_note',
          base_revision: base,
          value,
          expires_at: expiry,
        }),
      });
      assert.equal(response.status, 200, await response.clone().text());
      const result = (await response.json()) as { content: { text: string }[] };
      const receipt = JSON.parse(result.content[0]!.text) as { request_hash: string };
      return {
        proposal_id: proposalId,
        request_hash: receipt.request_hash,
        base_revision: base,
        grant_id: grantId,
        value,
        expires_at: expiry,
      };
    };
    const candidate = async (
      p: Awaited<ReturnType<typeof propose>>,
      value = p.value,
      selectedCredential = credential,
      purpose:
        | 'mikaki-agent-snapshot'
        | 'mikaki-approved-attribute-proof' = 'mikaki-approved-attribute-proof',
      serialize: (value: Awaited<ReturnType<typeof sealAttribute>>) => string = JSON.stringify,
    ) => {
      const sealed = await sealAttribute(
        encodeOwnerNote(value),
        prf,
        selectedCredential,
        new Uint8Array(32).fill(0x27),
        origin,
        'owner_note',
        p.base_revision + 1,
      );
      return withOpenedAttribute(
        sealed,
        prf,
        selectedCredential,
        origin,
        'owner_note',
        p.base_revision + 1,
        async (bytes, key) => {
          try {
            const body = serialize(sealed);
            const proof = await sealAgentValue(
              {
                proposal_id: p.proposal_id,
                request_hash: p.request_hash,
                candidate_sha256: hash(body),
                data_key: encodeBase64Url(key),
              },
              { key_id: keyId, public_jwk: publicJwk, resource },
              {
                owner: 'owner',
                grant_id: p.grant_id,
                key_id: keyId,
                resource,
                expires_at: p.expires_at,
                source_revision: p.base_revision + 1,
              },
              purpose,
            );
            return {
              proposal_id: p.proposal_id,
              request_hash: p.request_hash,
              operation_id: id(),
              candidate: body,
              proof,
            };
          } finally {
            bytes.fill(0);
          }
        },
      );
    };
    const commit = (
      p: Awaited<ReturnType<typeof propose>>,
      c: Awaited<ReturnType<typeof candidate>>,
      overrides: Record<string, string> = {},
      body = c.candidate,
      secret = cookie,
      attribute = 'owner_note',
    ) =>
      op.fetch(`${origin}/vault/attributes/${attribute}/approved`, {
        method: 'POST',
        headers: {
          ...headers,
          Cookie: `__Host-op-sso=${secret}`,
          'X-Operation-ID': c.operation_id,
          'X-Attribute-Proposal': p.proposal_id,
          'X-Proposal-Hash': p.request_hash,
          ...(p.base_revision === 0
            ? { 'If-None-Match': '*' }
            : { 'If-Match': `"${p.base_revision}"` }),
          ...overrides,
        },
        body,
      });
    const p = await propose(0),
      c = await candidate(p);
    assert.equal((await ownerCall('attribute-prepare', c)).status, 409);
    assert.equal((await commit(p, c)).status, 409);
    assert.equal(
      (
        await ownerCall('attribute-decide', {
          proposal_id: p.proposal_id,
          request_hash: p.request_hash,
          approve: true,
        })
      ).status,
      200,
    );
    assert.equal(
      (
        await ownerCall(
          'attribute-prepare',
          await candidate(p, newOwnerNote('Altered', 'Not approved')),
        )
      ).status,
      409,
    );
    assert.equal(
      (
        await ownerCall(
          'attribute-prepare',
          await candidate(p, p.value, credential, 'mikaki-agent-snapshot'),
        )
      ).status,
      409,
    );
    for (const serialize of [
      (value: { format_version: number }) => JSON.stringify(value) + '\n',
      (value: { format_version: number }) =>
        JSON.stringify(value).replace('{', '{"format_version":1,'),
    ]) {
      assert.equal(
        (
          await ownerCall(
            'attribute-prepare',
            await candidate(p, p.value, credential, 'mikaki-approved-attribute-proof', serialize),
          )
        ).status,
        409,
      );
    }
    await env.DB.prepare(
      "CREATE TRIGGER fail_prepare BEFORE INSERT ON agent_audit WHEN NEW.operation='attribute-prepare' BEGIN SELECT RAISE(ABORT,'audit failure'); END",
    ).run();
    assert.equal((await ownerCall('attribute-prepare', c)).status, 409);
    assert.equal(
      (await env.DB.prepare('SELECT count(*) n FROM agent_attribute_commit').first()).n,
      0,
    );
    await env.DB.prepare('DROP TRIGGER fail_prepare').run();
    const ready = await ownerCall('attribute-prepare', c);
    assert.equal(ready.status, 200, await ready.clone().text());
    assert.equal((await ownerCall('attribute-prepare', c)).status, 200);
    assert.equal((await ownerCall('attribute-prepare', await candidate(p))).status, 409);
    assert.equal((await commit(p, c, {}, c.candidate + ' ')).status, 409);
    assert.equal((await commit(p, c, { 'X-Operation-ID': id() })).status, 409);
    assert.equal((await commit(p, c, {}, c.candidate, otherCookie)).status, 409);
    assert.equal((await commit(p, c, {}, c.candidate, cookie, 'name')).status, 400);
    await env.DB.prepare('UPDATE commit_test_fault SET enabled=1').run();
    assert.ok((await commit(p, c)).status >= 500);
    assert.equal(
      (
        await env.DB.prepare('SELECT state FROM agent_attribute_proposal WHERE proposal_id=?')
          .bind(p.proposal_id)
          .first()
      ).state,
      'approved',
    );
    await env.DB.prepare('UPDATE commit_test_fault SET enabled=0').run();
    await env.DB.prepare(
      "CREATE TRIGGER fail_commit BEFORE INSERT ON agent_audit WHEN NEW.outcome='committed' BEGIN SELECT RAISE(ABORT,'audit failure'); END",
    ).run();
    assert.equal((await commit(p, c)).status, 503);
    assert.equal(
      (await op.fetch(`${origin}/vault/attributes/owner_note`, { headers })).status,
      404,
    );
    await env.DB.prepare('DROP TRIGGER fail_commit').run();
    // A failure after head and ledger operations rolls all of them back as well.
    await env.DB.prepare(
      "CREATE TRIGGER fail_result BEFORE UPDATE ON agent_attribute_commit BEGIN SELECT RAISE(ABORT,'result failure'); END",
    ).run();
    assert.equal((await commit(p, c)).status, 503);
    assert.equal(
      (
        await env.DB.prepare(
          'SELECT state,payload FROM agent_attribute_proposal WHERE proposal_id=?',
        )
          .bind(p.proposal_id)
          .first()
      ).state,
      'approved',
    );
    assert.equal(
      (await op.fetch(`${origin}/vault/attributes/owner_note`, { headers })).status,
      404,
    );
    await env.DB.prepare('DROP TRIGGER fail_result').run();
    const results = await Promise.all([commit(p, c), commit(p, c)]);
    for (const response of results)
      assert.equal(response.status, 200, await response.clone().text());
    assert.equal((await note()).revision, 1);
    assert.equal(
      (await env.DB.prepare("SELECT count(*) n FROM agent_audit WHERE outcome='committed'").first())
        .n,
      1,
    );
    const saved = await note();
    assert.deepEqual(
      decodeOwnerNote(await openAttribute(saved, prf, credential, origin, 'owner_note', 1)),
      p.value,
    );
    assert.equal(
      (
        await env.DB.prepare('SELECT payload FROM agent_attribute_proposal WHERE proposal_id=?')
          .bind(p.proposal_id)
          .first()
      ).payload,
      null,
    );
    // Historical acknowledgment is still safe after a newer owner edit and source invalidation.
    await write('owner_note', encodeOwnerNote(newOwnerNote('Owner edit', 'Newer value')), 2);
    assert.equal((await commit(p, c)).status, 200);
    assert.equal((await commit(p, c, { 'X-Proposal-Hash': id() })).status, 409);
    const stale = await propose(2),
      staleC = await candidate(stale);
    await ownerCall('attribute-decide', {
      proposal_id: stale.proposal_id,
      request_hash: stale.request_hash,
      approve: true,
    });
    assert.equal((await ownerCall('attribute-prepare', staleC)).status, 200);
    await write('owner_note', encodeOwnerNote(newOwnerNote('Concurrent owner', 'Wins')), 3);
    assert.equal((await commit(stale, staleC)).status, 409);
    const revoked = await propose(3),
      revokedC = await candidate(revoked);
    await ownerCall('attribute-decide', {
      proposal_id: revoked.proposal_id,
      request_hash: revoked.request_hash,
      approve: true,
    });
    await ownerCall('attribute-prepare', revokedC);
    await ownerCall('revoke', { grant_id: revoked.grant_id });
    assert.equal((await commit(revoked, revokedC)).status, 409);
    // Browser: absent PRF/unknown existing schemas cannot prepare; saved values reopen.
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.addInitScript(
      ({ credential, prf }) => {
        class MockCredential {
          rawId = Uint8Array.from(credential).buffer;
          getClientExtensionResults() {
            return Reflect.get(window, 'missingPrf')
              ? {}
              : { prf: { results: { first: Uint8Array.from(prf).buffer } } };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: { get: async () => new MockCredential() },
        });
      },
      { credential: [...credential], prf: [...prf] },
    );
    let loseCommit = true;
    const requests: string[] = [];
    await page.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const response = await op.fetch(request.url(), {
        method: request.method(),
        headers: { ...request.headers(), Cookie: `__Host-op-sso=${cookie}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      if (request.url().endsWith('/approved')) {
        requests.push(request.postData()!);
        if (loseCommit) {
          loseCommit = false;
          await route.abort();
          return;
        }
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    const browserP = await propose(3);
    await ownerCall('attribute-decide', {
      proposal_id: browserP.proposal_id,
      request_hash: browserP.request_hash,
      approve: true,
    });
    await page.goto(`${origin}/vault?lang=en&storage=legacy-v1`);
    await page.getByRole('link', { name: 'Sharing & connections', exact: true }).click();
    const panel = page.getByRole('region', { name: 'Share with an AI agent' });
    const saveButton = panel.getByRole('button', {
      name: 'Encrypt and save the approved note',
      exact: true,
    });
    await page.evaluate(() => Reflect.set(window, 'missingPrf', true));
    await saveButton.click();
    await expect(panel.getByRole('status')).toContainText('Could not commit.');
    assert.equal(requests.length, 0);
    await page.evaluate(() => Reflect.set(window, 'missingPrf', false));
    await saveButton.click();
    await expect(
      panel.getByRole('button', { name: 'Retry the same encrypted commit', exact: true }),
    ).toBeVisible();
    await panel
      .getByRole('button', { name: 'Retry the same encrypted commit', exact: true })
      .click();
    await expect(panel.getByRole('status')).toContainText('Approved note encrypted and saved');
    assert.equal(requests.length, 2);
    assert.equal(requests[0], requests[1]);
    await page.reload();
    const notePanel = page.getByRole('region', { name: 'Owner note', exact: true });
    await notePanel.getByRole('button', { name: 'Open note', exact: true }).click();
    await expect(notePanel.getByLabel('Note title', { exact: true })).toHaveValue('Proposed 3');
    // Prepare on one client, recover the immutable encrypted candidate after a fresh page load.
    const recovery = await propose(4),
      recoveryC = await candidate(recovery);
    await ownerCall('attribute-decide', {
      proposal_id: recovery.proposal_id,
      request_hash: recovery.request_hash,
      approve: true,
    });
    await ownerCall('attribute-prepare', recoveryC);
    await page.reload();
    await saveButton.click();
    await expect(panel.getByRole('status')).toContainText('Approved note encrypted and saved');
    assert.equal(requests.at(-1), recoveryC.candidate);
    assert.equal((await note()).revision, 5);
    await write(
      'owner_note',
      new TextEncoder().encode(
        JSON.stringify({ ...newOwnerNote('Future', 'Protected'), version: 2 }),
      ),
      6,
    );
    const unknown = await propose(6);
    await ownerCall('attribute-decide', {
      proposal_id: unknown.proposal_id,
      request_hash: unknown.request_hash,
      approve: true,
    });
    await page.reload();
    await saveButton.click();
    await expect(panel.getByRole('status')).toContainText('Could not commit.');
    assert.equal((await note()).revision, 6);
    const deleted = await op.fetch(`${origin}/vault/attributes/owner_note`, {
      method: 'DELETE',
      headers: { ...headers, 'X-Operation-ID': id(), 'If-Match': '"6"' },
    });
    assert.equal(deleted.status, 200);
    const recreate = await propose(7),
      recreateC = await candidate(recreate);
    await ownerCall('attribute-decide', {
      proposal_id: recreate.proposal_id,
      request_hash: recreate.request_hash,
      approve: true,
    });
    assert.equal((await ownerCall('attribute-prepare', recreateC)).status, 200);
    assert.equal((await commit(recreate, recreateC)).status, 200);
    assert.equal((await note()).revision, 8);
    // A prepared, formerly valid record cannot be applied once its deadline passes.
    const expiryBase = await propose(8);
    const expired = { ...expiryBase, proposal_id: id(), request_hash: id(), expires_at: time - 1 };
    const expiredC = await candidate(expired);
    await env.DB.prepare(
      `INSERT INTO agent_attribute_proposal
      (proposal_id,grant_id,grant_revision,request_hash,attribute_id,base_revision,payload,expires_at,created_at,state)
      VALUES(?,?,1,?,'owner_note',8,?,?,?,'approved')`,
    )
      .bind(
        expired.proposal_id,
        expiryBase.grant_id,
        expired.request_hash,
        JSON.stringify(expired.value),
        time - 1,
        time - 100,
      )
      .run();
    await env.DB.prepare(
      'INSERT INTO agent_attribute_commit(proposal_id,account_id,operation_id,candidate,candidate_sha256,origin,prepared_at,result_revision) VALUES(?,?,?,?,?,?,?,NULL)',
    )
      .bind(
        expired.proposal_id,
        'owner',
        expiredC.operation_id,
        expiredC.candidate,
        hash(expiredC.candidate),
        origin,
        time - 100,
      )
      .run();
    assert.equal((await commit(expired, expiredC)).status, 409);
    const stopped = await propose(8),
      stoppedC = await candidate(stopped);
    await ownerCall('attribute-decide', {
      proposal_id: stopped.proposal_id,
      request_hash: stopped.request_hash,
      approve: true,
    });
    await ownerCall('attribute-prepare', stoppedC);
    await env.DB.prepare('UPDATE credential SET active=0 WHERE credential_id=?')
      .bind(encodeBase64Url(credential))
      .run();
    assert.equal((await commit(stopped, stoppedC)).status, 401);
    await env.DB.prepare('UPDATE credential SET active=1 WHERE credential_id=?')
      .bind(encodeBase64Url(credential))
      .run();
    assert.equal((await commit(stopped, stoppedC)).status, 409);
    const foreign = await propose(8);
    await ownerCall('attribute-decide', {
      proposal_id: foreign.proposal_id,
      request_hash: foreign.request_hash,
      approve: true,
    });
    const foreignC = await candidate(foreign, foreign.value, new TextEncoder().encode('other-key'));
    assert.equal((await ownerCall('attribute-prepare', foreignC)).status, 200);
    assert.equal((await commit(foreign, foreignC)).status, 403);
    const retired = await propose(8),
      retiredC = await candidate(retired);
    await ownerCall('attribute-decide', {
      proposal_id: retired.proposal_id,
      request_hash: retired.request_hash,
      approve: true,
    });
    await ownerCall('attribute-prepare', retiredC);
    await env.DB.prepare("UPDATE agent_recipient_key SET state='disabled' WHERE key_id=?")
      .bind(keyId)
      .run();
    assert.equal((await commit(retired, retiredC)).status, 409);
    assert.equal((await commit(p, c)).status, 200);
    assert.equal((await note()).revision, 8);
    assert.deepEqual(errors, []);
  } finally {
    await browser?.close();
    await harness.close();
    await rm(directory, { recursive: true, force: true });
  }
});
