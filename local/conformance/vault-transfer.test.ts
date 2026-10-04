import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createECDH, createHash, randomBytes } from 'node:crypto';
import { createTestHarness } from 'wrangler';
import { chromium } from '@playwright/test';
import {
  sealAttribute,
  openAttribute,
  transferAttribute,
} from '../../crates/worker/ui/vault-crypto.ts';

const origin = 'https://mikaki.test';
const id = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');

function registration(credential: Buffer, challenge: string) {
  const key = createECDH('prime256v1');
  key.generateKeys();
  const pub = key.getPublicKey();
  const cose = Buffer.concat([
    Buffer.from('a5010203262001215820', 'hex'),
    pub.subarray(1, 33),
    Buffer.from('225820', 'hex'),
    pub.subarray(33),
  ]);
  const auth = Buffer.concat([
    createHash('sha256').update('mikaki.test').digest(),
    Buffer.from('4500000000', 'hex'),
    Buffer.alloc(16),
    Buffer.from([0, credential.length]),
    credential,
    cose,
  ]);
  const attestation = Buffer.concat([
    Buffer.from('a363666d74646e6f6e656761747453746d74a068617574684461746158', 'hex'),
    Buffer.from([auth.length]),
    auth,
  ]);
  return {
    id: credential.toString('base64url'),
    client_data: Buffer.from(
      JSON.stringify({ type: 'webauthn.create', challenge, origin }),
    ).toString('base64url'),
    attestation: attestation.toString('base64url'),
  };
}

test('same-account registration and transfer enforce freshness, replay, ownership, audit rollback, conflicts, and invalidation', async () => {
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        secrets: { MIKAKI_ISSUER: origin },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const env = await worker.getEnv();
    const source = randomBytes(32),
      target = randomBytes(32),
      outside = randomBytes(32);
    const sourcePrf = new Uint8Array(32).fill(0x23),
      targetPrf = new Uint8Array(32).fill(0x45);
    const secret = id(),
      time = Math.floor(Date.now() / 1000);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      env.DB.prepare("INSERT INTO account_security VALUES('outside',1,1)"),
      env.DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(
        source.toString('base64url'),
      ),
      env.DB.prepare("INSERT INTO credential VALUES(?,'outside',1)").bind(
        outside.toString('base64url'),
      ),
      env.DB.prepare(
        "INSERT INTO passkey_credential VALUES(?,'synthetic-public-key',?,0,0,0,1)",
      ).bind(source.toString('base64url'), id()),
      env.DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(
        source.toString('base64url'),
        time + 3600,
      ),
      env.DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(hash(secret), time),
    ]);
    const headers = {
      Cookie: `__Host-op-sso=${secret}`,
      Origin: origin,
      'Content-Type': 'application/json',
    };
    const start = () => worker.fetch(`${origin}/vault/passkeys/start`, { method: 'POST', headers });
    assert.equal((await worker.fetch(`${origin}/vault/passkeys`)).status, 401);
    assert.equal(
      (
        await worker.fetch(`${origin}/vault/passkeys/start`, {
          method: 'POST',
          headers: { ...headers, Origin: 'https://evil.test' },
        })
      ).status,
      403,
    );
    await env.DB.prepare("UPDATE sso_context SET auth_time=? WHERE sso_id='session'")
      .bind(time - 301)
      .run();
    assert.equal((await start()).status, 403);
    await env.DB.prepare("UPDATE sso_context SET auth_time=? WHERE sso_id='session'")
      .bind(time)
      .run();
    const started = await start();
    assert.equal(started.status, 200, await started.clone().text());
    const options = (await started.json()) as { transaction_id: string; challenge: string };
    const response = registration(target, options.challenge);
    const body = JSON.stringify({ transaction_id: options.transaction_id, response });
    const finish = (content = body) =>
      worker.fetch(`${origin}/vault/passkeys/finish`, { method: 'POST', headers, body: content });
    assert.equal((await finish()).status, 200);
    assert.equal((await finish()).status, 200);
    assert.equal(
      (
        await finish(
          JSON.stringify({
            transaction_id: options.transaction_id,
            response: registration(target, options.challenge),
          }),
        )
      ).status,
      409,
    );
    assert.equal(
      (
        await env.DB.prepare('SELECT count(*) AS n FROM credential WHERE account_id=?')
          .bind('owner')
          .first()
      ).n,
      2,
    );
    const failed = await start();
    const failureOptions = (await failed.json()) as typeof options;
    const bad = JSON.stringify({
      transaction_id: failureOptions.transaction_id,
      response: registration(randomBytes(32), id()),
    });
    for (let i = 0; i < 5; i++) assert.equal((await finish(bad)).status, 401);
    assert.equal((await finish(bad)).status, 400);

    const saved = await sealAttribute(
      new TextEncoder().encode('Saved owner'),
      sourcePrf,
      source,
      new Uint8Array(32).fill(0x67),
      origin,
      'name',
      1,
    );
    const url = `${origin}/vault/attributes/name`;
    const first = await worker.fetch(url, {
      method: 'PUT',
      headers: { ...headers, 'If-None-Match': '*', 'X-Operation-ID': id() },
      body: JSON.stringify(saved),
    });
    assert.equal(first.status, 200);
    await env.DB.prepare(
      `INSERT INTO agent_grant(grant_id,account_id,owner_epoch,credential_id,delegate,provider,resource,source_revision,recipient_key_id,operations,document_ids,encrypted_snapshot,token_hash,request_hash,created_at,expires_at)
      VALUES('transfer-grant','owner',1,?,'synthetic','synthetic','https://agent.test/mcp',1,'synthetic-key','["read"]','["name"]','synthetic-encrypted-copy',?,?,?,?)`,
    )
      .bind(source.toString('base64url'), id(), id(), time, time + 3600)
      .run();
    const sealed = await transferAttribute(
      saved,
      sourcePrf,
      targetPrf,
      target,
      new Uint8Array(32).fill(0x89),
      origin,
      'name',
      1,
    );
    const op = id();
    const content = JSON.stringify(sealed);
    const transfer = (text = content, operation = op, revision = 1) =>
      worker.fetch(`${url}/transfer`, {
        method: 'POST',
        headers: { ...headers, 'If-Match': `"${revision}"`, 'X-Operation-ID': operation },
        body: text,
      });
    const badTarget = await sealAttribute(
      new TextEncoder().encode('Saved owner'),
      targetPrf,
      outside,
      new Uint8Array(32).fill(0x89),
      origin,
      'name',
      2,
    );
    assert.equal((await transfer(JSON.stringify(badTarget), id())).status, 403);
    await env.DB.prepare('UPDATE credential SET active=0 WHERE credential_id=?')
      .bind(target.toString('base64url'))
      .run();
    assert.equal((await transfer()).status, 403);
    await env.DB.prepare('UPDATE credential SET active=1 WHERE credential_id=?')
      .bind(target.toString('base64url'))
      .run();
    await env.DB.prepare(
      "CREATE TRIGGER fail_transfer_audit BEFORE INSERT ON vault_passkey_transfer_audit BEGIN SELECT RAISE(ABORT,'test'); END",
    ).run();
    assert.equal((await transfer()).status, 503);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT revision FROM vault_attribute_head WHERE account_id='owner'",
        ).first()
      ).revision,
      1,
    );
    await env.DB.prepare('DROP TRIGGER fail_transfer_audit').run();
    const done = await transfer();
    assert.equal(done.status, 200, await done.clone().text());
    const stopped = await env.DB.prepare(
      "SELECT revoked,encrypted_snapshot FROM agent_grant WHERE grant_id='transfer-grant'",
    ).first();
    assert.equal(stopped.revoked, 1);
    assert.equal(stopped.encrypted_snapshot, null);
    assert.equal((await transfer()).status, 200);
    assert.equal((await transfer(JSON.stringify(saved))).status, 409);
    assert.equal((await transfer(content, id())).status, 409);
    const current = (await (await worker.fetch(url, { headers })).json()) as typeof saved & {
      revision: number;
    };
    assert.equal(current.revision, 2);
    assert.equal(
      new TextDecoder().decode(await openAttribute(current, targetPrf, target, origin, 'name', 2)),
      'Saved owner',
    );
    await assert.rejects(openAttribute(current, sourcePrf, source, origin, 'name', 2));
    assert.equal(
      (await env.DB.prepare('SELECT count(*) AS n FROM vault_passkey_transfer_audit').first()).n,
      1,
    );
    // A retry acknowledges its old result without overwriting a later owner edit.
    const edited = await sealAttribute(
      new TextEncoder().encode('Later owner edit'),
      targetPrf,
      target,
      new Uint8Array(32).fill(0x90),
      origin,
      'name',
      3,
    );
    assert.equal(
      (
        await worker.fetch(url, {
          method: 'PUT',
          headers: { ...headers, 'If-Match': '"2"', 'X-Operation-ID': id() },
          body: JSON.stringify(edited),
        })
      ).status,
      200,
    );
    assert.equal((await transfer()).status, 200);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT revision FROM vault_attribute_head WHERE account_id='owner'",
        ).first()
      ).revision,
      3,
    );
    const deleted = await worker.fetch(url, {
      method: 'DELETE',
      headers: { ...headers, 'If-Match': '"3"', 'X-Operation-ID': id() },
    });
    assert.equal(deleted.status, 200);
    assert.equal((await transfer(JSON.stringify(sealed), id(), 4)).status, 409);
  } finally {
    await harness.close();
  }
});

test('Vault browser adds a passkey, transfers only the saved name, survives a lost response, and reopens on a fresh browser', async () => {
  const source = randomBytes(32),
    target = randomBytes(32);
  const sourcePrf = new Uint8Array(32).fill(0x31),
    targetPrf = new Uint8Array(32).fill(0x51);
  const saved = await sealAttribute(
    new TextEncoder().encode('Saved browser owner'),
    sourcePrf,
    source,
    new Uint8Array(32).fill(0x71),
    origin,
    'name',
    1,
  );
  const registrationData = registration(target, id());
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.jsonc', import.meta.url).pathname,
        secrets: { MIKAKI_ISSUER: origin },
      },
    ],
  });
  let browser: import('@playwright/test').Browser | undefined;
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const env = await worker.getEnv();
    const time = Math.floor(Date.now() / 1000),
      cookie = id();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
      env.DB.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(
        source.toString('base64url'),
      ),
      env.DB.prepare(
        "INSERT INTO passkey_credential VALUES(?,'synthetic-public-key',?,0,0,0,1)",
      ).bind(source.toString('base64url'), id()),
      env.DB.prepare("INSERT INTO sso_session VALUES('session','owner',?,1,?,0)").bind(
        source.toString('base64url'),
        time + 3600,
      ),
      env.DB.prepare("INSERT INTO sso_context VALUES('session',?,?)").bind(hash(cookie), time),
    ]);
    const headers = {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: origin,
      'Content-Type': 'application/json',
    };
    assert.equal(
      (
        await worker.fetch(`${origin}/vault/attributes/name`, {
          method: 'PUT',
          headers: { ...headers, 'If-None-Match': '*', 'X-Operation-ID': id() },
          body: JSON.stringify(saved),
        })
      ).status,
      200,
    );
    browser = await chromium.launch({ headless: true });
    const setup = async () => {
      const page = await browser!.newPage();
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(error.message));
      await page.addInitScript(
        ({ source, target, sourcePrf, targetPrf, attestation }) => {
          const decode = (s: string) =>
            Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), (c) =>
              c.charCodeAt(0),
            ).buffer;
          const encode = (b: ArrayBuffer) =>
            btoa(String.fromCharCode(...new Uint8Array(b)))
              .replaceAll('+', '-')
              .replaceAll('/', '_')
              .replaceAll('=', '');
          class MockAttestation {
            clientDataJSON: ArrayBuffer;
            attestationObject = decode(attestation);
            constructor(challenge: ArrayBuffer) {
              this.clientDataJSON = new TextEncoder().encode(
                JSON.stringify({
                  type: 'webauthn.create',
                  challenge: encode(challenge),
                  origin: location.origin,
                }),
              ).buffer;
            }
          }
          class MockCredential {
            rawId: ArrayBuffer;
            id: string;
            response?: MockAttestation;
            constructor(bytes: number[], challenge?: ArrayBuffer) {
              this.rawId = Uint8Array.from(bytes).buffer;
              this.id = encode(this.rawId);
              if (challenge) this.response = new MockAttestation(challenge);
            }
            getClientExtensionResults() {
              if (
                this.id !== encode(Uint8Array.from(source).buffer) &&
                Reflect.get(window, 'testTargetPrfMissing')
              )
                return { credProps: { rk: true } };
              return {
                credProps: { rk: true },
                prf: {
                  results: {
                    first: Uint8Array.from(
                      this.id === encode(Uint8Array.from(source).buffer) ? sourcePrf : targetPrf,
                    ).buffer,
                  },
                },
              };
            }
          }
          Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
          Object.defineProperty(window, 'AuthenticatorAttestationResponse', {
            value: MockAttestation,
          });
          Object.defineProperty(navigator, 'credentials', {
            value: {
              get: async (options: CredentialRequestOptions) =>
                new MockCredential([
                  ...new Uint8Array(options.publicKey!.allowCredentials![0]!.id as ArrayBuffer),
                ]),
              create: async (options: CredentialCreationOptions) =>
                new MockCredential(target, options.publicKey!.challenge as ArrayBuffer),
            },
          });
        },
        {
          source: [...source],
          target: [...target],
          sourcePrf: [...sourcePrf],
          targetPrf: [...targetPrf],
          attestation: registrationData.attestation,
        },
      );
      return { page, errors };
    };
    let loseResponse = true;
    const requests: string[] = [];
    const routePage = async (page: import('@playwright/test').Page) => {
      await page.route(`${origin}/**`, async (route) => {
        const request = route.request();
        const response = await worker.fetch(request.url(), {
          method: request.method(),
          headers: { ...request.headers(), Cookie: `__Host-op-sso=${cookie}` },
          ...(request.postData() ? { body: request.postData()! } : {}),
        });
        if (request.url().endsWith('/transfer')) {
          requests.push(request.postData()!);
          if (loseResponse) {
            loseResponse = false;
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
    };
    const first = await setup();
    await routePage(first.page);
    await first.page.goto(`${origin}/vault?lang=en&storage=legacy-v1`);
    await first.page.getByRole('button', { name: 'Unlock with Passkey' }).click();
    await first.page.locator('#name').fill('Unsaved edit');
    first.page.on('dialog', (dialog) => {
      assert.equal(dialog.type(), 'confirm');
      assert.equal(
        dialog.message(),
        'Moving saved content will discard unsaved edits in this editor. Continue?',
      );
      void dialog.accept();
    });
    await first.page.locator('#security > summary').click();
    const panel = first.page.getByRole('region', { name: 'Move my saved name to another Passkey' });
    await panel.getByRole('checkbox').check();
    await panel.getByRole('button', { name: 'Add a Passkey to this account', exact: true }).click();
    await panel.getByText('Passkey added.', { exact: false }).waitFor();
    const move = panel.getByRole('button', {
      name: 'Move the saved name to this Passkey',
      exact: true,
    });
    await first.page.evaluate(() => Reflect.set(window, 'testTargetPrfMissing', true));
    await move.click();
    await panel.getByText('This passkey does not support PRF.', { exact: false }).waitFor();
    assert.equal(requests.length, 0);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT revision FROM vault_attribute_head WHERE account_id='owner'",
        ).first()
      ).revision,
      1,
    );
    await first.page.evaluate(() => Reflect.set(window, 'testTargetPrfMissing', false));
    await move.click();
    await panel.getByRole('button', { name: 'Forget the pending request' }).waitFor();
    await move.click();
    await panel.getByText('Saved name moved.', { exact: false }).waitFor();
    assert.equal(requests.length, 2);
    assert.equal(requests[0], requests[1]);
    const current = (await (
      await worker.fetch(`${origin}/vault/attributes/name`, { headers })
    ).json()) as typeof saved & { revision: number };
    assert.equal(current.revision, 2);
    assert.equal(
      new TextDecoder().decode(await openAttribute(current, targetPrf, target, origin, 'name', 2)),
      'Saved browser owner',
    );
    assert.deepEqual(first.errors, []);
    await first.page.close();
    const second = await setup();
    await routePage(second.page);
    await second.page.goto(`${origin}/vault?lang=en&storage=legacy-v1`);
    await second.page.getByRole('button', { name: 'Unlock with Passkey' }).click();
    assert.equal(await second.page.locator('#name').inputValue(), 'Saved browser owner');
    assert.deepEqual(second.errors, []);
    await env.DB.prepare(
      "UPDATE vault_attribute_head SET owner_envelope='AA' WHERE account_id='owner' AND attribute_id='name'",
    ).run();
    await second.page.reload();
    await second.page.getByRole('button', { name: 'Unlock with Passkey' }).click();
    await second.page
      .locator('#status')
      .filter({ hasText: 'The passkey could not unlock this value.' })
      .waitFor();
    assert.equal(await second.page.locator('#name').isDisabled(), true);
    assert.equal(await second.page.locator('#save').isDisabled(), true);
    const invalidRecord = (await (
      await worker.fetch(`${origin}/vault/attributes/name`, { headers })
    ).json()) as typeof current;
    assert.equal(invalidRecord.revision, current.revision);
    assert.equal(invalidRecord.ciphertext, current.ciphertext);
    assert.deepEqual(second.errors, []);
  } finally {
    await browser?.close();
    await harness.close();
  }
});
