import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { createTestHarness } from 'wrangler';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { chromium, expect } from '@playwright/test';
import { agentKeyId, sealAgentSnapshot } from '../../crates/worker/ui/agent-crypto.ts';
import { sealAttribute } from '../../crates/worker/ui/vault-crypto.ts';
import { toolOutputs } from '../../crates/agent-worker/tool-results.ts';
import { newOwnerNote } from '../../crates/worker/ui/vault-note.ts';

const origin = 'https://mikaki.test',
  resource = 'https://agent.mikaki.test/mcp';
const id = () => randomBytes(32).toString('base64url');
const hash = (s: string) => createHash('sha256').update(s).digest('base64url');
function receipt(result: unknown) {
  const value = result as { isError?: boolean; content: { type: string; text: string }[] };
  assert.notEqual(value.isError, true, JSON.stringify(result));
  assert.deepEqual(
    toolOutputs.propose_attribute.parse(
      (result as { structuredContent: unknown }).structuredContent,
    ),
    JSON.parse(value.content[0]!.text),
  );
  return JSON.parse(value.content[0]!.text) as {
    proposal_id: string;
    request_hash: string;
    state: string;
    expires_at: number;
  };
}

test('one proposal authority enforces explicit capability, exact review, concurrency and invalidation across HTTP/MCP/browser', async () => {
  const keys = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );
  const privateJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
  const keyId = await agentKeyId(publicJwk);
  const harness = createTestHarness({
    root: new URL('../..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../../crates/worker/wrangler.agent-local.jsonc', import.meta.url)
          .pathname,
      },
      {
        configPath: new URL('../../crates/agent-worker/wrangler.local.jsonc', import.meta.url)
          .pathname,
        secrets: { AGENT_PRIVATE_JWK: JSON.stringify(privateJwk) },
      },
    ],
  });
  const client = new Client({ name: 'attribute-test', version: '1' });
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-agent-local'),
      agent = harness.getWorker('mikaki-agent-local');
    await op.applyD1Migrations('DB');
    const env = await op.getEnv();
    await env.DB.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").bind(keyId).run();
    const time = Math.floor(Date.now() / 1000),
      cookie = id(),
      otherCookie = id();
    const credential = new Uint8Array(randomBytes(32)),
      prf = new Uint8Array(32).fill(0x33);
    for (const [account, secret] of [
      ['owner', cookie],
      ['other', otherCookie],
    ]) {
      await env.DB.batch([
        env.DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account),
        env.DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(
          account === 'owner' ? Buffer.from(credential).toString('base64url') : 'other-key',
          account,
        ),
        env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,?,0)').bind(
          account,
          account,
          account === 'owner' ? Buffer.from(credential).toString('base64url') : 'other-key',
          time + 3600,
        ),
        env.DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(account, hash(secret), time),
      ]);
    }
    const ownerHeaders = {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: origin,
      'Content-Type': 'application/json',
    };
    const ownerCall = (path: string, body: unknown, secret = cookie) =>
      op.fetch(`${origin}/vault/agents/${path}`, {
        method: 'POST',
        headers: { ...ownerHeaders, Cookie: `__Host-op-sso=${secret}` },
        body: JSON.stringify(body),
      });
    const name = await sealAttribute(
      new TextEncoder().encode('Legacy owner'),
      prf,
      credential,
      new Uint8Array(32).fill(0x29),
      origin,
      'name',
      1,
    );
    assert.equal(
      (
        await op.fetch(`${origin}/vault/attributes/name`, {
          method: 'PUT',
          headers: { ...ownerHeaders, 'X-Operation-ID': id(), 'If-None-Match': '*' },
          body: JSON.stringify(name),
        })
      ).status,
      200,
    );
    const createGrant = async (operations = ['read', 'propose', 'execute']) => {
      const grantId = id(),
        token = `mag_${id()}`;
      const expiresAt = time + 1800;
      const envelope = await sealAgentSnapshot(
        [{ id: 'name', title: 'Name', text: 'Legacy owner', source: 'vault:name:1' }],
        { key_id: keyId, resource, public_jwk: publicJwk },
        {
          owner: 'owner',
          grant_id: grantId,
          key_id: keyId,
          resource,
          expires_at: expiresAt,
          source_revision: 1,
        },
      );
      const response = await ownerCall('grants', {
        grant_id: grantId,
        delegate: 'synthetic-codex',
        provider: 'test provider',
        resource,
        source_revision: 1,
        recipient_key_id: keyId,
        operations,
        document_ids: ['name'],
        envelope,
        token_hash: hash(token),
        expires_at: expiresAt,
      });
      assert.equal(response.status, 200, await response.clone().text());
      return { grantId, token };
    };
    const main = await createGrant();
    const http = (input: unknown, token = main.token) =>
      agent.fetch('https://agent.mikaki.test/attribute-proposals', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
    const makeInput = () => ({
      proposal_id: id(),
      attribute_id: 'owner_note',
      base_revision: 0,
      value: newOwnerNote('Agent title', 'Exact suggested text 🗾'),
      expires_at: time + 600,
    });
    let input = makeInput();
    // Existing name/draft scope never implies note proposal rights.
    assert.equal((await http(input)).status, 409);
    const capability = { grant_id: main.grantId, attribute_id: 'owner_note', base_revision: 0 };
    assert.equal((await ownerCall('attribute-capability', capability, otherCookie)).status, 409);
    assert.equal(
      (await ownerCall('attribute-capability', { ...capability, base_revision: 7 })).status,
      409,
    );
    const readOnly = await createGrant(['read']);
    assert.equal(
      (await ownerCall('attribute-capability', { ...capability, grant_id: readOnly.grantId }))
        .status,
      409,
    );
    await env.DB.prepare(
      "CREATE TRIGGER fail_capability_audit BEFORE INSERT ON agent_audit WHEN NEW.operation='attribute-capability' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END",
    ).run();
    assert.equal((await ownerCall('attribute-capability', capability)).status, 409);
    assert.equal(
      (await env.DB.prepare('SELECT count(*) n FROM agent_attribute_capability').first()).n,
      0,
    );
    await env.DB.prepare('DROP TRIGGER fail_capability_audit').run();
    assert.equal((await ownerCall('attribute-capability', capability)).status, 200);
    assert.equal((await ownerCall('attribute-capability', capability)).status, 200);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT count(*) n FROM agent_audit WHERE grant_id=? AND operation='attribute-capability'",
        )
          .bind(main.grantId)
          .first()
      ).n,
      1,
    );
    const transport = new StreamableHTTPClientTransport(new URL(resource), {
      requestInit: { headers: { Authorization: `Bearer ${main.token}` } },
      fetch: async (url, init) => {
        const request = new Request(url, init);
        const response = await agent.fetch(request.url, {
          method: request.method,
          headers: Object.fromEntries(request.headers),
          ...(request.method === 'POST' ? { body: await request.text() } : {}),
        });
        return new Response(response.body === null ? null : await response.arrayBuffer(), {
          status: response.status,
          headers: Object.fromEntries(response.headers),
        });
      },
    });
    await client.connect(transport);
    const mcp = (args: Record<string, unknown>) =>
      client.callTool({ name: 'mikaki_propose_attribute', arguments: args });
    await env.DB.prepare(
      "CREATE TRIGGER fail_proposal_audit BEFORE INSERT ON agent_audit WHEN NEW.operation='attribute-propose' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END",
    ).run();
    assert.equal((await http(input)).status, 409);
    assert.equal(
      (await env.DB.prepare('SELECT count(*) n FROM agent_attribute_proposal').first()).n,
      0,
    );
    await env.DB.prepare('DROP TRIGGER fail_proposal_audit').run();
    const proposed = await http(input);
    assert.equal(proposed.status, 200, await proposed.clone().text());
    const first = receipt(await proposed.json());
    assert.deepEqual(receipt(await mcp(input)), first);
    assert.deepEqual(receipt(await (await http(input)).json()), first);
    assert.equal((await http({ ...input, value: newOwnerNote('Changed', 'Changed') })).status, 409);
    assert.equal((await http({ ...input, attribute_id: 'name' })).status, 409);
    assert.equal(
      (await http({ ...input, proposal_id: id(), value: { ...input.value, version: 2 } })).status,
      409,
    );
    assert.equal(
      (await http({ ...input, proposal_id: id(), expires_at: time + 4000 })).status,
      409,
    );
    assert.equal((await http({ ...input, proposal_id: id(), expires_at: time - 1 })).status, 409);
    const decision = {
      proposal_id: input.proposal_id,
      request_hash: first.request_hash,
      approve: true,
    };
    assert.equal((await ownerCall('attribute-decide', decision, otherCookie)).status, 409);
    assert.equal(
      (await ownerCall('attribute-decide', { ...decision, request_hash: id() })).status,
      409,
    );
    // Audit failure rolls approval back.
    await env.DB.prepare(
      "CREATE TRIGGER fail_attribute_audit BEFORE INSERT ON agent_audit WHEN NEW.operation='attribute-decision' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END",
    ).run();
    assert.equal((await ownerCall('attribute-decide', decision)).status, 409);
    assert.equal(
      (
        await env.DB.prepare('SELECT state FROM agent_attribute_proposal WHERE proposal_id=?')
          .bind(input.proposal_id)
          .first()
      ).state,
      'pending',
    );
    await env.DB.prepare('DROP TRIGGER fail_attribute_audit').run();
    // Browser reviews the exact typed payload, approves once, and cannot save it yet.
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(e.message));
    await page.addInitScript(
      ({ credential, prf }) => {
        class MockCredential {
          rawId = Uint8Array.from(credential).buffer;
          getClientExtensionResults() {
            return { prf: { results: { first: Uint8Array.from(prf).buffer } } };
          }
        }
        Object.defineProperty(window, 'PublicKeyCredential', { value: MockCredential });
        Object.defineProperty(navigator, 'credentials', {
          value: { get: async () => new MockCredential() },
        });
      },
      { credential: [...credential], prf: [...prf] },
    );
    await page.route(`${origin}/**`, async (route) => {
      const request = route.request();
      const response = await op.fetch(request.url(), {
        method: request.method(),
        headers: { ...request.headers(), Cookie: `__Host-op-sso=${cookie}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    await page.goto(`${origin}/vault?lang=en`);
    const panel = page.getByRole('region', { name: 'Share with an AI agent' });
    const allowButton = panel.getByRole('button', {
      name: 'Allow note proposals for this connection',
      exact: true,
    });
    await expect(allowButton).toBeDisabled();
    await panel
      .getByLabel(
        'I consent to the selected connection proposing a note change at the displayed revision for up to one hour',
        { exact: true },
      )
      .check();
    await allowButton.click();
    await expect(panel.getByRole('status')).toHaveText('Note proposal capability granted.');
    await expect(panel.getByText('Exact suggested text 🗾', { exact: true })).toBeVisible();
    await panel
      .getByRole('button', { name: 'Approve this note proposal (do not save yet)', exact: true })
      .click();
    await expect(panel.getByRole('status')).toHaveText(
      'Note decision recorded. The Vault has not changed.',
    );
    assert.equal((await ownerCall('attribute-decide', decision)).status, 200);
    assert.equal(
      (await ownerCall('attribute-decide', { ...decision, approve: false })).status,
      409,
    );
    assert.equal(receipt(await mcp(input)).state, 'approved');
    assert.equal(
      (
        await client.callTool({
          name: 'mikaki_execute',
          arguments: { proposal_id: input.proposal_id, request_hash: first.request_hash },
        })
      ).isError,
      true,
    );
    assert.equal((await ownerCall('decide', decision)).status, 409);
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT count(*) n FROM agent_audit WHERE operation='attribute-decision' AND outcome='approved'",
        ).first()
      ).n,
      1,
    );
    assert.equal(
      (await op.fetch(`${origin}/vault/attributes/owner_note`, { headers: ownerHeaders })).status,
      404,
    );
    // Identical concurrent proposals share one record and one audit event.
    const concurrent = makeInput();
    const results = await Promise.all([http(concurrent), http(concurrent)]);
    for (const response of results)
      assert.equal(response.status, 200, await response.clone().text());
    assert.deepEqual(receipt(await results[0]!.json()), receipt(await results[1]!.json()));
    assert.equal(
      (
        await env.DB.prepare(
          "SELECT count(*) n FROM agent_audit WHERE operation='attribute-propose'",
        ).first()
      ).n,
      2,
    );
    const rejectedInput = makeInput();
    const rejected = receipt(await mcp(rejectedInput));
    const reject = {
      proposal_id: rejected.proposal_id,
      request_hash: rejected.request_hash,
      approve: false,
    };
    assert.equal((await ownerCall('attribute-decide', reject)).status, 200);
    assert.equal((await ownerCall('attribute-decide', reject)).status, 200);
    assert.equal(
      (
        await env.DB.prepare('SELECT payload FROM agent_attribute_proposal WHERE proposal_id=?')
          .bind(rejected.proposal_id)
          .first()
      ).payload,
      null,
    );
    // A first stored note invalidates pending/approved revision-zero proposals irreversibly.
    const sealed = await sealAttribute(
      new TextEncoder().encode('opaque future-format fixture'),
      prf,
      credential,
      new Uint8Array(32).fill(0x28),
      origin,
      'owner_note',
      1,
    );
    assert.equal(
      (
        await op.fetch(`${origin}/vault/attributes/owner_note`, {
          method: 'PUT',
          headers: { ...ownerHeaders, 'X-Operation-ID': id(), 'If-None-Match': '*' },
          body: JSON.stringify(sealed),
        })
      ).status,
      200,
    );
    assert.equal((await ownerCall('attribute-decide', decision)).status, 409);
    assert.equal((await http(input)).status, 409);
    const invalid = await env.DB.prepare(
      'SELECT state,payload FROM agent_attribute_proposal WHERE proposal_id=?',
    )
      .bind(input.proposal_id)
      .first();
    assert.deepEqual(invalid, { state: 'invalid', payload: null });
    // New explicit capability for the new base. Revocation erases and rejects future use.
    const next = await createGrant();
    assert.equal(
      (
        await ownerCall('attribute-capability', {
          ...capability,
          grant_id: next.grantId,
          base_revision: 1,
        })
      ).status,
      200,
    );
    input = { ...makeInput(), base_revision: 1 };
    const nextResult = receipt(await (await http(input, next.token)).json());
    assert.equal((await ownerCall('revoke', { grant_id: next.grantId })).status, 200);
    assert.equal((await http(input, next.token)).status, 409);
    assert.equal(
      (
        await ownerCall('attribute-decide', {
          proposal_id: input.proposal_id,
          request_hash: nextResult.request_hash,
          approve: true,
        })
      ).status,
      409,
    );
    assert.deepEqual(
      await env.DB.prepare('SELECT state,payload FROM agent_attribute_proposal WHERE proposal_id=?')
        .bind(input.proposal_id)
        .first(),
      { state: 'invalid', payload: null },
    );
    assert.equal((await env.DB.prepare('SELECT count(*) n FROM agent_draft').first()).n, 0);
    // Expiry fixture exercises the real read/decision guards and scheduled erasure.
    const expiryGrant = await createGrant();
    assert.equal(
      (
        await ownerCall('attribute-capability', {
          ...capability,
          grant_id: expiryGrant.grantId,
          base_revision: 1,
        })
      ).status,
      200,
    );
    const expiredId = id(),
      expiredHash = id();
    await env.DB.prepare(
      `INSERT INTO agent_attribute_proposal
      (proposal_id,grant_id,grant_revision,request_hash,attribute_id,base_revision,payload,expires_at,created_at)
      VALUES(?,?,1,?,'owner_note',1,?,?,?)`,
    )
      .bind(
        expiredId,
        expiryGrant.grantId,
        expiredHash,
        JSON.stringify(newOwnerNote('Expired', 'Expired secret')),
        time - 1,
        time - 100,
      )
      .run();
    assert.equal(
      (
        await ownerCall('attribute-decide', {
          proposal_id: expiredId,
          request_hash: expiredHash,
          approve: true,
        })
      ).status,
      409,
    );
    await agent.scheduled({ cron: '0 * * * *', scheduledTime: new Date() });
    assert.deepEqual(
      await env.DB.prepare('SELECT state,payload FROM agent_attribute_proposal WHERE proposal_id=?')
        .bind(expiredId)
        .first(),
      { state: 'invalid', payload: null },
    );
    // Credential stop cascades into this domain, and re-enabling cannot restore rights.
    const credentialGrant = await createGrant();
    assert.equal(
      (
        await ownerCall('attribute-capability', {
          ...capability,
          grant_id: credentialGrant.grantId,
          base_revision: 1,
        })
      ).status,
      200,
    );
    const credentialInput = { ...makeInput(), base_revision: 1 };
    const credentialResult = receipt(
      await (await http(credentialInput, credentialGrant.token)).json(),
    );
    await env.DB.prepare('UPDATE credential SET active=0 WHERE credential_id=?')
      .bind(Buffer.from(credential).toString('base64url'))
      .run();
    await env.DB.prepare('UPDATE credential SET active=1 WHERE credential_id=?')
      .bind(Buffer.from(credential).toString('base64url'))
      .run();
    assert.equal((await http(credentialInput, credentialGrant.token)).status, 409);
    assert.equal(
      (
        await ownerCall('attribute-decide', {
          proposal_id: credentialInput.proposal_id,
          request_hash: credentialResult.request_hash,
          approve: true,
        })
      ).status,
      409,
    );
    assert.deepEqual(
      await env.DB.prepare('SELECT state,payload FROM agent_attribute_proposal WHERE proposal_id=?')
        .bind(credentialInput.proposal_id)
        .first(),
      { state: 'invalid', payload: null },
    );
    assert.deepEqual(errors, []);
  } finally {
    await browser?.close();
    await client.close();
    await harness.close();
  }
});
