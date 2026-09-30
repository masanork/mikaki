import { startBrowserEvidence } from './support/browser-evidence.ts';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { chromium, expect } from '@playwright/test';
import { createTestHarness } from 'wrangler';
import { sealAttribute } from '../../crates/worker/ui/vault-crypto.ts';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import { encodeOwnerNote, newOwnerNote } from '../../crates/worker/ui/vault-note.ts';

test('Vault owner selects saved content, exports locally, issues remote access, and revokes from the dashboard', async () => {
  const credential = new TextEncoder().encode('browser-credential');
  const prf = new Uint8Array(32).fill(0x35);
  const sealed = await sealAttribute(
    new TextEncoder().encode('Saved owner name'),
    prf,
    credential,
    new Uint8Array(32).fill(0x57),
    'https://mikaki.test',
    'name',
    1,
  );
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
        secrets: {
          AGENT_PRIVATE_JWK: JSON.stringify(await crypto.subtle.exportKey('jwk', keys.privateKey)),
        },
      },
    ],
  });
  let browser;
  let evidence: Awaited<ReturnType<typeof startBrowserEvidence>> | undefined;
  let failure: unknown;
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-agent-local');
    await op.applyD1Migrations('DB');
    const env = await op.getEnv();
    await env.DB.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')")
      .bind(await agentKeyId(await crypto.subtle.exportKey('jwk', keys.publicKey)))
      .run();
    const cookie = randomBytes(32).toString('base64url');
    const time = Math.floor(Date.now() / 1000);
    const credentialId = Buffer.from(credential).toString('base64url');
    await env.DB.batch([
      env.DB.prepare("INSERT INTO account_security VALUES('browser-owner',1,1)"),
      env.DB.prepare("INSERT INTO credential VALUES(?,'browser-owner',1)").bind(credentialId),
      env.DB.prepare(
        "INSERT INTO sso_session VALUES('browser-session','browser-owner',?,1,?,0)",
      ).bind(credentialId, time + 3600),
      env.DB.prepare("INSERT INTO sso_context VALUES('browser-session',?,?)").bind(
        createHash('sha256').update(cookie).digest('base64url'),
        time,
      ),
    ]);
    const put = await op.fetch('https://mikaki.test/vault/attributes/name', {
      method: 'PUT',
      headers: {
        Cookie: `__Host-op-sso=${cookie}`,
        Origin: 'https://mikaki.test',
        'Content-Type': 'application/json',
        'X-Operation-ID': randomBytes(32).toString('base64url'),
        'If-None-Match': '*',
      },
      body: JSON.stringify(sealed),
    });
    assert.equal(put.status, 200, await put.text());
    const putNote = await op.fetch('https://mikaki.test/vault/attributes/owner_note', {
      method: 'PUT',
      headers: {
        Cookie: `__Host-op-sso=${cookie}`,
        Origin: 'https://mikaki.test',
        'Content-Type': 'application/json',
        'X-Operation-ID': randomBytes(32).toString('base64url'),
        'If-None-Match': '*',
      },
      body: JSON.stringify(
        await sealAttribute(
          encodeOwnerNote(newOwnerNote('Saved note title', 'Saved note body')),
          prf,
          credential,
          new Uint8Array(32).fill(0x58),
          'https://mikaki.test',
          'owner_note',
          1,
        ),
      ),
    });
    assert.equal(putNote.status, 200, await putNote.text());
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    evidence = await startBrowserEvidence(page.context(), 'agent-browser');
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
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
    let unavailableName = false;
    let malformedName = false;
    let unavailableSession = false;
    let shortDisplayExpiry = false;
    await page.route('https://mikaki.test/**', async (route) => {
      const request = route.request();
      if (unavailableSession && request.url().endsWith('/vault/session')) {
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: '{"error":"unavailable"}',
        });
        return;
      }
      if (request.method() === 'GET' && request.url().endsWith('/attributes/name')) {
        if (unavailableName) {
          await route.fulfill({
            status: 503,
            contentType: 'application/json',
            body: '{"error":"storage_unavailable"}',
          });
          return;
        }
        if (malformedName) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: '{"revision":99,"format_version":1,"ciphertext":"opaque","owner_envelope":"opaque"}',
          });
          return;
        }
      }
      const response = await op.fetch(request.url(), {
        method: request.method(),
        headers: { ...request.headers(), Cookie: `__Host-op-sso=${cookie}` },
        ...(request.postData() ? { body: request.postData()! } : {}),
      });
      if (shortDisplayExpiry && request.url().endsWith('/vault/agents/status') && response.ok) {
        const body = (await response.json()) as { grants: { expires_at: number }[] };
        for (const grant of body.grants) grant.expires_at = Math.floor(Date.now() / 1000) + 2;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify(body),
        });
        return;
      }
      await route.fulfill({
        status: response.status,
        headers: Object.fromEntries(response.headers),
        body: Buffer.from(await response.arrayBuffer()),
      });
    });
    await page.goto('https://mikaki.test/vault?lang=en');
    const panel = page.getByRole('region', { name: 'Share with an AI agent' });
    await assert.rejects(
      panel
        .getByRole('button', { name: 'Create remote access', exact: true })
        .click({ timeout: 300 }),
    );
    await page.getByRole('button', { name: 'Unlock with Passkey' }).click();
    await panel.getByRole('checkbox', { name: 'Share my saved name' }).check();
    await assert.rejects(
      panel
        .getByRole('button', { name: 'Create remote access', exact: true })
        .click({ timeout: 300 }),
    );
    await panel.getByRole('checkbox', { name: 'I approve disclosure' }).check();
    await page.locator('#name').fill('Unsaved edit must not be disclosed');
    await panel.getByRole('button', { name: 'Prepare a local MCP export' }).click();
    const sources = panel.getByRole('region', { name: 'Saved source versions', exact: true });
    await expect(sources.locator('[data-source="name"]')).toContainText(
      'Last confirmed saved revision: 1',
    );
    await expect(sources.locator('[data-source="name"]')).toContainText(
      'Same revision at the time of checking',
    );
    await expect(
      panel.getByRole('heading', { name: 'Saved name, revision 1', exact: true }),
    ).toBeVisible();
    const exportDownload = page.waitForEvent('download');
    await panel.getByRole('button', { name: 'Download selected plaintext' }).click();
    const downloaded = await exportDownload;
    const stream = await downloaded.createReadStream();
    assert.ok(stream);
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(chunk);
    const text = Buffer.concat(chunks).toString('utf8');
    const history = panel.getByRole('region', { name: 'Local download records', exact: true });
    await expect(history).toContainText('Copy based on revision 1');
    await expect(history).toContainText('Plaintext download started:');
    assert.match(text, /Saved owner name/);
    assert.doesNotMatch(text, /Unsaved edit/);
    const noteSelection = panel.getByRole('checkbox', {
      name: 'Share my saved owner note through local MCP',
      exact: true,
    });
    await noteSelection.check();
    await expect(panel.getByRole('button', { name: 'Download selected plaintext' })).toHaveCount(0);
    await expect(
      panel.getByRole('button', { name: 'Create remote access', exact: true }),
    ).toBeDisabled();
    await panel.getByRole('button', { name: 'Prepare a local MCP export' }).click();
    const combinedEvent = page.waitForEvent('download');
    await panel.getByRole('button', { name: 'Download selected plaintext' }).click();
    const combinedStream = await (await combinedEvent).createReadStream();
    assert.ok(combinedStream);
    const combinedChunks: Buffer[] = [];
    for await (const chunk of combinedStream) combinedChunks.push(chunk);
    const combined = JSON.parse(Buffer.concat(combinedChunks).toString('utf8'));
    assert.deepEqual(
      combined.documents.map((document: { id: string }) => document.id),
      ['name', 'owner_note'],
    );
    assert.match(combined.documents[1].text, /Saved note body/);
    await noteSelection.uncheck();
    await expect(panel.getByRole('button', { name: 'Download selected plaintext' })).toHaveCount(0);
    shortDisplayExpiry = true;
    await panel.getByRole('button', { name: 'Create remote access', exact: true }).click();
    await panel.getByLabel('Agent access credential').waitFor();
    const token = await panel.getByLabel('Agent access credential').inputValue();
    assert.match(token, /^mag_[A-Za-z0-9_-]{43}$/);
    const grant = await env.DB.prepare(
      "SELECT * FROM agent_grant WHERE account_id='browser-owner'",
    ).first();
    assert.ok(grant);
    assert.doesNotMatch(JSON.stringify(grant), /Saved owner name|Unsaved edit|mag_/);
    assert.equal(grant.token_hash, createHash('sha256').update(token).digest('base64url'));
    // Abbreviate only this status fixture's display expiry; a day-long global clock
    // jump correctly locks the whole Vault and cannot isolate grant expiry anymore.
    await expect(panel.getByText('Inactive', { exact: true })).toBeVisible();
    shortDisplayExpiry = false;
    await panel.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(panel.getByRole('button', { name: 'Revoke access', exact: true })).toBeVisible();
    await panel.getByRole('button', { name: 'Revoke access', exact: true }).click();
    await panel.getByText('Inactive', { exact: true }).waitFor();
    assert.equal(await panel.getByLabel('Agent access credential').count(), 0);
    assert.equal(
      (
        await env.DB.prepare('SELECT encrypted_snapshot FROM agent_grant WHERE grant_id=?')
          .bind(grant.grant_id)
          .first()
      ).encrypted_snapshot,
      null,
    );
    await panel.getByRole('button', { name: 'Prepare a local MCP export', exact: true }).click();
    await expect(
      panel.getByRole('button', { name: 'Download selected plaintext', exact: true }),
    ).toBeVisible();
    const sourceHeaders = {
      Cookie: `__Host-op-sso=${cookie}`,
      Origin: 'https://mikaki.test',
      'Content-Type': 'application/json',
      'X-Operation-ID': randomBytes(32).toString('base64url'),
      'If-Match': '"1"',
    };
    const changed = await sealAttribute(
      new TextEncoder().encode('New saved name'),
      prf,
      credential,
      new Uint8Array(32).fill(0x22),
      'https://mikaki.test',
      'name',
      2,
    );
    assert.equal(
      (
        await op.fetch('https://mikaki.test/vault/attributes/name', {
          method: 'PUT',
          headers: sourceHeaders,
          body: JSON.stringify(changed),
        })
      ).status,
      200,
    );
    await sources.getByRole('button', { name: 'Check saved source versions', exact: true }).click();
    await expect(sources.locator('[data-source="name"]')).toContainText(
      'Last confirmed saved revision: 2',
    );
    await expect(
      panel.getByRole('button', { name: 'Download selected plaintext', exact: true }),
    ).toHaveCount(0);
    await expect(history).toContainText('A newer saved revision was observed');
    await expect(history).toContainText('Same revision at the time of checking');
    await expect(panel).toContainText('Remote access created:');
    // Failed checks retain the last observation but must stop claiming a matching/current source.
    unavailableName = true;
    await sources.getByRole('button', { name: 'Check saved source versions', exact: true }).click();
    await expect(sources.locator('[data-source="name"]')).toContainText(
      'Source version unconfirmed',
    );
    await expect(sources.locator('[data-source="name"]')).toContainText(
      'Last confirmed saved revision: 2',
    );
    await expect(history).toContainText('Source version unconfirmed');
    await expect(history).not.toContainText('A newer saved revision was observed');
    unavailableName = false;
    assert.equal(
      (
        await op.fetch('https://mikaki.test/vault/attributes/name', {
          method: 'DELETE',
          headers: {
            ...sourceHeaders,
            'X-Operation-ID': randomBytes(32).toString('base64url'),
            'If-Match': '"2"',
          },
        })
      ).status,
      200,
    );
    await sources.getByRole('button', { name: 'Check saved source versions', exact: true }).click();
    await expect(sources.locator('[data-source="name"]')).toContainText(
      'Last confirmed saved revision: 3',
    );
    await expect(history).toContainText('Saved source was deleted');
    malformedName = true;
    await sources.getByRole('button', { name: 'Check saved source versions', exact: true }).click();
    await expect(history).toContainText('Source version unconfirmed');
    await expect(sources.locator('[data-source="name"]')).not.toContainText('99');
    unavailableSession = true;
    await panel.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(panel.getByText('Remote access created:', { exact: false })).toHaveCount(0);
    await expect(sources.locator('[data-source="owner_note"]')).toContainText(
      'Source version unconfirmed',
    );
    unavailableSession = false;
    malformedName = false;
    await panel.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(panel).toContainText('Remote access created:');
    assert.deepEqual(errors, []);
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    await evidence?.finish(failure);
    await browser?.close();
    await harness.close();
  }
});
