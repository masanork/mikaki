/** Optional actual-client qualification against disposable workerd state and synthetic data. */
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash, randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { agentKeyId } from '../crates/worker/ui/agent-crypto.ts';
import { sealRecordAgentSnapshot } from '../crates/worker/ui/agent-record-crypto.ts';
import type { D1Database } from '@cloudflare/workers-types';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { createTestHarness } from 'wrangler';

const run = promisify(execFile);
const complete = process.argv.includes('--container');
if (process.argv.slice(2).some((arg) => arg !== '--container'))
  throw new Error('Usage: probe-agent-oauth-clients.ts [--container]');
const image = 'mikaki-codex-oauth-probe:0.157.1';
const opaque = () => randomBytes(32).toString('base64url');
const digest = (value: string) => createHash('sha256').update(value).digest('base64url');
let container = '';
let issuedToken = '';
const recipient = await crypto.subtle.generateKey(
  {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  },
  true,
  ['encrypt', 'decrypt'],
);
const dir = await mkdtemp(join(tmpdir(), 'mikaki-oauth-client-'));
const callback = 'http://127.0.0.1:43123/callback';
const clientId = 'codex-preregistered-probe';
let harness: ReturnType<typeof createTestHarness> | undefined;
let agent: ReturnType<ReturnType<typeof createTestHarness>['getWorker']> | undefined;
const requests: string[] = [];
const server = createServer(
  {
    key: await (async () => {
      await run('openssl', [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-days',
        '1',
        '-keyout',
        join(dir, 'key.pem'),
        '-out',
        join(dir, 'cert.pem'),
        '-subj',
        '/CN=127.0.0.1',
        '-addext',
        'subjectAltName=IP:127.0.0.1,DNS:host.docker.internal',
      ]);
      return readFile(join(dir, 'key.pem'));
    })().catch(async (error: unknown) => {
      await rm(dir, { recursive: true, force: true });
      throw error;
    }),
    cert: await readFile(join(dir, 'cert.pem')),
  },
  async (request, response) => {
    try {
      const path = request.url!;
      requests.push(new URL(path, 'https://127.0.0.1').pathname);
      const chunks: Buffer[] = [];
      let bytes = 0;
      for await (const chunk of request) {
        bytes += chunk.length;
        if (bytes > 8192) {
          response.writeHead(413);
          response.end('probe_request_too_large');
          return;
        }
        chunks.push(Buffer.from(chunk));
      }
      const body = Buffer.concat(chunks);
      const reply = await agent!.fetch(`${issuer}${path}`, {
        method: request.method,
        headers: Object.fromEntries(
          Object.entries(request.headers).flatMap(([k, v]) =>
            v === undefined ? [] : [[k, Array.isArray(v) ? v.join(', ') : v]],
          ),
        ),
        redirect: 'manual',
        ...(body.length ? { body } : {}),
      });
      if (new URL(path, issuer).pathname === '/oauth/token' && reply.status === 200) {
        issuedToken = ((await reply.clone().json()) as { access_token: string }).access_token;
      }
      response.writeHead(reply.status, Object.fromEntries(reply.headers));
      response.end(Buffer.from(await reply.arrayBuffer()));
    } catch {
      response.writeHead(500);
      response.end('probe_failed');
    }
  },
);
let issuer = '';
let child: ReturnType<typeof spawn> | undefined;
try {
  server.listen(0, complete ? '0.0.0.0' : '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  issuer = `https://${complete ? 'host.docker.internal' : '127.0.0.1'}:${address.port}`;
  const resource = `${issuer}/mcp`;
  harness = createTestHarness({
    root: new URL('..', import.meta.url).pathname,
    workers: [
      {
        configPath: new URL('../crates/worker/wrangler.agent-local.jsonc', import.meta.url)
          .pathname,
      },
      {
        configPath: new URL('../crates/agent-worker/wrangler.local.jsonc', import.meta.url)
          .pathname,
        vars: { AGENT_RESOURCE: resource, AGENT_OWNER_URL: 'https://mikaki.test/vault' },
        secrets: {
          AGENT_PRIVATE_JWK: JSON.stringify(
            await crypto.subtle.exportKey('jwk', recipient.privateKey),
          ),
        },
      },
    ],
  });
  await harness.listen();
  const op = harness.getWorker('mikaki-op-agent-local');
  agent = harness.getWorker('mikaki-agent-local');
  await op.applyD1Migrations('DB');
  const { DB } = await op.getEnv();
  await DB.prepare('INSERT INTO agent_oauth_client VALUES(?,?,?,1)')
    .bind(clientId, 'Installed Codex discovery probe', JSON.stringify([callback]))
    .run();
  const args = ['mcp', 'login', clientId, '--no-browser', '--scopes', 'list,search,read'];
  for (const [key, value] of Object.entries({
    [`mcp_servers.${clientId}.url`]: resource,
    [`mcp_servers.${clientId}.oauth.client_id`]: clientId,
    [`mcp_servers.${clientId}.oauth.callback_url`]: callback,
    [`mcp_servers.${clientId}.oauth.callback_port`]: 43123,
    mcp_oauth_credentials_store: 'file',
    log_dir: complete ? '/tmp/probe-logs' : join(dir, 'logs'),
  }))
    args.push('-c', `${key}=${JSON.stringify(value)}`);
  const configArgs = args.slice(args.indexOf('-c'));
  if (complete) {
    container = (await run('docker', ['run', '-d', '--rm', image])).stdout.trim();
    await run('docker', ['exec', container, 'mkdir', '/probe']);
    await run('docker', ['cp', join(dir, 'cert.pem'), `${container}:/probe/cert.pem`]);
  }
  const codexCommand = complete ? 'docker' : 'codex';
  const codexArgs = (command: string[]) =>
    complete
      ? ['exec', '-i', '-e', 'CODEX_CA_CERTIFICATE=/probe/cert.pem', container, 'codex', ...command]
      : command;
  child = spawn(codexCommand, codexArgs(args), {
    cwd: dir,
    env: { ...process.env, CODEX_CA_CERTIFICATE: join(dir, 'cert.pem') },
    stdio: 'pipe',
  });
  const authorization = await new Promise<URL>((resolve, reject) => {
    let output = '';
    const timeout = setTimeout(
      () => reject(new Error('Codex did not produce an authorization URL within 30s')),
      30_000,
    );
    child!.on('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child!.on('exit', (code) => {
      clearTimeout(timeout);
      reject(new Error(`Codex exited before authorization (${code})`));
    });
    child!.stdout!.on('data', (data) => {
      output += String(data);
      const found = output.match(
        /https:\/\/(?:127\.0\.0\.1|host\.docker\.internal):\d+\/oauth\/authorize\?[^\s]+/,
      );
      if (found) {
        clearTimeout(timeout);
        resolve(new URL(found[0]));
      }
    });
    // Suppress diagnostic content; neither user configuration nor authorization secrets are output.
    child!.stderr!.resume();
  });
  if (!complete) {
    child.kill('SIGTERM');
    await once(child, 'exit');
  }
  const query = authorization.searchParams;
  assert.equal(query.get('client_id'), clientId);
  assert.equal(query.get('redirect_uri'), callback);
  assert.equal(query.get('resource'), resource);
  assert.equal(query.get('code_challenge_method'), 'S256');
  assert.deepEqual(query.get('scope')!.split(' ').sort(), ['list', 'read', 'search']);
  assert.equal(
    query.has('authorization_details'),
    false,
    'installed Codex uses the scope-only compatibility path',
  );
  const pending = await agent.fetch(authorization.href, { redirect: 'manual' });
  assert.equal(pending.status, 302);
  let fullEvidence: Record<string, boolean> | undefined;
  if (complete) {
    fullEvidence = await qualify(
      DB,
      op,
      agent,
      pending.headers.get('Location')!,
      child,
      () =>
        spawn(codexCommand, codexArgs(['app-server', '--listen', 'stdio://', ...configArgs]), {
          stdio: 'pipe',
        }),
      resource,
      issuer,
      () => issuedToken,
    );
  } else {
    assert.ok(!requests.some((path) => path.includes('register') || path === '/oauth/token'));
  }
  const version = (await run(codexCommand, codexArgs(['--version']))).stdout.trim();
  console.log(
    JSON.stringify(
      {
        codex: {
          version,
          metadata_requests: requests,
          preregistered_client: true,
          exact_callback: true,
          resource: true,
          s256: true,
          authorization_accepted: true,
          authorization_details: 'not requested: installed Codex used scopes only',
          token_exchange: complete
            ? 'passed'
            : 'not exercised: stopped before credential persistence',
          ...fullEvidence,
        },
      },
      null,
      2,
    ),
  );
} finally {
  child?.kill('SIGTERM');
  if (container) await run('docker', ['stop', container]).catch(() => {});
  await harness?.close();
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await rm(dir, { recursive: true, force: true });
}

function rpc(child: ReturnType<typeof spawn>) {
  let sequence = 0;
  const pending = new Map<
    number,
    { resolve: (value: unknown) => void; reject: (error: Error) => void }
  >();
  const lines = createInterface({ input: child.stdout! });
  child.stderr!.resume();
  lines.on('line', (line) => {
    const message = JSON.parse(line) as { id?: number; result?: unknown; error?: unknown };
    if (message.id === undefined) return;
    const waiter = pending.get(message.id);
    if (!waiter) return;
    pending.delete(message.id);
    if (message.error)
      waiter.reject(new Error('Codex RPC rejected request: ' + JSON.stringify(message.error)));
    else waiter.resolve(message.result);
  });
  child.on('exit', () => {
    for (const waiter of pending.values()) waiter.reject(new Error('Codex app server exited'));
    pending.clear();
  });
  return {
    notify(method: string) {
      child.stdin!.write(JSON.stringify({ method }) + '\n');
    },
    call(method: string, params: unknown): Promise<unknown> {
      const id = ++sequence;
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`Codex RPC timeout: ${method}`));
        }, 30_000);
        pending.set(id, {
          resolve: (v) => {
            clearTimeout(timeout);
            resolve(v);
          },
          reject: (error) => {
            clearTimeout(timeout);
            reject(error);
          },
        });
        child.stdin!.write(JSON.stringify({ id, method, params }) + '\n');
      });
    },
  };
}

type HarnessWorker = Pick<NonNullable<typeof agent>, 'fetch'>;
async function qualify(
  db: D1Database,
  op: HarnessWorker,
  agent: HarnessWorker,
  location: string,
  login: ReturnType<typeof spawn>,
  startApp: () => ReturnType<typeof spawn>,
  resource: string,
  issuer: string,
  token: () => string,
): Promise<Record<string, boolean>> {
  const time = Math.floor(Date.now() / 1000),
    cookie = opaque(),
    credential = new TextEncoder().encode('synthetic-codex-owner');
  const credentialId = Buffer.from(credential).toString('base64url');
  await db.batch([
    db.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
    db.prepare("INSERT INTO credential VALUES(?,'owner',1)").bind(credentialId),
    db
      .prepare("INSERT INTO sso_session VALUES('owner-session','owner',?,1,?,0)")
      .bind(credentialId, time + 3600),
    db.prepare("INSERT INTO sso_context VALUES('owner-session',?,?)").bind(digest(cookie), time),
  ]);
  const publicJwk = await crypto.subtle.exportKey('jwk', recipient.publicKey),
    keyId = await agentKeyId(publicJwk);
  await db.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").bind(keyId).run();
  const headers = {
    Cookie: `__Host-op-sso=${cookie}`,
    Origin: 'https://mikaki.test',
    'Content-Type': 'application/json',
  };
  const owner = (path: string, body: unknown) =>
    op.fetch(`https://mikaki.test/vault/agents/${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
  const source = {
      storage_version: 2 as const,
      origin: 'https://mikaki.test',
      owner_id: 'owner',
      vault_id: 'codex-probe-vault',
      collection_id: 'personal' as const,
      record_id: 'name' as const,
      kind: 'name' as const,
      revision: 1,
      ciphertext_sha256: digest('Synthetic Codex owner ciphertext'),
    },
    authority = { key_generation: 1, owner_key_revision: 1 };
  await db.batch([
    db
      .prepare(
        `INSERT INTO vault_owner_key_head VALUES('owner','codex-probe-vault',?,1,1,2,
      'PRF-HKDF-SHA256-AES256GCM-v2',?,?,?)`,
      )
      .bind(source.origin, opaque(), opaque(), time),
    db
      .prepare(
        `INSERT INTO vault_owner_record_head VALUES('owner','codex-probe-vault','personal',
      'name','name',1,1,2,'codex-probe-name',?,?,0,?)`,
      )
      .bind(source.ciphertext_sha256, 'e'.repeat(82), time),
  ]);
  const grantId = opaque(),
    expires = time + 3600;
  const envelope = await sealRecordAgentSnapshot(
    [{ id: 'name', title: 'Name', source: 'vault:record:name:1', text: 'mikaki-codex-oauth-ok' }],
    { key_id: keyId, public_jwk: publicJwk, resource },
    {
      owner: 'owner',
      grant_id: grantId,
      key_id: keyId,
      resource,
      expires_at: expires,
      source,
      authority,
    },
  );
  assert.equal(
    (
      await owner('grants', {
        storage_version: 2,
        grant_id: grantId,
        delegate: clientId,
        provider: 'Synthetic Codex test',
        resource,
        source,
        authority,
        recipient_key_id: keyId,
        operations: ['list', 'search', 'read', 'propose', 'execute'],
        document_ids: ['name'],
        envelope,
        token_hash: digest('mag_' + opaque()),
        expires_at: expires,
      })
    ).status,
    200,
  );
  const request_id = new URL(location).searchParams.get('agent_oauth_request')!;
  assert.equal((await owner('oauth-request', { request_id })).status, 200);
  const consent = await owner('oauth-decide', { request_id, grant_id: grantId, approve: true });
  assert.equal(consent.status, 200);
  const returned = ((await consent.json()) as { redirect: string }).redirect;
  assert.ok(returned);
  const exited = once(login, 'exit');
  login.stdin!.end(returned + '\n');
  const [exit] = await exited;
  assert.equal(exit, 0, 'Codex CLI OAuth login must succeed');
  assert.match(token(), /^moa_[A-Za-z0-9_-]{43}$/);
  assert.equal(
    (await db.prepare('SELECT count(*) n FROM agent_oauth_token').first<{ n: number }>())!.n,
    1,
  );
  assert.equal(
    (await run('docker', ['exec', container, 'test', '-s', '/root/.codex/.credentials.json']))
      .stderr,
    '',
  );
  async function appRead() {
    const app = startApp();
    const api = rpc(app);
    try {
      await api.call('initialize', {
        clientInfo: { name: 'mikaki_oauth_probe', version: '1' },
        capabilities: { experimentalApi: true },
      });
      api.notify('initialized');
      const thread = (await api.call('thread/start', {
        cwd: '/tmp',
        ephemeral: true,
        approvalPolicy: 'never',
        sandbox: 'read-only',
      })) as { thread: { id: string } };
      const call = (tool: string, args: unknown) =>
        api.call('mcpServer/tool/call', {
          threadId: thread.thread.id,
          server: clientId,
          tool,
          arguments: args,
        });
      const result = (await call('mikaki_read', { id: 'name' })) as {
        isError?: boolean;
        content: { type: string; text?: string }[];
      };
      assert.ok(!result.isError);
      assert.ok(result.content.some((part) => part.text?.includes('mikaki-codex-oauth-ok')));
      const denied = (await call('mikaki_propose', {
        proposal_id: opaque(),
        document_id: 'name',
        title: 'Forbidden',
        text: 'Must not be written',
      })) as { isError?: boolean };
      assert.equal(denied.isError, true);
      return { app, call };
    } catch (error) {
      app.kill('SIGTERM');
      throw error;
    }
  }
  const first = await appRead();
  first.app.kill('SIGTERM');
  await once(first.app, 'exit');
  const second = await appRead();
  try {
    assert.equal(
      (
        await agent.fetch(`${issuer}/oauth/revoke`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ client_id: clientId, token: token() }).toString(),
        })
      ).status,
      200,
    );
    const stopped = (await second.call('mikaki_read', { id: 'name' }).catch(() => null)) as {
      isError?: boolean;
      content?: unknown;
    } | null;
    assert.ok(stopped === null || stopped.isError, 'Revoked token must stop Codex read');
    assert.equal(
      (await db
        .prepare('SELECT revoked FROM agent_oauth_token WHERE token_hash=?')
        .bind(digest(token()))
        .first<{ revoked: number }>())!.revoked,
      1,
    );
    assert.equal(
      (await db
        .prepare(
          "SELECT count(*) n FROM agent_audit WHERE operation='read' AND outcome='authorized'",
        )
        .first<{ n: number }>())!.n,
      2,
    );
    assert.equal(
      (await db
        .prepare(
          "SELECT count(*) n FROM agent_audit WHERE operation='propose' AND outcome='denied'",
        )
        .first<{ n: number }>())!.n,
      2,
    );
    assert.equal(
      (await db.prepare('SELECT count(*) n FROM agent_proposal').first<{ n: number }>())!.n,
      0,
    );
    assert.equal(
      (await db.prepare('SELECT count(*) n FROM agent_oauth_token').first<{ n: number }>())!.n,
      1,
    );
  } finally {
    second.app.kill('SIGTERM');
  }
  return {
    credential_file_persisted: true,
    codex_app_server_read: true,
    new_process_reused_token: true,
    scope_narrowing: true,
    revocation_stopped_read: true,
    synthetic_data_only: true,
  };
}
