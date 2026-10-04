/** Synthetic in-process Worker/SQLite adapter tests. Executes checked-in Worker,
 * store, OAuth and migration code; does not claim workerd, D1 or browser coverage. */
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { test } from 'node:test';
import { build } from 'esbuild';
import { agentQueries } from '../../crates/worker/service/agent-catalog.ts';
import { agentKeyId, sealAgentSnapshot } from '../../crates/worker/ui/agent-crypto.ts';
import { sealRecordAgentSnapshot } from '../../crates/worker/ui/agent-record-crypto.ts';
import { encodeOwnerNote, newOwnerNote } from '../../crates/worker/ui/vault-note.ts';

const root = new URL('../..', import.meta.url).pathname;
const compiled = await build({
  stdin: {
    contents: `export * as model from './crates/agent-worker/model.ts';
    export * as records from './crates/agent-worker/record-proposals.ts';
    export * as store from './crates/agent-worker/store.ts';
    export * as oauth from './crates/agent-worker/oauth.ts';
    export * as details from './crates/agent-worker/authorization-details.ts';
    export { default as worker, OwnerAgents } from './crates/agent-worker/worker.ts';`,
    resolveDir: root,
  },
  bundle: true,
  write: false,
  platform: 'node',
  format: 'esm',
  logLevel: 'silent',
  plugins: [
    {
      name: 'synthetic-worker-entrypoint',
      setup(b) {
        b.onResolve({ filter: /^cloudflare:workers$/ }, () => ({
          path: 'entrypoint',
          namespace: 'fixture',
        }));
        b.onLoad({ filter: /.*/, namespace: 'fixture' }, () => ({
          contents: `export class WorkerEntrypoint {
      constructor(_context, env) { this.env=env; }
    }`,
        }));
      },
    },
  ],
});
// esbuild resolves the Worker's .js source imports to their checked-in .ts files.
const implementation = await import(
  `data:text/javascript;base64,${Buffer.from(compiled.outputFiles[0]!.text).toString('base64')}`
);
const { model, store, oauth, details, records, worker, OwnerAgents } = implementation;
const origin = 'https://mikaki.test',
  resource = 'https://agent.mikaki.test/mcp';
const id = () => randomBytes(32).toString('base64url');
const hash = (value: string) => createHash('sha256').update(value).digest('base64url');
const migrationDir = new URL('../../crates/worker/migrations/', import.meta.url);
const migrations = readdirSync(migrationDir)
  .filter((name) => /^\d{4}_.+\.sql$/.test(name))
  .sort();
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
const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
const keyId = await agentKeyId(publicJwk);

type Hook = (sql: string) => void;
function adapter(sqlite: DatabaseSync) {
  let hook: Hook | undefined;
  class Statement {
    values: SQLInputValue[] = [];
    readonly sql: string;
    constructor(sql: string) {
      this.sql = sql;
    }
    bind(...values: SQLInputValue[]) {
      this.values = values;
      return this;
    }
    async first() {
      const value = sqlite.prepare(this.sql).get(...this.values) ?? null;
      hook?.(this.sql);
      return value;
    }
    async all() {
      const results = sqlite.prepare(this.sql).all(...this.values);
      hook?.(this.sql);
      return { results };
    }
    async run() {
      const statement = sqlite.prepare(this.sql);
      const results = statement.columns().length ? statement.all(...this.values) : [];
      const changes = statement.columns().length ? 0 : statement.run(...this.values).changes;
      hook?.(this.sql);
      return { results, meta: { changes } };
    }
  }
  const db = {
    prepare(sql: string) {
      return new Statement(sql);
    },
    withSession(_mode: string) {
      return db;
    },
    async batch(statements: Statement[]) {
      sqlite.exec('BEGIN');
      try {
        const results = [];
        for (const statement of statements) results.push(await statement.run());
        sqlite.exec('COMMIT');
        return results;
      } catch (error) {
        sqlite.exec('ROLLBACK');
        throw error;
      }
    },
  };
  return {
    db,
    afterQuery(value?: Hook) {
      hook = value;
    },
  };
}
function fixture(before33 = false) {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec('PRAGMA foreign_keys=ON');
  for (const name of migrations) {
    if (before33 && Number(name.slice(0, 4)) >= 33) break;
    sqlite.exec(readFileSync(new URL(name, migrationDir), 'utf8'));
  }
  const time = Math.floor(Date.now() / 1000),
    cookie = hash('synthetic-owner-cookie');
  sqlite.exec("INSERT INTO account_security VALUES('owner',1,1),('other',1,1);");
  sqlite.exec("INSERT INTO credential VALUES('passkey','owner',1),('other-passkey','other',1)");
  sqlite
    .prepare("INSERT INTO sso_session VALUES('session','owner','passkey',1,?,0)")
    .run(time + 3600);
  sqlite.prepare("INSERT INTO sso_context VALUES('session',?,?)").run(cookie, time);
  sqlite.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").run(keyId);
  sqlite
    .prepare(
      `INSERT INTO vault_attribute_head(account_id,attribute_id,revision,format_version,object_key,ciphertext_sha256,owner_envelope,deleted,updated_at)
    VALUES('owner','name',1,1,'old-name','synthetic-hash','synthetic-envelope',0,?)`,
    )
    .run(time);
  sqlite
    .prepare(
      `INSERT INTO vault_owner_key_head VALUES('owner','vault',?,1,1,2,'PRF-HKDF-SHA256-AES256GCM-v2',?,?,?)`,
    )
    .run(origin, id(), id(), time);
  for (const record of ['name', 'owner_note'])
    sqlite
      .prepare(
        `INSERT INTO vault_owner_record_head
    VALUES('owner','vault','personal',?,?,1,1,2,?,?,?,0,?)`,
      )
      .run(record, record, `record-${record}`, hash(record), 'e'.repeat(82), time);
  sqlite
    .prepare("INSERT INTO agent_oauth_client VALUES('client','Synthetic client',?,1)")
    .run(JSON.stringify(['https://client.test/callback']));
  const shim = adapter(sqlite);
  const env = {
    DB: shim.db,
    AUTH_STORE: {
      async fetch(_url: string, init: RequestInit) {
        const { statements } = JSON.parse(init.body as string);
        const prepared = statements.map(
          ({ id, values }: { id: string; values: SQLInputValue[] }) => {
            const query = agentQueries[id];
            assert.ok(query, 'synthetic binding accepts only checked-in Agent capabilities');
            return shim.db.prepare(query).bind(...values);
          },
        );
        return Response.json(await shim.db.batch(prepared));
      },
    },
    AGENT_PRIVATE_JWK: JSON.stringify(privateJwk),
    AGENT_RESOURCE: resource,
    AGENT_OWNER_URL: `${origin}/vault`,
  };
  const owner = { account: 'owner', secretHash: cookie };
  const ownerAgent = new OwnerAgents({}, env);
  const ownerRequest = async (path: string, body?: unknown) =>
    ownerAgent.fetch(
      new Request(`${origin}${path}`, {
        method: body === undefined ? 'GET' : 'POST',
        headers: {
          'X-Mikaki-Account': 'owner',
          'X-Mikaki-Session-Hash': cookie,
          'X-Mikaki-Origin': origin,
          'Content-Type': 'application/json',
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      }),
    );
  return { sqlite, ...shim, env, owner, ownerRequest, time };
}
type Fixture = ReturnType<typeof fixture>;
async function selected(f: Fixture, record: 'name' | 'owner_note' = 'name') {
  const source = {
    storage_version: 2 as const,
    origin,
    owner_id: 'owner',
    vault_id: 'vault',
    collection_id: 'personal' as const,
    record_id: record,
    kind: record,
    revision: 1,
    ciphertext_sha256: hash(record),
  };
  const authority = { key_generation: 1, owner_key_revision: 1 };
  const text =
    record === 'name'
      ? 'Selected v2 name'
      : new TextDecoder().decode(
          encodeOwnerNote(newOwnerNote('Private selected note', 'Only this saved note')),
        );
  const document = {
    id: record,
    title: 'Selected record',
    source: 'vault:name:999:forged-label',
    text,
  };
  const grantId = id(),
    token = `mag_${id()}`;
  const binding = {
    owner: 'owner',
    grant_id: grantId,
    key_id: keyId,
    resource,
    expires_at: f.time + 600,
    source,
    authority,
  };
  const envelope = await sealRecordAgentSnapshot(
    [document],
    { public_jwk: publicJwk, key_id: keyId, resource },
    binding,
  );
  const input = {
    storage_version: 2 as const,
    grant_id: grantId,
    delegate: 'synthetic',
    provider: 'Synthetic provider',
    resource,
    source,
    authority,
    recipient_key_id: keyId,
    operations: ['list', 'search', 'read', 'propose', 'execute'],
    document_ids: [record],
    envelope,
    token_hash: hash(token),
    expires_at: binding.expires_at,
  };
  return { input, binding, token, document };
}
async function legacy(f: Fixture) {
  const grantId = id(),
    token = `mag_${id()}`;
  const envelope = await sealAgentSnapshot(
    [{ id: 'name', title: 'Name', source: 'v1', text: 'Legacy v1 name' }],
    { public_jwk: publicJwk, key_id: keyId, resource },
    {
      owner: 'owner',
      grant_id: grantId,
      key_id: keyId,
      resource,
      expires_at: f.time + 600,
      source_revision: 1,
    },
  );
  const input = {
    grant_id: grantId,
    delegate: 'synthetic',
    provider: 'Synthetic provider',
    resource,
    source_revision: 1,
    recipient_key_id: keyId,
    operations: ['list', 'search', 'read', 'propose', 'execute'],
    document_ids: ['name'],
    envelope,
    token_hash: hash(token),
    expires_at: f.time + 600,
  };
  return { input, token };
}
async function create(f: Fixture, input: unknown) {
  const result = await f.ownerRequest('/grants', input);
  assert.equal(result.status, 200, await result.text());
}
async function rpc(f: Fixture, token: string, name: string, args: unknown = {}) {
  const response = await worker.fetch(
    new Request(resource, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2025-11-25',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: `mikaki_${name}`, arguments: args },
      }),
    }),
    f.env,
  );
  return {
    status: response.status,
    data: response.body
      ? ((await response.json()) as { result?: { isError?: boolean; structuredContent?: any } })
      : null,
  };
}
async function read(f: Fixture, token: string, record = 'name') {
  return rpc(f, token, 'read', { id: record });
}
function row(f: Fixture, grantId: string) {
  return f.sqlite.prepare('SELECT * FROM agent_grant WHERE grant_id=?').get(grantId)!;
}
function stopped(f: Fixture, grantId: string) {
  assert.equal(row(f, grantId).revoked, 1);
  assert.equal(row(f, grantId).encrypted_snapshot, null);
}

// Pre-migration populated v1 state must retain its shape, hash and authorization.
test('0033 preserves populated v1 grants and legacy request hashes', async () => {
  const f = fixture(true);
  try {
    const v1 = await legacy(f),
      parsed = model.grantInput.parse(v1.input);
    assert.equal(JSON.stringify(parsed), JSON.stringify(v1.input));
    f.sqlite
      .prepare(
        `INSERT INTO agent_grant(grant_id,account_id,owner_epoch,credential_id,delegate,provider,resource,source_revision,
      recipient_key_id,operations,document_ids,encrypted_snapshot,token_hash,request_hash,created_at,expires_at)
      VALUES(?,'owner',1,'passkey','synthetic','Synthetic provider',?,1,?,?,?,?,?,?,?,?)`,
      )
      .run(
        v1.input.grant_id,
        resource,
        keyId,
        JSON.stringify(v1.input.operations),
        '["name"]',
        JSON.stringify(v1.input.envelope),
        hash(v1.token),
        hash(JSON.stringify(v1.input)),
        f.time,
        f.time + 600,
      );
    f.sqlite.exec(readFileSync(new URL('0033_agent_record_sources.sql', migrationDir), 'utf8'));
    assert.equal(row(f, v1.input.grant_id).storage_version, 1);
    await create(f, v1.input);
    const result = await read(f, v1.token);
    assert.equal(result.data?.result?.structuredContent?.text, 'Legacy v1 name');
    assert.equal(result.data?.result?.structuredContent?.access.source_check, 'revision-matched');
  } finally {
    f.sqlite.close();
  }
});

test('v1/v2 same-name isolation and exactly one canonical selected owner_note', async () => {
  const f = fixture();
  try {
    const v1 = await legacy(f),
      v2 = await selected(f),
      note = await selected(f, 'owner_note');
    await create(f, v1.input);
    await create(f, v2.input);
    await create(f, note.input);
    const result = await read(f, v2.token);
    const content = result.data?.result?.structuredContent;
    assert.equal(content.text, 'Selected v2 name');
    assert.equal(content.access.source_check, 'record-matched');
    assert.deepEqual(content.source_info.source, v2.input.source);
    assert.deepEqual(content.source_info.authority, v2.input.authority);
    assert.equal(content.source_info.confirmed_at, content.access.checked_at);
    assert.equal((await read(f, note.token)).data?.result?.isError, true);
    assert.equal(
      (await read(f, note.token, 'owner_note')).data?.result?.structuredContent?.text,
      note.document.text,
    );
    const listed = await rpc(f, note.token, 'list');
    assert.deepEqual(
      listed.data?.result?.structuredContent.documents.map((d: any) => d.id),
      ['owner_note'],
    );
    f.sqlite.exec(
      "UPDATE vault_attribute_head SET revision=2 WHERE account_id='owner' AND attribute_id='name'",
    );
    stopped(f, v1.input.grant_id);
    assert.equal((await read(f, v1.token)).status, 401);
    assert.equal(
      (await read(f, v2.token)).data?.result?.structuredContent?.text,
      'Selected v2 name',
    );
    f.sqlite.exec("UPDATE vault_owner_record_head SET revision=2 WHERE record_id='name'");
    stopped(f, v2.input.grant_id);
    assert.equal(
      (await read(f, note.token, 'owner_note')).data?.result?.structuredContent?.text,
      note.document.text,
    );
    // Historical replay acknowledges the immutable request; it never restores access.
    await create(f, v2.input);
    stopped(f, v2.input.grant_id);
    f.sqlite.exec("UPDATE vault_owner_record_head SET revision=1 WHERE record_id='name'");
    await create(f, v2.input);
    assert.equal((await read(f, v2.token)).status, 401);
  } finally {
    f.sqlite.close();
  }
});

test('source identity and authority are exact, bounded, authenticated, and immutable', async () => {
  const f = fixture();
  try {
    const v2 = await selected(f);
    for (const changed of [
      { source: { ...v2.input.source, owner_id: 'other' } },
      { source: { ...v2.input.source, origin: 'https://other.test' } },
      { source: { ...v2.input.source, vault_id: 'other-vault' } },
      { source: { ...v2.input.source, collection_id: 'other' } },
      {
        source: { ...v2.input.source, record_id: 'owner_note', kind: 'owner_note' },
        document_ids: ['owner_note'],
      },
      { source: { ...v2.input.source, revision: 2 } },
      { source: { ...v2.input.source, ciphertext_sha256: id() } },
      { authority: { key_generation: 2, owner_key_revision: 1 } },
      { authority: { key_generation: 1, owner_key_revision: 2 } },
      { document_ids: ['name', 'owner_note'] },
      { envelope: { ...v2.input.envelope, version: 1 } },
    ]) {
      assert.equal((await f.ownerRequest('/grants', { ...v2.input, ...changed })).status, 409);
    }
    for (const text of ['é'.repeat(257), '\ud800']) {
      const envelope = await sealRecordAgentSnapshot(
        [{ ...v2.document, text }],
        { public_jwk: publicJwk, key_id: keyId, resource },
        v2.binding,
      );
      assert.equal((await f.ownerRequest('/grants', { ...v2.input, envelope })).status, 409);
    }
    const note = await selected(f, 'owner_note');
    for (const text of [
      note.document.text + ' ',
      '{"type":"mikaki.owner-note","version":1}',
      'arbitrary note text',
    ]) {
      const envelope = await sealRecordAgentSnapshot(
        [{ ...note.document, text }],
        { public_jwk: publicJwk, key_id: keyId, resource },
        note.binding,
      );
      assert.equal((await f.ownerRequest('/grants', { ...note.input, envelope })).status, 409);
    }
    await create(f, v2.input);
    for (const [column, value] of [
      ['storage_version', 1],
      ['source_revision', 2],
      ['source_origin', 'https://other.test'],
      ['source_vault_id', 'other'],
      ['source_collection_id', 'other'],
      ['source_record_id', 'owner_note'],
      ['source_kind', 'owner_note'],
      ['source_ciphertext_sha256', id()],
      ['source_key_generation', 2],
      ['source_owner_key_revision', 2],
    ] as const)
      assert.throws(() =>
        f.sqlite
          .prepare(`UPDATE agent_grant SET ${column}=? WHERE grant_id=?`)
          .run(value, v2.input.grant_id),
      );
    f.sqlite
      .prepare('UPDATE agent_grant SET encrypted_snapshot=NULL WHERE grant_id=?')
      .run(v2.input.grant_id);
    assert.throws(() =>
      f.sqlite
        .prepare('UPDATE agent_grant SET encrypted_snapshot=? WHERE grant_id=?')
        .run(JSON.stringify(v2.input.envelope), v2.input.grant_id),
    );
  } finally {
    f.sqlite.close();
  }
});

test('a fresh encrypted request still cannot create against mismatched or deleted live sources', async () => {
  for (const mutate of [
    "UPDATE vault_owner_record_head SET revision=2 WHERE record_id='name'",
    `UPDATE vault_owner_record_head SET ciphertext_sha256='${hash('different')}' WHERE record_id='name'`,
    "UPDATE vault_owner_record_head SET kind='other' WHERE record_id='name'",
    'UPDATE vault_owner_key_head SET revision=2',
    "UPDATE vault_owner_key_head SET origin='https://other.test'",
    "DELETE FROM vault_owner_record_head WHERE record_id='name'",
  ]) {
    const f = fixture();
    try {
      const v2 = await selected(f);
      f.sqlite.exec(mutate);
      assert.equal((await f.ownerRequest('/grants', v2.input)).status, 409);
      assert.equal(f.sqlite.prepare('SELECT count(*) n FROM agent_grant').get()!.n, 0);
    } finally {
      f.sqlite.close();
    }
  }
});

test('record digest, tombstone, delete and registry revision irreversibly stop matching snapshots', async () => {
  for (const mutate of [
    `UPDATE vault_owner_record_head SET ciphertext_sha256='${hash('new')}' WHERE record_id='name'`,
    "UPDATE vault_owner_record_head SET deleted=1,object_key=NULL,ciphertext_sha256=NULL,key_envelope=NULL WHERE record_id='name'",
    "DELETE FROM vault_owner_record_head WHERE record_id='name'",
    'UPDATE vault_owner_key_head SET revision=2',
    "UPDATE vault_owner_key_head SET origin='https://other.test'",
  ]) {
    const f = fixture();
    try {
      const v2 = await selected(f);
      await create(f, v2.input);
      f.sqlite.exec(mutate);
      stopped(f, v2.input.grant_id);
      assert.equal((await read(f, v2.token)).status, 401);
      assert.throws(() =>
        f.sqlite
          .prepare('UPDATE agent_grant SET revoked=0 WHERE grant_id=?')
          .run(v2.input.grant_id),
      );
    } finally {
      f.sqlite.close();
    }
  }
});

test('revocation after initial read and during authorized audit prevents plaintext return', async () => {
  for (const stage of ['decrypt', 'audit', 'audit-failure']) {
    const f = fixture();
    try {
      const v2 = await selected(f);
      await create(f, v2.input);
      if (stage === 'decrypt') {
        let calls = 0;
        f.afterQuery((sql) => {
          if (sql.startsWith('SELECT g.*,CASE') && ++calls === 2) {
            f.afterQuery();
            f.sqlite.exec("UPDATE vault_owner_record_head SET revision=2 WHERE record_id='name'");
          }
        });
      } else
        f.sqlite.exec(
          stage === 'audit'
            ? "CREATE TRIGGER revoke_at_audit AFTER INSERT ON agent_audit WHEN NEW.operation='read' AND NEW.outcome='authorized' BEGIN UPDATE vault_owner_record_head SET revision=2 WHERE record_id='name'; END"
            : "CREATE TRIGGER fail_audit BEFORE INSERT ON agent_audit WHEN NEW.operation='read' BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END",
        );
      const result = await read(f, v2.token);
      assert.equal(result.data?.result?.isError, true, JSON.stringify(result));
      assert.doesNotMatch(
        JSON.stringify(result),
        /Selected v2 name|ciphertext_sha256|synthetic audit failure/,
      );
    } finally {
      f.sqlite.close();
    }
  }
});

test('v2 private drafts remain selected, review-bound and separate from legacy attribute capabilities', async () => {
  const f = fixture();
  try {
    const note = await selected(f, 'owner_note');
    await create(f, note.input);
    assert.equal(
      (
        await f.ownerRequest('/attribute-capability', {
          grant_id: note.input.grant_id,
          attribute_id: 'owner_note',
          base_revision: 0,
        })
      ).status,
      409,
    );
    assert.throws(() =>
      f.sqlite
        .prepare(
          "INSERT INTO agent_attribute_capability(grant_id,attribute_id,base_revision,grant_revision,created_at,expires_at) VALUES(?,'owner_note',0,1,?,?)",
        )
        .run(note.input.grant_id, f.time, f.time + 600),
    );
    const proposal = {
      proposal_id: id(),
      document_id: 'owner_note',
      title: 'Private draft',
      text: 'No Vault mutation',
    };
    assert.equal(
      (await rpc(f, note.token, 'propose', { ...proposal, document_id: 'name' })).data?.result
        ?.isError,
      true,
    );
    const proposed = await rpc(f, note.token, 'propose', proposal);
    const receipt = proposed.data?.result?.structuredContent;
    assert.equal(receipt.state, 'pending');
    const executeArgs = { proposal_id: proposal.proposal_id, request_hash: receipt.request_hash };
    assert.equal((await rpc(f, note.token, 'execute', executeArgs)).data?.result?.isError, true);
    assert.equal((await f.ownerRequest('/decide', { ...executeArgs, approve: true })).status, 200);
    const first = await rpc(f, note.token, 'execute', executeArgs);
    const retry = await rpc(f, note.token, 'execute', executeArgs);
    assert.deepEqual(first.data, retry.data);
    assert.equal(first.data?.result?.structuredContent.state, 'executed');
    assert.equal(f.sqlite.prepare('SELECT count(*) n FROM agent_draft').get()!.n, 1);
    assert.equal(
      f.sqlite
        .prepare("SELECT revision FROM vault_owner_record_head WHERE record_id='owner_note'")
        .get()!.revision,
      1,
    );
    assert.equal(
      (
        await rpc(f, note.token, 'propose_attribute', {
          proposal_id: id(),
          attribute_id: 'owner_note',
          base_revision: 0,
          value: newOwnerNote('Denied', 'Legacy capability'),
          expires_at: f.time + 300,
        })
      ).data?.result?.isError,
      true,
    );
  } finally {
    f.sqlite.close();
  }
});

function authorization(grant: Awaited<ReturnType<typeof selected>>) {
  return [
    {
      type: 'mikaki_agent_snapshot',
      storage_version: 2,
      locations: [resource],
      actions: ['read'],
      document_id: grant.input.source.record_id,
      source: grant.input.source,
      authority: grant.input.authority,
      purpose: 'Read one selected record',
    },
  ];
}
async function pending(f: Fixture, authorizationDetails: unknown) {
  const verifier = id();
  const url = new URL('https://agent.mikaki.test/oauth/authorize');
  for (const [key, value] of Object.entries({
    response_type: 'code',
    client_id: 'client',
    redirect_uri: 'https://client.test/callback',
    resource,
    scope: 'read',
    state: id(),
    code_challenge: hash(verifier),
    code_challenge_method: 'S256',
    ...(authorizationDetails === null
      ? {}
      : { authorization_details: JSON.stringify(authorizationDetails) }),
  }))
    url.searchParams.set(key, value);
  const response = await oauth.authorize(new Request(url), f.env);
  assert.equal(response.status, 302, await response.text());
  return {
    requestId: new URL(response.headers.get('Location')!).searchParams.get('agent_oauth_request')!,
    verifier,
  };
}
async function exchange(f: Fixture, code: string, verifier: string) {
  return oauth.token(
    new Request('https://agent.mikaki.test/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: 'client',
        redirect_uri: 'https://client.test/callback',
        resource,
        code_verifier: verifier,
      }),
    }),
    f.env,
  );
}

test('OAuth requires exact v2 detail; legacy/scope-only, tuple, digest and authority mismatches fail closed', async () => {
  const f = fixture();
  try {
    const v2 = await selected(f);
    await create(f, v2.input);
    const [target] = authorization(v2);
    for (const value of [
      null,
      [
        {
          type: 'mikaki_agent_snapshot',
          locations: [resource],
          actions: ['read'],
          document_id: 'name',
          source_revision: 1,
          purpose: 'legacy',
        },
      ],
      [{ ...target, source: { ...target.source, owner_id: 'other' } }],
      [{ ...target, source: { ...target.source, vault_id: 'other' } }],
      [{ ...target, source: { ...target.source, ciphertext_sha256: id() } }],
      [{ ...target, source: { ...target.source, revision: 2 } }],
      [{ ...target, authority: { ...target.authority, owner_key_revision: 2 } }],
      [{ ...target, authority: { ...target.authority, key_generation: 2 } }],
    ]) {
      const request = await pending(f, value);
      await assert.rejects(
        oauth.decide(
          f.db,
          f.owner,
          { request_id: request.requestId, approve: true, grant_id: v2.input.grant_id },
          f.env,
        ),
      );
    }
    const request = await pending(f, authorization(v2));
    const approved = await oauth.decide(
      f.db,
      f.owner,
      { request_id: request.requestId, approve: true, grant_id: v2.input.grant_id },
      f.env,
    );
    const code = new URL(approved.redirect).searchParams.get('code')!;
    const issued = await exchange(f, code, request.verifier);
    assert.equal(issued.status, 200, await issued.clone().text());
    const token = (await issued.json()) as { access_token: string; authorization_details: unknown };
    assert.deepEqual(
      token.authorization_details,
      details.parseAuthorizationDetails(JSON.stringify(authorization(v2)), resource, ['read']),
    );
    assert.equal(
      (await read(f, token.access_token)).data?.result?.structuredContent.text,
      'Selected v2 name',
    );
    assert.equal((await rpc(f, token.access_token, 'list')).data?.result?.isError, true);
    assert.equal((await exchange(f, code, request.verifier)).status, 400);
    f.sqlite
      .prepare('UPDATE agent_oauth_token SET authorization_details=?')
      .run(
        JSON.stringify([{ ...target, authority: { ...target.authority, owner_key_revision: 2 } }]),
      );
    assert.equal((await read(f, token.access_token)).status, 401);
    f.sqlite
      .prepare('UPDATE agent_oauth_token SET authorization_details=?')
      .run(JSON.stringify(authorization(v2)));
    f.sqlite.exec('UPDATE vault_owner_key_head SET revision=2');
    assert.equal((await read(f, token.access_token)).status, 401);
  } finally {
    f.sqlite.close();
  }
});

test('OAuth redemption rechecks exact details, live source and authority after consent', async () => {
  for (const stage of ['details', 'source', 'authority', 'audit']) {
    const f = fixture();
    try {
      const v2 = await selected(f);
      await create(f, v2.input);
      const request = await pending(f, authorization(v2));
      const approved = await oauth.decide(
        f.db,
        f.owner,
        { request_id: request.requestId, approve: true, grant_id: v2.input.grant_id },
        f.env,
      );
      if (stage === 'details') {
        assert.throws(() =>
          f.sqlite
            .prepare('UPDATE agent_oauth_request SET authorization_details=? WHERE request_id=?')
            .run(
              JSON.stringify([
                {
                  ...authorization(v2)[0],
                  source: { ...v2.input.source, ciphertext_sha256: id() },
                },
              ]),
              request.requestId,
            ),
        );
        continue;
      }
      if (stage === 'source')
        f.sqlite.exec("UPDATE vault_owner_record_head SET revision=2 WHERE record_id='name'");
      if (stage === 'authority') f.sqlite.exec('UPDATE vault_owner_key_head SET revision=2');
      if (stage === 'audit')
        f.sqlite.exec(
          'CREATE TRIGGER revoke_token_issue AFTER INSERT ON agent_oauth_token BEGIN UPDATE vault_owner_key_head SET revision=2; END',
        );
      const response = await exchange(
        f,
        new URL(approved.redirect).searchParams.get('code')!,
        request.verifier,
      );
      assert.equal(response.status, 400);
      assert.doesNotMatch(await response.text(), /moa_/);
    } finally {
      f.sqlite.close();
    }
  }
});

test('legacy and record status are isolated and use the same live source/recipient fences', async () => {
  const f = fixture();
  try {
    const v1 = await legacy(f),
      v2 = await selected(f);
    await create(f, v1.input);
    await create(f, v2.input);
    const legacyStatus = (await (await f.ownerRequest('/status')).json()) as any;
    assert.deepEqual(
      legacyStatus.grants.map((g: any) => g.grant_id),
      [v1.input.grant_id],
    );
    assert.ok(legacyStatus.audit.every((a: any) => a.grant_id === v1.input.grant_id));
    const connections = (await (await f.ownerRequest('/connections')).json()) as any;
    assert.deepEqual(
      connections.grants.map((g: any) => g.grant_id),
      [v1.input.grant_id],
    );
    assert.deepEqual(connections.proposals, []);
    assert.deepEqual(connections.drafts, []);
    assert.deepEqual(connections.attribute_proposals, []);
    assert.equal(connections.note_revision, 0);
    const recordStatus = (await (await f.ownerRequest('/record-status')).json()) as any;
    assert.equal(recordStatus.storage_version, 2);
    assert.equal(recordStatus.attribute_proposals, undefined);
    assert.deepEqual(
      recordStatus.grants.map((g: any) => g.grant_id),
      [v2.input.grant_id],
    );
    assert.equal(recordStatus.grants[0].active, 1);
    f.sqlite.prepare("UPDATE agent_recipient_key SET state='disabled' WHERE key_id=?").run(keyId);
    const stoppedStatus = (await (await f.ownerRequest('/record-status')).json()) as any;
    assert.equal(stoppedStatus.grants[0].active, 0);
    stopped(f, v2.input.grant_id);
  } finally {
    f.sqlite.close();
  }
});

test('v2 grants retain account, credential, expiry, session and resource boundaries', async () => {
  for (const mutation of [
    "UPDATE account_security SET epoch=2 WHERE account_id='owner'",
    "UPDATE account_security SET active=0 WHERE account_id='owner'",
    "UPDATE credential SET active=0 WHERE credential_id='passkey'",
    `UPDATE agent_grant SET created_at=${Math.floor(Date.now() / 1000) - 600},expires_at=${Math.floor(Date.now() / 1000) - 1}`,
    'UPDATE agent_grant SET revoked=1',
    "UPDATE vault_owner_record_head SET key_generation=2 WHERE record_id='name'",
    'UPDATE vault_owner_key_head SET key_generation=2',
  ]) {
    const f = fixture();
    try {
      const v2 = await selected(f);
      await create(f, v2.input);
      f.sqlite.exec(mutation);
      assert.equal((await read(f, v2.token)).status, 401);
      if (!mutation.includes('expires_at')) stopped(f, v2.input.grant_id);
    } finally {
      f.sqlite.close();
    }
  }
  for (const mutation of [
    'UPDATE sso_session SET revoked=1',
    'UPDATE sso_session SET expires_at=unixepoch()',
    'DELETE FROM sso_context',
    "UPDATE credential SET active=0 WHERE credential_id='passkey'",
  ]) {
    const f = fixture();
    try {
      const v2 = await selected(f);
      f.sqlite.exec(mutation);
      assert.equal((await f.ownerRequest('/grants', v2.input)).status, 401);
    } finally {
      f.sqlite.close();
    }
  }
});

test('fresh authenticated envelopes for a wrong tuple or authority cannot pass creation SQL', async () => {
  const f = fixture();
  try {
    const original = await selected(f);
    for (const changes of [
      { source: { ...original.input.source, vault_id: 'other-vault' } },
      { source: { ...original.input.source, revision: 2 } },
      { source: { ...original.input.source, ciphertext_sha256: id() } },
      { authority: { key_generation: 2, owner_key_revision: 1 } },
      { authority: { key_generation: 1, owner_key_revision: 2 } },
    ]) {
      const binding = { ...original.binding, ...changes };
      const envelope = await sealRecordAgentSnapshot(
        [original.document],
        { public_jwk: publicJwk, key_id: keyId, resource },
        binding,
      );
      assert.equal(
        (await f.ownerRequest('/grants', { ...original.input, ...changes, envelope })).status,
        409,
      );
    }
    assert.equal(f.sqlite.prepare('SELECT count(*) n FROM agent_grant').get()!.n, 0);
  } finally {
    f.sqlite.close();
  }
});

test('remote v2 names preserve the owner character bound and leading BOM exactly', async () => {
  const f = fixture();
  try {
    for (const text of ['é'.repeat(129), '山'.repeat(256), '\ufeffOwner name', '😀'.repeat(128)]) {
      const selectedName = await selected(f);
      const envelope = await sealRecordAgentSnapshot(
        [{ ...selectedName.document, text }],
        { public_jwk: publicJwk, key_id: keyId, resource },
        selectedName.binding,
      );
      await create(f, { ...selectedName.input, envelope });
      assert.equal((await read(f, selectedName.token)).data?.result?.structuredContent?.text, text);
    }
  } finally {
    f.sqlite.close();
  }
});

for (const stage of ['retry', 'after-audit'] as const)
  for (const [label, mutation] of Object.entries({
    target:
      "UPDATE vault_owner_record_head SET ciphertext_sha256='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE record_id='owner_note'",
    grant: 'UPDATE agent_grant SET revoked=1',
    recipient: "UPDATE agent_recipient_key SET state='disabled'",
    credential: 'UPDATE credential SET active=0',
  }))
    test(`record proposal ${stage} rechecks live ${label} before returning delegated metadata`, async () => {
      const f = fixture();
      try {
        f.sqlite.exec("INSERT INTO vault_owner_key_wrap VALUES('owner',1,'passkey','{}')");
        const v2 = await selected(f);
        await create(f, v2.input);
        const target = {
          ...v2.input.source,
          record_id: 'owner_note',
          kind: 'owner_note',
          ciphertext_sha256: hash('owner_note'),
          deleted: false,
        };
        const allowed = await f.ownerRequest('/record-capability', {
          grant_id: v2.input.grant_id,
          target,
          authority: v2.input.authority,
        });
        assert.equal(allowed.status, 200, await allowed.text());
        const input = {
          storage_version: 2,
          proposal_id: id(),
          target,
          authority: v2.input.authority,
          value: newOwnerNote('Approved target', 'Keep this exact target'),
          expires_at: f.time + 300,
        };
        const grant = await store.active(f.db, hash(v2.token), keyId, resource);
        if (stage === 'retry') await records.propose(f.db, grant, input);
        let injected = false;
        f.afterQuery((sql) => {
          if (
            !injected &&
            (stage === 'retry' ? sql.startsWith('SELECT cap.*') : sql.includes("'record-propose'"))
          ) {
            injected = true;
            f.sqlite.exec(mutation);
          }
        });
        await assert.rejects(records.propose(f.db, grant, input), /Access denied/);
        assert.equal(injected, true);
      } finally {
        f.sqlite.close();
      }
    });

for (const [label, mutation] of Object.entries({
  target:
    "UPDATE vault_owner_record_head SET ciphertext_sha256='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE record_id='owner_note'",
  capability: 'DELETE FROM agent_attribute_capability',
  expiry: 'UPDATE agent_attribute_proposal SET expires_at=unixepoch()',
}))
  test(`public record proposal closes the final generic-refresh ${label} race`, async () => {
    const f = fixture();
    try {
      f.sqlite.exec("INSERT INTO vault_owner_key_wrap VALUES('owner',1,'passkey','{}')");
      const v2 = await selected(f);
      await create(f, v2.input);
      const target = {
        ...v2.input.source,
        record_id: 'owner_note',
        kind: 'owner_note',
        ciphertext_sha256: hash('owner_note'),
        deleted: false,
      };
      const allowed = await f.ownerRequest('/record-capability', {
        grant_id: v2.input.grant_id,
        target,
        authority: v2.input.authority,
      });
      assert.equal(allowed.status, 200, await allowed.text());
      const input = {
        storage_version: 2,
        proposal_id: id(),
        target,
        authority: v2.input.authority,
        value: newOwnerNote('Exact target', 'Do not return stale authority'),
        expires_at: f.time + 300,
      };
      let injected = false;
      f.afterQuery((sql) => {
        if (
          !injected &&
          sql.startsWith('SELECT p.* FROM agent_attribute_proposal p WHERE p.proposal_id=')
        ) {
          injected = true;
          if (label === 'expiry') {
            // Advance database time, never mutate an immutable proposal deadline.
            f.sqlite.function('unixepoch', () => f.time + 301);
          } else f.sqlite.exec(mutation);
        }
      });
      const response = await rpc(f, v2.token, 'propose_record', input);
      assert.equal(response.status, 200);
      assert.equal(response.data?.result?.isError, true);
      assert.equal(response.data?.result?.structuredContent, undefined);
      assert.equal(injected, true);
    } finally {
      f.sqlite.close();
    }
  });
