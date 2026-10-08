import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { VaultScope } from '../../crates/worker/ui/vault-lifecycle.ts';
import { OwnerVaultController } from '../../crates/worker/ui/vault-owner-controller.ts';
import {
  OwnerRecordStore,
  OWNER_NAME,
  OWNER_NOTE,
} from '../../crates/worker/ui/vault-owner-record-store.ts';
import { OwnerRecordDisclosure } from '../../crates/worker/ui/vault-owner-disclosure.ts';
import { encodeOwnerNote, newOwnerNote } from '../../crates/worker/ui/vault-note.ts';
import { encodeBase64Url, decodeBase64Url } from '../../crates/worker/ui/vault-crypto.ts';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import {
  openRecordAgentSnapshot,
  sealRecordAgentSnapshot,
  type RecordAgentBinding,
} from '../../crates/worker/ui/agent-record-crypto.ts';
import {
  parseVaultRecordSource,
  parseVaultSource,
  parseVaultRecordAuthority,
  equalVaultSource,
} from '../../crates/worker/ui/vault-record-source.ts';
import { AgentAccess } from '../agent-access.ts';
import { toolOutputs, toolResult } from '../../crates/agent-worker/tool-results.ts';

const encoder = new TextEncoder();
function fixture() {
  const credential = new Uint8Array(32).fill(8);
  const identity = {
    account_id: 'owner',
    credential_id: encodeBase64Url(credential),
    session_tag: 's'.repeat(43),
  };
  let root: Record<string, unknown> | null = null,
    ceremonies = 0;
  const heads = new Map<string, Record<string, unknown>>();
  const paths: string[] = [];
  let intercept: ((path: string, init: RequestInit | undefined) => Promise<void>) | undefined;
  const scope = new VaultScope(
    () => {},
    undefined,
    undefined,
    async (url, init) => {
      const path = String(url);
      paths.push(path);
      if (intercept) await intercept(path, init);
      if (path === '/vault/session') return Response.json(identity);
      if (path === '/vault/owner-key') {
        if (init?.method === 'PUT')
          root = {
            ...JSON.parse(String(init.body)),
            revision: 1,
            origin: 'https://mikaki.test',
            owner_id: 'owner',
          };
        return root
          ? Response.json(root, { headers: { ETag: `"${root.revision}"` } })
          : Response.json({ error: 'owner_key_missing' }, { status: 404 });
      }
      if (init?.method === 'PUT' || init?.method === 'DELETE') {
        const value = JSON.parse(String(init.body));
        heads.set(path, { ...value, deleted: init.method === 'DELETE' });
        return Response.json(
          { revision: value.revision, deleted: init.method === 'DELETE' },
          { headers: { ETag: `"${value.revision}"` } },
        );
      }
      const value = heads.get(path);
      if (!value) return Response.json({ error: 'not_found' }, { status: 404 });
      if (value.deleted)
        return Response.json(
          { error: 'not_found', deleted: true },
          { status: 404, headers: { ETag: `"${value.revision}"` } },
        );
      return Response.json(
        {
          ...value,
          owner_id: 'owner',
          origin: 'https://mikaki.test',
          collection_id: 'personal',
          record_id: path.split('/').at(-1),
          owner_key_revision: root!.revision,
        },
        { headers: { ETag: `"${value.revision}"` } },
      );
    },
  );
  const owner = new OwnerVaultController(scope, 'https://mikaki.test', async () => {
    ceremonies++;
    return { credentialId: credential, output: new Uint8Array(32).fill(9) };
  });
  return {
    owner,
    scope,
    heads,
    paths,
    ceremonies: () => ceremonies,
    intercept: (hook: typeof intercept) => {
      intercept = hook;
    },
    replaceSession: () => {
      identity.session_tag = 'r'.repeat(43);
    },
    replaceRoot: () => {
      root!.revision = Number(root!.revision) + 1;
    },
  };
}
async function savedFixture() {
  const f = fixture();
  await f.owner.open();
  const name = new OwnerRecordStore(f.owner, OWNER_NAME),
    note = new OwnerRecordStore(f.owner, OWNER_NOTE);
  await name.commit(await name.prepare('PUT', 0, encoder.encode('Selected name')));
  await note.commit(
    await note.prepare(
      'PUT',
      0,
      encodeOwnerNote(newOwnerNote('Private note', 'Never include unless selected')),
    ),
  );
  f.paths.length = 0;
  return { ...f, name, note, disclosure: new OwnerRecordDisclosure(f.owner, () => 1000) };
}
const options = { delegate: 'local-codex', service: 'OpenAI', ttl: 3600 };
async function recipient() {
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
  const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
  return {
    privateKey: keys.privateKey,
    recipient: {
      public_jwk: jwk,
      key_id: await agentKeyId(jwk),
      resource: 'https://agent.test/mcp',
    },
  };
}

test('source identity requires explicit storage version, canonical digest and exact bounded target; content and authority revisions stay separate', () => {
  const source = {
    storage_version: 2,
    origin: 'https://mikaki.test',
    owner_id: 'owner',
    vault_id: 'vault',
    collection_id: 'personal',
    record_id: 'name',
    kind: 'name',
    revision: 5,
    ciphertext_sha256: 'A'.repeat(43),
  };
  const normalized = parseVaultRecordSource(source);
  assert.ok(Object.isFrozen(normalized));
  assert.deepEqual(parseVaultRecordAuthority({ key_generation: 2, owner_key_revision: 9 }), {
    key_generation: 2,
    owner_key_revision: 9,
  });
  const legacy = parseVaultSource({
    storage_version: 1,
    origin: source.origin,
    owner_id: source.owner_id,
    attribute_id: 'name',
    revision: 5,
    ciphertext_sha256: source.ciphertext_sha256,
  });
  assert.equal(equalVaultSource(legacy, normalized), false);
  for (const change of [
    { storage_version: undefined },
    { storage_version: 3 },
    { record_id: 'name', kind: 'owner_note' },
    { collection_id: 'threads' },
    { record_id: 'thread1', kind: 'thread_v1' },
    { origin: 'https://mikaki.test/' },
    { origin: 'http://mikaki.test' },
    { owner_id: '' },
    { revision: 0 },
    { revision: Number.MAX_SAFE_INTEGER + 1 },
    { ciphertext_sha256: 'B'.repeat(43) },
    { key_generation: 1 },
    { owner_key_revision: 1 },
    { owner_key: 'forbidden' },
  ])
    assert.throws(() => parseVaultRecordSource({ ...source, ...change }));
  source.revision = 99;
  assert.equal(normalized.revision, 5);
});

test('selected local export reads only selected saved records with one owner ceremony and does not expose root/content keys', async () => {
  const f = await savedFixture();
  const prepared = await f.disclosure.prepareLocalExport(['name'], options);
  const bundle = JSON.parse(prepared.bundle),
    grant = JSON.parse(prepared.grant);
  assert.equal(bundle.version, 2);
  assert.equal(grant.version, 2);
  assert.equal(bundle.documents.length, 1);
  assert.equal(bundle.documents[0].text, 'Selected name');
  assert.equal(bundle.documents[0].source_info.kind, 'vault-record');
  assert.equal(bundle.documents[0].source_info.source.revision, 1);
  assert.equal(bundle.documents[0].source_info.authority.owner_key_revision, 1);
  assert.deepEqual(grant.document_ids, ['name']);
  assert.equal(f.ceremonies(), 1);
  assert.ok(!f.paths.includes('/vault/records/personal/owner_note'));
  assert.ok(!f.paths.some((path) => path.includes('/vault/attributes/')));
  assert.doesNotMatch(
    prepared.bundle + prepared.grant,
    /Never include|key_envelope|owner_envelope|wrapped_key|prf_input/,
  );
  assert.ok(
    Object.isFrozen(prepared) &&
      Object.isFrozen(prepared.sources) &&
      Object.isFrozen(prepared.sources[0]!.source),
  );
  const both = await f.disclosure.prepareLocalExport(['name', 'owner_note'], options);
  assert.equal(JSON.parse(both.bundle).documents.length, 2);
  assert.equal(f.ceremonies(), 1);
  await assert.rejects(f.disclosure.prepareLocalExport([], options));
  await assert.rejects(f.disclosure.prepareLocalExport(['name', 'name'], options));
  await assert.rejects(f.disclosure.prepareLocalExport(['name'], { ...options, ttl: 86401 }));
});

test('local v2 export round-trips through actual stdio MCP; explicit source binding, expiry, audit and v1 isolation remain enforced', async () => {
  const f = await savedFixture();
  const disclosure = new OwnerRecordDisclosure(f.owner);
  const prepared = await disclosure.prepareLocalExport(['owner_note'], options);
  const dir = await mkdtemp(join(tmpdir(), 'record-export-'));
  const exportPath = join(dir, 'export.json'),
    grantPath = join(dir, 'grant.json'),
    auditPath = join(dir, 'audit.jsonl');
  await writeFile(exportPath, prepared.bundle);
  await writeFile(grantPath, prepared.grant);
  const client = new Client({ name: 'record-fixture', version: '1' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [resolve('local/agent-mcp.ts'), grantPath, exportPath, auditPath, options.delegate],
    stderr: 'pipe',
  });
  try {
    await client.connect(transport);
    const list = await client.callTool({ name: 'mikaki_list', arguments: {} });
    const listed = toolOutputs.list.parse(list.structuredContent);
    assert.equal(list.isError, undefined);
    assert.deepEqual(
      listed.documents.map((doc) => doc.id),
      ['owner_note'],
    );
    const listedInfo = listed.documents[0]!.source_info;
    if (listedInfo.kind !== 'vault-record') throw new Error('Expected v2 list metadata');
    assert.deepEqual(listedInfo.source, JSON.parse(prepared.grant).sources[0].source);
    assert.deepEqual(listedInfo.authority, JSON.parse(prepared.grant).sources[0].authority);
    const search = await client.callTool({
      name: 'mikaki_search',
      arguments: { query: 'Never include unless selected' },
    });
    const searched = toolOutputs.search.parse(search.structuredContent);
    assert.equal(search.isError, undefined);
    assert.deepEqual(
      searched.documents.map((doc) => doc.id),
      ['owner_note'],
    );
    const result = await client.callTool({ name: 'mikaki_read', arguments: { id: 'owner_note' } });
    assert.equal(result.isError, undefined);
    const value = result.structuredContent as Record<string, unknown>;
    assert.deepEqual(toolResult('read', value).structuredContent, value);
    assert.match(String(value.text), /Never include/);
    assert.equal((value.source_info as { kind: string }).kind, 'vault-record');
    assert.equal((value.access as { source_check: string }).source_check, 'not-checked');
    assert.deepEqual(
      (value.source_info as { source: unknown }).source,
      JSON.parse(prepared.grant).sources[0].source,
    );
    assert.deepEqual(
      (value.source_info as { authority: unknown }).authority,
      JSON.parse(prepared.grant).sources[0].authority,
    );
    const missing = await client.callTool({ name: 'mikaki_read', arguments: { id: 'name' } });
    assert.equal(missing.isError, true);
    assert.equal(missing.structuredContent, undefined);
    const original = JSON.parse(prepared.grant);
    for (const change of [
      { revoked: true },
      { version: 1 },
      {
        sources: [
          { ...original.sources[0], source: { ...original.sources[0].source, vault_id: 'other' } },
        ],
      },
      {
        sources: [
          { ...original.sources[0], source: { ...original.sources[0].source, revision: 9 } },
        ],
      },
      {
        sources: [
          { ...original.sources[0], authority: { key_generation: 2, owner_key_revision: 1 } },
        ],
      },
    ]) {
      await writeFile(grantPath, JSON.stringify({ ...original, ...change }));
      for (const [tool, args] of [
        ['mikaki_list', {}],
        ['mikaki_search', { query: 'v2-probe-needle' }],
        ['mikaki_read', { id: 'owner_note' }],
      ] as const) {
        const denied = await client.callTool({ name: tool, arguments: args });
        assert.equal(denied.isError, true);
        assert.equal(denied.structuredContent, undefined);
      }
    }
    await writeFile(grantPath, prepared.grant);
    const brokenAudit = await AgentAccess.create({
      grantPath,
      exportPath,
      auditPath: dir,
      delegate: options.delegate,
    });
    await assert.rejects(brokenAudit.call('read', { id: 'owner_note' }));
  } finally {
    await client.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('record snapshot uses separate version/domain and independently decrypts only the selected canonical plaintext', async () => {
  const f = await savedFixture(),
    key = await recipient();
  const prepared = await f.disclosure.prepareSnapshot('owner_note', key.recipient, {
    grant_id: 'g'.repeat(43),
    expires_at: 2000,
  });
  const binding: RecordAgentBinding = {
    owner: 'owner',
    grant_id: 'g'.repeat(43),
    key_id: key.recipient.key_id,
    resource: key.recipient.resource,
    expires_at: 2000,
    source: prepared.source,
    authority: prepared.authority,
  };
  // This receiver constructs the specified bytes independently, not through the product opener.
  const label = encoder.encode(JSON.stringify(['mikaki-agent-record-snapshot', 2, binding]));
  const raw = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'RSA-OAEP', label },
      key.privateKey,
      decodeBase64Url(prepared.envelope.wrapped_key),
    ),
  );
  try {
    const dataKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const bytes = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: decodeBase64Url(prepared.envelope.nonce), additionalData: label },
        dataKey,
        decodeBase64Url(prepared.envelope.ciphertext),
      ),
    );
    try {
      assert.equal(JSON.parse(new TextDecoder().decode(bytes))[0].id, 'owner_note');
    } finally {
      bytes.fill(0);
    }
  } finally {
    raw.fill(0);
  }
  const opened = await openRecordAgentSnapshot(prepared.envelope, key.privateKey, binding);
  assert.equal((opened as { id: string }[])[0]!.id, 'owner_note');
  for (const source of [
    { ...prepared.source, revision: 2 },
    { ...prepared.source, vault_id: 'other' },
    { ...prepared.source, owner_id: 'other' },
    { ...prepared.source, origin: 'https://other.test' },
    { ...prepared.source, record_id: 'name', kind: 'name' },
    { ...prepared.source, ciphertext_sha256: 'A'.repeat(43) },
  ])
    await assert.rejects(
      openRecordAgentSnapshot(prepared.envelope, key.privateKey, {
        ...binding,
        source: source as typeof prepared.source,
      }),
    );
  for (const change of [
    { grant_id: 'h'.repeat(43) },
    { expires_at: 2001 },
    { authority: { key_generation: 2, owner_key_revision: 1 } },
    { authority: { key_generation: 1, owner_key_revision: 2 } },
  ])
    await assert.rejects(
      openRecordAgentSnapshot(prepared.envelope, key.privateKey, { ...binding, ...change }),
    );
  await assert.rejects(
    openRecordAgentSnapshot(
      { ...prepared.envelope, version: 1 } as unknown as Parameters<
        typeof openRecordAgentSnapshot
      >[0],
      key.privateKey,
      binding,
    ),
  );
  await assert.rejects(sealRecordAgentSnapshot([], key.recipient, binding));
  await assert.rejects(
    sealRecordAgentSnapshot(
      [{ id: 'name', title: 'Wrong', source: 'x', text: 'x' }],
      key.recipient,
      binding,
    ),
  );
  assert.equal(f.ceremonies(), 1);
});

test('source changes, malformed plaintext, deletion, replaced authority and late decrypt/transport outputs fail closed', async () => {
  for (const kind of ['changed', 'deleted', 'root', 'session', 'hidden'] as const) {
    const f = await savedFixture();
    let reads = 0;
    f.intercept(async (path, init) => {
      if (path !== '/vault/records/personal/name' || init?.method) return;
      if (++reads !== 2) return;
      if (kind === 'changed')
        await f.name.commit(await f.name.prepare('PUT', 1, encoder.encode('Changed')));
      if (kind === 'deleted') await f.name.commit(await f.name.prepare('DELETE', 1));
      if (kind === 'root') f.replaceRoot();
      if (kind === 'session') f.replaceSession();
      if (kind === 'hidden') f.owner.suspend();
    });
    await assert.rejects(
      f.disclosure.prepareLocalExport(['name'], options),
      { name: /Error/ },
      kind,
    );
  }
  const f = await savedFixture();
  await f.note.commit(await f.note.prepare('PUT', 1, encoder.encode('{"unknown":"not a note"}')));
  await assert.rejects(f.disclosure.prepareLocalExport(['owner_note'], options));
  await f.name.commit(await f.name.prepare('PUT', 1, new Uint8Array([0xff])));
  await assert.rejects(f.disclosure.prepareLocalExport(['name'], options));
  const late = await savedFixture();
  const session = late.owner.lease().session,
    open = session.open.bind(session);
  let captured: Uint8Array<ArrayBuffer> | undefined;
  session.open = async (...args) => {
    captured = await open(...args);
    late.owner.lock();
    return captured;
  };
  await assert.rejects(late.disclosure.prepareLocalExport(['name'], options));
  assert.ok(captured?.every((byte) => byte === 0));
});

test('suspension during independent transport encryption rejects late output, and preparation cannot return expired grants', async (t) => {
  const f = await savedFixture(),
    key = await recipient();
  const original = crypto.subtle.encrypt.bind(crypto.subtle);
  let encrypted = false;
  t.mock.method(
    crypto.subtle,
    'encrypt',
    async (...args: Parameters<typeof crypto.subtle.encrypt>) => {
      const result = await original(...args);
      const algorithm = args[0];
      if (typeof algorithm === 'object' && algorithm.name === 'RSA-OAEP') {
        encrypted = true;
        f.owner.suspend();
      }
      return result;
    },
  );
  await assert.rejects(
    f.disclosure.prepareSnapshot('name', key.recipient, {
      grant_id: 'g'.repeat(43),
      expires_at: 2000,
    }),
  );
  assert.equal(encrypted, true);
  t.mock.restoreAll();
  const expired = await savedFixture();
  let time = 1000,
    reads = 0;
  expired.intercept(async (path) => {
    if (path === '/vault/records/personal/name' && ++reads === 3) time = 5000;
  });
  await assert.rejects(
    new OwnerRecordDisclosure(expired.owner, () => time).prepareLocalExport(['name'], options),
    /expired/,
  );
});

test('temporary exported plaintext digest bytes are cleared after success and digest rejection', async (t) => {
  for (const fail of [false, true]) {
    const f = await savedFixture();
    const original = crypto.subtle.digest.bind(crypto.subtle);
    let captured: Uint8Array | undefined;
    t.mock.method(
      crypto.subtle,
      'digest',
      async (...args: Parameters<typeof crypto.subtle.digest>) => {
        const value = args[1];
        if (
          value instanceof Uint8Array &&
          new TextDecoder().decode(value).includes('Selected name')
        ) {
          captured = value;
          if (fail) throw new Error('injected digest failure');
        }
        return original(...args);
      },
    );
    if (fail)
      await assert.rejects(f.disclosure.prepareLocalExport(['name'], options), /injected digest/);
    else await f.disclosure.prepareLocalExport(['name'], options);
    assert.ok(captured && captured.every((byte) => byte === 0));
    t.mock.restoreAll();
  }
});
