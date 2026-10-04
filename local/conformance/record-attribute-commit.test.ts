/** Paired real Rust OP and TypeScript agent Workers, with workerd D1/R2.
 * All identities, PRF values, ciphertext and recipient keys are disposable.
 * Build the Rust Worker before running; this suite needs no browser or remote service. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTestHarness } from 'wrangler';
import { agentKeyId } from '../../crates/worker/ui/agent-crypto.ts';
import { sealRecordAgentSnapshot } from '../../crates/worker/ui/agent-record-crypto.ts';
import { sealAttribute } from '../../crates/worker/ui/vault-crypto.ts';
import {
  createOwnerKey,
  openOwnerKey,
  openOwnerRecord,
  sealOwnerRecord,
  sealApprovedOwnerRecord,
  OWNER_KEY_SUITE,
  type OwnerRecord,
} from '../../crates/worker/ui/vault-owner-crypto.ts';
import {
  encodeOwnerNote,
  decodeOwnerNote,
  newOwnerNote,
} from '../../crates/worker/ui/vault-note.ts';
import type {
  ApprovedRecordNote,
  RecordNoteTarget,
} from '../../crates/worker/ui/vault-record-approval.ts';
import type { VaultRecordSource } from '../../crates/worker/ui/vault-record-source.ts';

const origin = 'https://mikaki.test',
  resource = 'https://agent.mikaki.test/mcp';
const id = () => randomBytes(32).toString('base64url');
const hash = (value: string | Uint8Array) => createHash('sha256').update(value).digest('base64url');
const bytes = (value: string) => new TextEncoder().encode(value);
const base64 = (value: Uint8Array) => Buffer.from(value).toString('base64url');
const recordUrl = (record = 'owner_note', collection = 'personal') =>
  `${origin}/vault/records/${collection}/${record}`;
const fields = (...parts: string[]) =>
  new Uint8Array(
    Buffer.concat(
      parts.flatMap((part) => {
        const body = Buffer.from(part),
          length = Buffer.alloc(2);
        length.writeUInt16BE(body.length);
        return [length, body];
      }),
    ),
  );
const authority = { key_generation: 1, owner_key_revision: 1 };
type CandidateBody = {
  format_version: 2;
  vault_id: string;
  key_generation: number;
  owner_key_revision: number;
  kind: string;
  revision: number;
  ciphertext: string;
  key_envelope: string;
};
type SavedRecord = OwnerRecord & {
  owner_id: string;
  origin: string;
  vault_id: string;
  collection_id: 'personal';
  record_id: 'name' | 'owner_note';
  kind: 'name' | 'owner_note';
  revision: number;
};

test('v2 approved owner-note commits bind exact values and atomically preserve live authority in paired Workers', async (t) => {
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
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey),
    privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey),
    keyId = await agentKeyId(publicJwk),
    recipient = { public_jwk: publicJwk, key_id: keyId, resource };
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-record-commit-'));
  const shim = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
  // Faults wrap only the test-owned R2 binding. SQL, triggers, rollback and the
  // final batch use real workerd D1. The post-upload hook crosses the real await
  // between preflight and consumption; no service/Rust authorization is mocked.
  const services = new URL('../../crates/worker/service/entrypoint.ts', import.meta.url).pathname;
  await writeFile(
    join(directory, 'op.mjs'),
    `import Op from ${JSON.stringify(shim)};
    export { AgentStore, ClaimStore } from ${JSON.stringify(services)};
    export default {async fetch(request,env,ctx){
      const fault=await env.DB.prepare('SELECT mode,statement,until FROM record_commit_test_fault WHERE id=1').first();
      const bucket=new Proxy(env.VAULT_BLOBS,{get(target,key){
        if(key==='constructor') return target.constructor;
        if(key==='put') return async (...args)=>{
          if(fault.mode){
            await env.DB.prepare('UPDATE record_commit_test_fault SET hits=hits+1 WHERE id=1').run();
            if(fault.mode==='throw') throw new Error('injected R2 upload failure');
          }
          const result=await target.put(...args);
          if(fault.mode==='after-put'){
            if(fault.statement) await env.DB.exec(fault.statement);
            if(fault.until) await new Promise(resolve=>setTimeout(resolve,Math.max(0,(fault.until+1)*1000-Date.now())));
          }
          return result;
        };
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
          main: join(directory, 'op.mjs'),
          compatibility_date: '2026-09-28',
          rules: [{ type: 'Text', globs: ['**/*.sql'], fallthrough: true }],
          vars: { MIKAKI_ISSUER: origin },
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
  try {
    await harness.listen();
    const op = harness.getWorker('mikaki-op-agent-local'),
      agent = harness.getWorker('mikaki-agent-local');
    await op.applyD1Migrations('DB');
    const env = await op.getEnv();
    await env.DB.exec(
      "CREATE TABLE record_commit_test_fault(id INTEGER PRIMARY KEY,mode TEXT,statement TEXT,until INTEGER,hits INTEGER); INSERT INTO record_commit_test_fault VALUES(1,'','',0,0)",
    );
    await env.DB.prepare("INSERT INTO agent_recipient_key VALUES(?,'active')").bind(keyId).run();
    const fault = (mode = '', statement = '', until = 0) =>
      env.DB.prepare(
        'UPDATE record_commit_test_fault SET mode=?,statement=?,until=?,hits=0 WHERE id=1',
      )
        .bind(mode, statement, until)
        .run();
    const bootstrap = async (account: string) => {
      const cookie = id(),
        credential = new Uint8Array(randomBytes(32)),
        prf = new Uint8Array(randomBytes(32)),
        now = Math.floor(Date.now() / 1000);
      await env.DB.batch([
        env.DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account),
        env.DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(base64(credential), account),
        env.DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,?,0)').bind(
          account,
          account,
          base64(credential),
          now + 3600,
        ),
        env.DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(account, hash(cookie), now),
      ]);
      const headers = {
        Cookie: `__Host-op-sso=${cookie}`,
        Origin: origin,
        'Content-Type': 'application/json',
      };
      const context = { origin, ownerId: account, vaultId: 'vault', keyGeneration: 1 };
      const created = await createOwnerKey(
        context,
        credential,
        new Uint8Array(randomBytes(32)),
        prf.slice(),
      );
      const response = await op.fetch(`${origin}/vault/owner-key`, {
        method: 'PUT',
        headers: { ...headers, 'X-Operation-ID': id(), 'If-None-Match': '*' },
        body: JSON.stringify({
          format_version: 2,
          suite: OWNER_KEY_SUITE,
          vault_id: 'vault',
          key_generation: 1,
          owner_envelope: created.envelope,
        }),
      });
      assert.equal(response.status, 200, await response.clone().text());
      const recovered = await op.fetch(`${origin}/vault/owner-key`, { headers });
      assert.equal(recovered.status, 200);
      const root = (await recovered.json()) as { owner_envelope: unknown };
      const key = await openOwnerKey(root.owner_envelope, context, credential, prf.slice());
      return { account, cookie, credential, prf, context, headers, key };
    };
    type Owner = Awaited<ReturnType<typeof bootstrap>>;
    const ownerCall = (owner: Owner, path: string, body?: unknown) =>
      op.fetch(`${origin}/vault/agents/${path}`, {
        method: body === undefined ? 'GET' : 'POST',
        headers: owner.headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    const get = (owner: Owner, record = 'owner_note') =>
      op.fetch(recordUrl(record), { headers: owner.headers });
    const head = (owner: Owner, record = 'owner_note') =>
      env.DB.prepare(
        "SELECT * FROM vault_owner_record_head WHERE account_id=? AND vault_id='vault' AND collection_id='personal' AND record_id=?",
      )
        .bind(owner.account, record)
        .first();
    const write = async (
      owner: Owner,
      record: 'name' | 'owner_note',
      revision: number,
      value: Uint8Array<ArrayBuffer>,
    ) => {
      const encrypted = await sealOwnerRecord(value, owner.key, owner.context, {
        collectionId: 'personal',
        recordId: record,
        kind: record,
        revision,
      });
      const body = JSON.stringify({
        format_version: 2,
        vault_id: 'vault',
        ...authority,
        kind: record,
        revision,
        ciphertext: encrypted.ciphertext,
        key_envelope: encrypted.key_envelope,
      });
      const response = await op.fetch(recordUrl(record), {
        method: 'PUT',
        headers: {
          ...owner.headers,
          'X-Operation-ID': id(),
          ...(revision === 1 ? { 'If-None-Match': '*' } : { 'If-Match': `"${revision - 1}"` }),
        },
        body,
      });
      assert.equal(response.status, 200, await response.clone().text());
      return body;
    };
    const target = async (owner: Owner): Promise<RecordNoteTarget> => {
      const current = await head(owner);
      return {
        storage_version: 2,
        origin,
        owner_id: owner.account,
        vault_id: 'vault',
        collection_id: 'personal',
        record_id: 'owner_note',
        kind: 'owner_note',
        revision: current?.revision ?? 0,
        ciphertext_sha256: current?.ciphertext_sha256 ?? null,
        deleted: current?.deleted === 1,
      };
    };
    const propose = async (owner: Owner, expires = Math.floor(Date.now() / 1000) + 1200) => {
      let sourceHead = await head(owner, 'name');
      if (!sourceHead) {
        await write(owner, 'name', 1, bytes('Selected v2 name'));
        sourceHead = await head(owner, 'name');
      }
      const source: VaultRecordSource = {
        storage_version: 2,
        origin,
        owner_id: owner.account,
        vault_id: 'vault',
        collection_id: 'personal',
        record_id: 'name',
        kind: 'name',
        revision: sourceHead.revision,
        ciphertext_sha256: sourceHead.ciphertext_sha256,
      };
      const grantId = id(),
        token = `mag_${id()}`,
        grantExpires = Math.floor(Date.now() / 1000) + 1800;
      const envelope = await sealRecordAgentSnapshot(
        [
          {
            id: 'name',
            title: 'Name',
            source: 'untrusted display label',
            text: 'Selected v2 name',
          },
        ],
        recipient,
        {
          owner: owner.account,
          grant_id: grantId,
          key_id: keyId,
          resource,
          expires_at: grantExpires,
          source,
          authority,
        },
      );
      const grant = await ownerCall(owner, 'grants', {
        storage_version: 2,
        grant_id: grantId,
        delegate: 'synthetic-agent',
        provider: 'fixture',
        resource,
        source,
        authority,
        recipient_key_id: keyId,
        operations: ['read', 'propose', 'execute'],
        document_ids: ['name'],
        envelope,
        token_hash: hash(token),
        expires_at: grantExpires,
      });
      assert.equal(grant.status, 200, await grant.clone().text());
      const selectedTarget = await target(owner);
      const capability = await ownerCall(owner, 'record-capability', {
        grant_id: grantId,
        target: selectedTarget,
        authority,
      });
      assert.equal(capability.status, 200, await capability.clone().text());
      const proposalId = id(),
        value = newOwnerNote(`Proposed ${selectedTarget.revision}`, 'Exact approved value 🗾');
      const response = await agent.fetch('https://agent.mikaki.test/record-proposals', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          storage_version: 2,
          proposal_id: proposalId,
          target: selectedTarget,
          authority,
          value,
          expires_at: expires,
        }),
      });
      assert.equal(response.status, 200, await response.clone().text());
      const result = (await response.json()) as { content: { text: string }[] };
      const receipt = JSON.parse(result.content[0]!.text) as {
        request_hash: string;
        target: RecordNoteTarget;
        authority: typeof authority;
      };
      assert.deepEqual(receipt.target, selectedTarget);
      assert.deepEqual(receipt.authority, authority);
      const approval: ApprovedRecordNote = {
        proposal_id: proposalId,
        request_hash: receipt.request_hash,
        grant_id: grantId,
        payload: new TextDecoder().decode(encodeOwnerNote(value)),
        expires_at: expires,
        target: selectedTarget,
        authority,
      };
      return { ...approval, value, token };
    };
    type Proposal = Awaited<ReturnType<typeof propose>>;
    const approve = async (owner: Owner, p: Proposal) => {
      const response = await ownerCall(owner, 'record-decide', {
        proposal_id: p.proposal_id,
        request_hash: p.request_hash,
        approve: true,
      });
      assert.equal(response.status, 200, await response.clone().text());
    };
    // Independently construct candidate frames, length-prefixed AAD and encrypted
    // proof. A correctly signed noncanonical candidate tests the receiver rather
    // than just failing an old digest or the production client's own validator.
    const candidate = async (
      owner: Owner,
      p: Proposal,
      options: {
        payload?: string;
        serialize?: (value: CandidateBody) => string;
        proofPurpose?: string;
        proofBinding?: Record<string, unknown>;
        candidateContext?: {
          origin?: string;
          owner?: string;
          vault?: string;
          collection?: string;
          record?: string;
          revision?: number;
        };
      } = {},
    ) => {
      const raw = new Uint8Array(randomBytes(32)),
        transport = new Uint8Array(randomBytes(32));
      try {
        const dataKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
        const nonce = new Uint8Array(randomBytes(12)),
          wrapNonce = new Uint8Array(randomBytes(12));
        const identity = options.candidateContext;
        const common = [
          '2',
          identity?.origin ?? origin,
          identity?.owner ?? owner.account,
          identity?.vault ?? 'vault',
        ];
        const record = [
          identity?.collection ?? 'personal',
          identity?.record ?? 'owner_note',
          'owner_note',
          String(identity?.revision ?? p.target.revision + 1),
        ];
        const encrypted = new Uint8Array(
          await crypto.subtle.encrypt(
            {
              name: 'AES-GCM',
              iv: nonce,
              additionalData: fields('mikaki-vault-record-content', ...common, ...record),
            },
            dataKey,
            bytes(options.payload ?? p.payload),
          ),
        );
        const wrapped = new Uint8Array(
          await crypto.subtle.encrypt(
            {
              name: 'AES-GCM',
              iv: wrapNonce,
              additionalData: fields('mikaki-vault-record-key', ...common, '1', ...record),
            },
            owner.key,
            raw,
          ),
        );
        const ciphertext = base64(
          new Uint8Array(Buffer.concat([new Uint8Array([2]), nonce, encrypted])),
        );
        const body: CandidateBody = {
          format_version: 2,
          vault_id: 'vault',
          ...authority,
          kind: 'owner_note',
          revision: p.target.revision + 1,
          ciphertext,
          key_envelope: base64(
            new Uint8Array(Buffer.concat([new Uint8Array([2]), wrapNonce, wrapped])),
          ),
        };
        const serialized = (options.serialize ?? JSON.stringify)(body),
          operation = id();
        const binding = {
          owner: owner.account,
          grant_id: p.grant_id,
          key_id: keyId,
          resource,
          expires_at: p.expires_at,
          proposal_id: p.proposal_id,
          request_hash: p.request_hash,
          operation_id: operation,
          candidate_sha256: hash(serialized),
          target: p.target,
          authority,
          candidate_source: {
            storage_version: 2,
            origin,
            owner_id: owner.account,
            vault_id: 'vault',
            collection_id: 'personal',
            record_id: 'owner_note',
            kind: 'owner_note',
            revision: p.target.revision + 1,
            ciphertext_sha256: hash(Buffer.from(ciphertext, 'base64url')),
          },
          ...options.proofBinding,
        };
        const label = bytes(
          JSON.stringify([options.proofPurpose ?? 'mikaki-approved-record-proof', 2, binding]),
        );
        const proofKey = await crypto.subtle.importKey('raw', transport, 'AES-GCM', false, [
          'encrypt',
        ]);
        const proofNonce = new Uint8Array(randomBytes(12));
        const proof = {
          version: 2,
          wrapped_key: base64(
            new Uint8Array(
              await crypto.subtle.encrypt({ name: 'RSA-OAEP', label }, pair.publicKey, transport),
            ),
          ),
          nonce: base64(proofNonce),
          ciphertext: base64(
            new Uint8Array(
              await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: proofNonce, additionalData: label },
                proofKey,
                raw,
              ),
            ),
          ),
        };
        return {
          proposal_id: p.proposal_id,
          request_hash: p.request_hash,
          operation_id: operation,
          candidate: serialized,
          proof,
        };
      } finally {
        raw.fill(0);
        transport.fill(0);
      }
    };
    type Candidate = Awaited<ReturnType<typeof candidate>>;
    const prepare = (owner: Owner, c: Candidate) => ownerCall(owner, 'record-prepare', c);
    const commit = (
      owner: Owner,
      p: Proposal,
      c: Candidate,
      options: {
        headers?: Record<string, string | null>;
        body?: string;
        url?: string;
        method?: string;
      } = {},
    ) => {
      const headers = new Headers({
        ...owner.headers,
        'X-Operation-ID': c.operation_id,
        'X-Attribute-Proposal': p.proposal_id,
        'X-Proposal-Hash': p.request_hash,
        ...(p.target.revision === 0
          ? { 'If-None-Match': '*' }
          : { 'If-Match': `"${p.target.revision}"` }),
      });
      for (const [name, value] of Object.entries(options.headers ?? {})) {
        if (value === null) headers.delete(name);
        else headers.set(name, value);
      }
      return op.fetch(options.url ?? `${recordUrl()}/approved`, {
        method: options.method ?? 'POST',
        headers: Object.fromEntries(headers),
        body: options.body ?? c.candidate,
      });
    };
    const ready = async (owner: Owner, expires?: number) => {
      const p = await propose(owner, expires),
        c = await candidate(owner, p);
      await approve(owner, p);
      const response = await prepare(owner, c);
      assert.equal(response.status, 200, await response.clone().text());
      return { p, c };
    };
    const inspect = async (owner: Owner, p: Proposal, c: Candidate) => ({
      head: await head(owner),
      proposal: await env.DB.prepare(
        'SELECT state,payload FROM agent_attribute_proposal WHERE proposal_id=?',
      )
        .bind(p.proposal_id)
        .first(),
      prepared: await env.DB.prepare(
        'SELECT result_revision FROM agent_attribute_commit WHERE proposal_id=?',
      )
        .bind(p.proposal_id)
        .first(),
      mutations: (
        await env.DB.prepare(
          'SELECT count(*) n FROM vault_owner_record_mutation WHERE account_id=? AND operation_id=?',
        )
          .bind(owner.account, c.operation_id)
          .first()
      ).n,
      audits: (
        await env.DB.prepare(
          "SELECT count(*) n FROM agent_audit WHERE grant_id=? AND outcome='committed'",
        )
          .bind(p.grant_id)
          .first()
      ).n,
      guards: (
        await env.DB.prepare(
          'SELECT count(*) n FROM agent_attribute_commit_guard WHERE operation_id=?',
        )
          .bind(c.operation_id)
          .first()
      ).n,
    });
    const reopen = async (owner: Owner) => {
      const response = await get(owner);
      assert.equal(response.status, 200, await response.clone().text());
      const saved = (await response.json()) as SavedRecord;
      assert.equal(response.headers.get('etag'), `"${saved.revision}"`);
      assert.equal(response.headers.get('cache-control'), 'no-store');
      const plaintext = await openOwnerRecord(
        { format_version: 2, ciphertext: saved.ciphertext, key_envelope: saved.key_envelope },
        owner.key,
        owner.context,
        {
          collectionId: 'personal',
          recordId: 'owner_note',
          kind: 'owner_note',
          revision: saved.revision,
        },
      );
      try {
        return { saved, value: decodeOwnerNote(plaintext) };
      } finally {
        plaintext.fill(0);
      }
    };

    await t.test(
      'exact value, purpose, identity and canonical encoding must verify before preparation',
      async () => {
        const owner = await bootstrap('proof-owner'),
          other = await bootstrap('proof-other');
        const p = await propose(owner),
          c = await candidate(owner, p);
        assert.equal((await prepare(owner, c)).status, 409);
        assert.equal((await commit(owner, p, c)).status, 409);
        await approve(owner, p);
        const bad: Parameters<typeof candidate>[2][] = [
          {
            payload: new TextDecoder().decode(
              encodeOwnerNote(newOwnerNote('Altered', 'Not the approved note')),
            ),
          },
          { payload: JSON.stringify({ ...p.value, version: 2 }) },
          { proofPurpose: 'mikaki-agent-record-snapshot' },
          { proofPurpose: 'mikaki-approved-attribute-proof' },
          { proofBinding: { operation_id: id() } },
          { proofBinding: { request_hash: id() } },
          { proofBinding: { authority: { ...authority, owner_key_revision: 2 } } },
          { candidateContext: { owner: 'proof-other' } },
          { candidateContext: { collection: 'messages' } },
          { candidateContext: { revision: 2 } },
          { serialize: (value) => JSON.stringify(value) + '\n' },
          { serialize: (value) => JSON.stringify(value).replace('{', '{"format_version":2,') },
          {
            serialize: (value) => {
              const { ciphertext, ...rest } = value;
              return JSON.stringify({ ciphertext, ...rest });
            },
          },
          { serialize: (value) => JSON.stringify({ ...value, unknown: true }) },
          { serialize: (value) => JSON.stringify(value).replace('owner_note', 'owner_\\u006eote') },
          { serialize: (value) => JSON.stringify({ ...value, vault_id: 'other-vault' }) },
          { serialize: (value) => JSON.stringify({ ...value, key_generation: 2 }) },
          { serialize: (value) => JSON.stringify({ ...value, owner_key_revision: 2 }) },
          { serialize: (value) => JSON.stringify({ ...value, revision: 2 }) },
        ];
        for (const options of bad)
          assert.equal((await prepare(owner, await candidate(owner, p, options))).status, 409);
        assert.equal((await prepare(other, c)).status, 409);
        assert.equal((await ownerCall(owner, 'attribute-prepare', c)).status, 404);
        assert.equal(
          (
            await ownerCall(owner, 'attribute-decide', {
              proposal_id: p.proposal_id,
              request_hash: p.request_hash,
              approve: true,
            })
          ).status,
          404,
        );
        assert.equal(
          (
            await ownerCall(owner, 'attribute-capability', {
              grant_id: p.grant_id,
              attribute_id: 'owner_note',
              base_revision: 0,
            })
          ).status,
          404,
        );
        // A public caller cannot acquire the owner-only prepare surface.
        assert.equal(
          (
            await agent.fetch('https://agent.mikaki.test/record-prepare', {
              method: 'POST',
              headers: { Authorization: `Bearer ${p.token}`, 'Content-Type': 'application/json' },
              body: JSON.stringify(c),
            })
          ).status,
          404,
        );
        assert.equal((await inspect(owner, p, c)).prepared, null);
        await env.DB.prepare(
          "CREATE TRIGGER fail_record_prepare BEFORE INSERT ON agent_audit WHEN NEW.operation='record-prepare' BEGIN SELECT RAISE(ABORT,'prepare audit failure'); END",
        ).run();
        try {
          assert.equal((await prepare(owner, c)).status, 409);
          assert.equal((await inspect(owner, p, c)).prepared, null);
        } finally {
          await env.DB.prepare('DROP TRIGGER fail_record_prepare').run();
        }
        const prepared = await prepare(owner, c);
        assert.equal(prepared.status, 200, await prepared.clone().text());
        assert.equal((await prepare(owner, c)).status, 200);
        assert.equal((await prepare(owner, await candidate(owner, p))).status, 409);
        const status = await ownerCall(owner, 'record-status');
        assert.equal(status.status, 200);
        const content = (await status.json()) as {
          record_proposals: Array<{
            proposal_id: string;
            candidate: string | null;
            operation_id: string | null;
          }>;
        };
        const recovery = content.record_proposals.find(
          (item) => item.proposal_id === p.proposal_id,
        );
        assert.equal(recovery?.candidate, c.candidate);
        assert.equal(recovery?.operation_id, c.operation_id);
        const response = await commit(owner, p, c);
        assert.equal(response.status, 200, await response.clone().text());
        assert.deepEqual(await response.json(), { revision: 1, deleted: false });
        assert.deepEqual((await reopen(owner)).value, p.value);
        assert.equal((await inspect(owner, p, c)).proposal.payload, null);
      },
    );

    await t.test(
      'R2, audit, result and final guard failure roll back consumption/head/ledger together; identical races commit once',
      async () => {
        const owner = await bootstrap('atomic-owner');
        await write(
          owner,
          'owner_note',
          1,
          encodeOwnerNote(newOwnerNote('Original', 'Must survive every failed batch')),
        );
        const { p, c } = await ready(owner),
          before = await inspect(owner, p, c);
        await fault('throw');
        try {
          assert.equal((await commit(owner, p, c)).status, 503);
          assert.equal(
            (await env.DB.prepare('SELECT hits FROM record_commit_test_fault').first()).hits,
            1,
          );
          assert.deepEqual(await inspect(owner, p, c), before);
        } finally {
          await fault();
        }
        for (const [name, sql] of [
          ['audit', "BEFORE INSERT ON agent_audit WHEN NEW.outcome='committed'"],
          ['result', 'BEFORE UPDATE ON agent_attribute_commit'],
          ['guard', 'BEFORE INSERT ON agent_attribute_commit_guard'],
        ]) {
          await env.DB.prepare(
            `CREATE TRIGGER fail_record_${name} ${sql} BEGIN SELECT RAISE(ABORT,'injected late failure'); END`,
          ).run();
          try {
            assert.equal((await commit(owner, p, c)).status, 503, name);
            assert.deepEqual(await inspect(owner, p, c), before, name);
            assert.deepEqual(
              (await reopen(owner)).value,
              newOwnerNote('Original', 'Must survive every failed batch'),
            );
          } finally {
            await env.DB.prepare(`DROP TRIGGER fail_record_${name}`).run();
          }
        }
        const competing = await propose(owner);
        await approve(owner, competing);
        const responses = await Promise.all([commit(owner, p, c), commit(owner, p, c)]);
        for (const response of responses) {
          assert.equal(response.status, 200, await response.clone().text());
          assert.deepEqual(await response.json(), { revision: 2, deleted: false });
        }
        const after = await inspect(owner, p, c);
        assert.equal(after.proposal.state, 'committed');
        assert.equal(after.proposal.payload, null);
        assert.equal(after.prepared.result_revision, 2);
        assert.equal(after.mutations, 1);
        assert.equal(after.audits, 1);
        assert.deepEqual((await reopen(owner)).value, p.value);
        assert.equal(
          (
            await env.DB.prepare('SELECT state FROM agent_attribute_proposal WHERE proposal_id=?')
              .bind(competing.proposal_id)
              .first()
          ).state,
          'invalid',
        );
      },
    );

    await t.test(
      'proposal/body/operation/conditional identity cannot replay across headers, v1, PUT or targets',
      async () => {
        const owner = await bootstrap('identity-owner'),
          other = await bootstrap('identity-other');
        const { p, c } = await ready(owner);
        const before = await inspect(owner, p, c);
        const invalidHeaders: Array<Record<string, string | null>> = [
          { 'X-Operation-ID': id() },
          { 'X-Attribute-Proposal': id() },
          { 'X-Proposal-Hash': id() },
          { 'X-Attribute-Proposal': null },
          { 'X-Proposal-Hash': null },
          { 'X-Operation-ID': null },
          { 'If-None-Match': null },
          { 'If-None-Match': null, 'If-Match': '"1"' },
          { Cookie: other.headers.Cookie },
        ];
        for (const headers of invalidHeaders)
          assert.notEqual((await commit(owner, p, c, { headers })).status, 200);
        for (const body of [
          c.candidate + ' ',
          JSON.stringify({ ...JSON.parse(c.candidate), key_envelope: id() }),
        ])
          assert.notEqual((await commit(owner, p, c, { body })).status, 200);
        for (const url of [
          `${recordUrl('name')}/approved`,
          `${recordUrl('owner_note', 'messages')}/approved`,
          `${origin}/vault/attributes/owner_note/approved`,
        ])
          assert.notEqual((await commit(owner, p, c, { url })).status, 200);
        assert.deepEqual(await inspect(owner, p, c), before);
        assert.equal((await commit(owner, p, c)).status, 200);
        assert.equal((await commit(owner, p, c, { url: recordUrl(), method: 'PUT' })).status, 409);
        assert.equal(
          (await commit(owner, p, c, { headers: { 'X-Proposal-Hash': id() } })).status,
          409,
        );
        assert.equal(
          (await commit(owner, p, c, { headers: { 'X-Attribute-Proposal': id() } })).status,
          409,
        );
        assert.equal(
          (await commit(owner, p, c, { headers: { 'If-None-Match': null, 'If-Match': '"1"' } }))
            .status,
          400,
        );
        assert.equal((await inspect(owner, p, c)).mutations, 1);
        // An ordinary PUT with this operation does not consume the corresponding
        // approval and cannot subsequently masquerade as its approved commit.
        const ordinary = await bootstrap('ordinary-owner'),
          next = await ready(ordinary);
        assert.equal(
          (await commit(ordinary, next.p, next.c, { url: recordUrl(), method: 'PUT' })).status,
          200,
        );
        assert.equal((await commit(ordinary, next.p, next.c)).status, 409);
        const rejected = await inspect(ordinary, next.p, next.c);
        assert.equal(rejected.proposal.state, 'invalid');
        assert.equal(rejected.prepared.result_revision, null);
        assert.equal(rejected.audits, 0);
      },
    );

    await t.test(
      'v1 same-name edits cannot satisfy or invalidate v2 authority, and production candidate reopens',
      async () => {
        const owner = await bootstrap('isolated-owner');
        const legacy = await sealAttribute(
          encodeOwnerNote(newOwnerNote('Legacy note', 'Never replace this v1 note')),
          owner.prf,
          owner.credential,
          new Uint8Array(randomBytes(32)),
          origin,
          'owner_note',
          1,
        );
        // Historical rows can still exist after the HTTP API is retired. Seed
        // them in the disposable DB instead of calling the removed writer.
        const seedLegacy = async (revision: number, value: typeof legacy) => {
          const objectKey = `vault/${owner.account}/owner_note/${revision}/${id()}`;
          await env.VAULT_BLOBS.put(objectKey, Buffer.from(value.ciphertext, 'base64url'));
          await env.DB.prepare(
            `INSERT INTO vault_attribute_head
             (account_id,attribute_id,revision,format_version,object_key,ciphertext_sha256,owner_envelope,deleted,updated_at)
             VALUES(?,'owner_note',?,1,?,?,?,0,unixepoch())
             ON CONFLICT(account_id,attribute_id) DO UPDATE SET
             revision=excluded.revision,object_key=excluded.object_key,
             ciphertext_sha256=excluded.ciphertext_sha256,owner_envelope=excluded.owner_envelope,
             updated_at=excluded.updated_at`,
          )
            .bind(
              owner.account,
              revision,
              objectKey,
              hash(Buffer.from(value.ciphertext, 'base64url')),
              value.owner_envelope,
            )
            .run();
          return objectKey;
        };
        await seedLegacy(1, legacy);
        const response = await op.fetch(`${origin}/vault/attributes/owner_note`, {
          method: 'PUT',
          headers: { ...owner.headers, 'X-Operation-ID': id(), 'If-None-Match': '*' },
          body: JSON.stringify(legacy),
        });
        assert.equal(response.status, 404, await response.clone().text());
        const p = await propose(owner);
        assert.equal(p.target.revision, 0);
        await approve(owner, p);
        const { value: _value, token: _token, ...approval } = p;
        const generated = await sealApprovedOwnerRecord(
          approval,
          id(),
          recipient,
          owner.key,
          owner.context,
        );
        const c = {
          proposal_id: generated.proposal_id,
          request_hash: generated.request_hash,
          operation_id: generated.operation_id,
          candidate: generated.candidate,
          proof: generated.proof,
        };
        assert.equal((await prepare(owner, c)).status, 200);
        const changed = await sealAttribute(
          encodeOwnerNote(newOwnerNote('Legacy edit', 'Separate storage version')),
          owner.prf,
          owner.credential,
          new Uint8Array(randomBytes(32)),
          origin,
          'owner_note',
          2,
        );
        assert.equal(
          (
            await op.fetch(`${origin}/vault/attributes/owner_note`, {
              method: 'PUT',
              headers: { ...owner.headers, 'X-Operation-ID': id(), 'If-Match': '"1"' },
              body: JSON.stringify(changed),
            })
          ).status,
          404,
        );
        assert.equal(
          (
            await env.DB.prepare(
              "SELECT revision FROM vault_attribute_head WHERE account_id=? AND attribute_id='owner_note'",
            )
              .bind(owner.account)
              .first()
          ).revision,
          1,
        );
        const changedKey = await seedLegacy(2, changed);
        assert.equal((await commit(owner, p, c)).status, 200);
        assert.deepEqual((await reopen(owner)).value, p.value);
        const untouched = await op.fetch(`${origin}/vault/attributes/owner_note`, {
          headers: owner.headers,
        });
        assert.equal(untouched.status, 404);
        const legacySaved = await env.DB.prepare(
          "SELECT revision,object_key,ciphertext_sha256,owner_envelope FROM vault_attribute_head WHERE account_id=? AND attribute_id='owner_note'",
        )
          .bind(owner.account)
          .first();
        assert.equal(legacySaved.revision, 2);
        assert.equal(legacySaved.object_key, changedKey);
        assert.equal(legacySaved.owner_envelope, changed.owner_envelope);
        assert.equal(
          legacySaved.ciphertext_sha256,
          hash(Buffer.from(changed.ciphertext, 'base64url')),
        );
        assert.equal(
          base64(new Uint8Array(await (await env.VAULT_BLOBS.get(changedKey)).arrayBuffer())),
          changed.ciphertext,
        );
      },
    );

    await t.test(
      'stale target/source/owner authority and revocation across R2 await cannot partially commit',
      async () => {
        for (const scenario of [
          'source',
          'target',
          'owner-key',
          'session',
          'credential',
          'grant',
        ] as const) {
          const owner = await bootstrap(`race-${scenario}`);
          await write(
            owner,
            'owner_note',
            1,
            encodeOwnerNote(newOwnerNote('Old', 'Uncommitted candidate stays separate')),
          );
          const { p, c } = await ready(owner),
            before = await inspect(owner, p, c);
          const sql = {
            source: `UPDATE vault_owner_record_head SET ciphertext_sha256='${id()}' WHERE account_id='${owner.account}' AND record_id='name'`,
            target: `UPDATE vault_owner_record_head SET revision=revision+1 WHERE account_id='${owner.account}' AND record_id='owner_note'`,
            'owner-key': `UPDATE vault_owner_key_head SET revision=revision+1 WHERE account_id='${owner.account}'`,
            session: `UPDATE sso_session SET revoked=1 WHERE account_id='${owner.account}'`,
            credential: `UPDATE credential SET active=0 WHERE account_id='${owner.account}'`,
            grant: `UPDATE agent_grant SET revoked=1,revision=revision+1 WHERE grant_id='${p.grant_id}'`,
          }[scenario];
          await fault('after-put', sql);
          try {
            assert.equal(
              (await commit(owner, p, c)).status,
              ['owner-key', 'session', 'credential'].includes(scenario) ? 409 : 503,
              scenario,
            );
            assert.equal(
              (await env.DB.prepare('SELECT hits FROM record_commit_test_fault').first()).hits,
              1,
            );
          } finally {
            await fault();
          }
          const after = await inspect(owner, p, c);
          assert.equal(after.head.object_key, before.head.object_key, scenario);
          assert.equal(after.head.ciphertext_sha256, before.head.ciphertext_sha256, scenario);
          assert.equal(after.mutations, 0, scenario);
          assert.equal(after.audits, 0, scenario);
          assert.equal(after.prepared.result_revision, null, scenario);
          assert.notEqual(after.proposal.state, 'committed', scenario);
          assert.notEqual((await commit(owner, p, c)).status, 200, scenario);
        }
      },
    );

    await t.test(
      'real database-clock proposal expiry after R2 upload aborts the entire final batch',
      async () => {
        const owner = await bootstrap('expiry-owner');
        // Establish the grant source first, then give the actual prepared operation
        // a short deadline. The fault waits for the database clock, without editing
        // immutable timestamps or trusting a fake client time.
        await write(owner, 'name', 1, bytes('Selected v2 name'));
        const { p, c } = await ready(owner, Math.floor(Date.now() / 1000) + 8),
          before = await inspect(owner, p, c);
        await fault('after-put', '', p.expires_at);
        try {
          assert.equal((await commit(owner, p, c)).status, 503);
        } finally {
          await fault();
        }
        assert.deepEqual(await inspect(owner, p, c), before);
        assert.equal((await commit(owner, p, c)).status, 409);
      },
    );

    await t.test(
      'tombstones require their exact positive base; historical acknowledgments survive newer edits, expiry, retirement and metadata cleanup',
      async () => {
        const owner = await bootstrap('history-owner');
        await write(
          owner,
          'owner_note',
          1,
          encodeOwnerNote(newOwnerNote('Delete', 'Tombstone next')),
        );
        const deleted = await op.fetch(recordUrl(), {
          method: 'DELETE',
          headers: { ...owner.headers, 'X-Operation-ID': id(), 'If-Match': '"1"' },
          body: JSON.stringify({
            format_version: 2,
            vault_id: 'vault',
            ...authority,
            kind: 'owner_note',
            revision: 2,
          }),
        });
        assert.equal(deleted.status, 200, await deleted.clone().text());
        const { p, c } = await ready(owner);
        assert.deepEqual(
          [p.target.revision, p.target.deleted, p.target.ciphertext_sha256],
          [2, true, null],
        );
        assert.notEqual(
          (await commit(owner, p, c, { headers: { 'If-Match': null, 'If-None-Match': '*' } }))
            .status,
          200,
        );
        const committed = await commit(owner, p, c);
        assert.equal(committed.status, 200, await committed.clone().text());
        const receipt = await committed.json();
        assert.deepEqual(receipt, { revision: 3, deleted: false });
        assert.deepEqual((await reopen(owner)).value, p.value);
        const later = newOwnerNote(
          'Newer owner edit',
          'A historical retry must not reapply the proposal',
        );
        await write(owner, 'owner_note', 4, encodeOwnerNote(later));
        await write(owner, 'name', 2, bytes('New source invalidates old grants'));
        await env.DB.prepare(
          'UPDATE agent_grant SET created_at=unixepoch()-120,expires_at=unixepoch()-1 WHERE grant_id=?',
        )
          .bind(p.grant_id)
          .run();
        assert.deepEqual(await (await commit(owner, p, c)).json(), receipt);
        // Recipient retirement is terminal, so exercise it last. A separate still-
        // prepared operation is denied while the committed operation is acknowledged.
        const retiredOwner = await bootstrap('retired-owner'),
          retired = await ready(retiredOwner);
        await env.DB.prepare("UPDATE agent_recipient_key SET state='disabled' WHERE key_id=?")
          .bind(keyId)
          .run();
        assert.equal((await commit(retiredOwner, retired.p, retired.c)).status, 409);
        assert.equal((await inspect(retiredOwner, retired.p, retired.c)).mutations, 0);
        const retiredRetry = await commit(owner, p, c);
        assert.equal(retiredRetry.status, 200);
        assert.deepEqual(await retiredRetry.json(), receipt);
        await env.DB.prepare('DELETE FROM agent_attribute_proposal WHERE proposal_id=?')
          .bind(p.proposal_id)
          .run();
        assert.equal((await inspect(owner, p, c)).prepared, null);
        const cleanedRetry = await commit(owner, p, c);
        assert.equal(cleanedRetry.status, 200);
        assert.deepEqual(await cleanedRetry.json(), receipt);
        assert.deepEqual((await reopen(owner)).value, later);
        // Live same-owner authentication is enough for a retained exact receipt;
        // removed wrapping access cannot turn a historical ACK into a new write.
        await env.DB.prepare('DELETE FROM vault_owner_key_wrap WHERE account_id=?')
          .bind(owner.account)
          .run();
        const withoutWrap = await commit(owner, p, c);
        assert.equal(withoutWrap.status, 200);
        assert.deepEqual(await withoutWrap.json(), receipt);
        assert.equal((await head(owner)).revision, 4);
        assert.equal((await inspect(owner, p, c)).mutations, 1);
        assert.equal(
          (await commit(owner, p, c, { headers: { 'X-Proposal-Hash': id() } })).status,
          409,
        );
        await env.DB.prepare('UPDATE sso_session SET revoked=1 WHERE account_id=?')
          .bind(owner.account)
          .run();
        assert.equal((await commit(owner, p, c)).status, 401);
      },
    );
  } finally {
    await harness.close();
    await rm(directory, { recursive: true, force: true });
  }
});
