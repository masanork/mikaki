/** The OP owns D1. Named entrypoints are reachable only through service bindings. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { z } from 'zod';
import op from '../build/worker/shim.mjs';
import { agentQueries } from './agent-catalog';
import activeRelease from '../../userinfo-claim-worker/src/active_name_release.sql';
import auditRelease from '../../userinfo-claim-worker/src/audit_name_release.sql';
import activeRecord from '../../userinfo-claim-worker/src/active_name_record_release.sql';
import auditRecord from '../../userinfo-claim-worker/src/audit_name_record_release.sql';

const batchInput = z.strictObject({
  statements: z
    .array(
      z.strictObject({
        id: z.string().regex(/^[a-f0-9]{64}$/),
        values: z.array(z.union([z.string().max(65536), z.number().finite(), z.null()])).max(64),
      }),
    )
    .min(1)
    .max(64),
});
async function body(request: Request, max = 65536) {
  if (!request.body) throw new Error('Missing body');
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > max) {
        await reader.cancel();
        throw new Error('Too large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return JSON.parse(
    new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes),
  ) as unknown;
}
function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}
export class AgentStore extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    try {
      if (request.method !== 'POST' || new URL(request.url).pathname !== '/statements')
        return json({ error: 'not_found' }, 404);
      const input = batchInput.parse(await body(request));
      const session = this.env.DB.withSession('first-primary');
      const statements = input.statements.map(({ id, values }) => {
        const sql = agentQueries[id];
        if (!sql) throw new Error('Unknown capability');
        return session.prepare(sql).bind(...values);
      });
      return json(await session.batch(statements));
    } catch (error) {
      console.error(JSON.stringify({ event: 'service_store_failure' }));
      return json({ error: 'store_unavailable_or_denied' }, 503);
    }
  }
}
const keyQuery =
  'SELECT key_id,service_id,algorithm,public_key,secret_ref,state,generation FROM vault_recipient_key WHERE key_id=?1';
const releaseQuery = `SELECT v.account_id,ac.client_id,h.revision,r.version AS release_version,
 h.object_key,h.ciphertext_sha256,e.frame,k.key_id,k.public_key,k.secret_ref,k.generation,
 1 AS storage_version,'' AS source_origin,'' AS vault_id,'' AS collection_id,'' AS record_id,'' AS kind,
 0 AS key_generation,0 AS owner_key_revision,g.version AS system_grant_version,e.envelope_id ${activeRelease}
 UNION ALL SELECT v.account_id,ac.client_id,h.revision,r.version AS release_version,
 h.object_key,h.ciphertext_sha256,e.frame,k.key_id,k.public_key,k.secret_ref,k.generation,
 2 AS storage_version,g.origin AS source_origin,g.vault_id,g.collection_id,g.record_id,g.kind,
 g.key_generation,g.owner_key_revision,g.version AS system_grant_version,e.envelope_id ${activeRecord}`;
const opaque = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export class ClaimStore extends WorkerEntrypoint<Env> {
  async fetch(request: Request): Promise<Response> {
    try {
      if (request.method !== 'POST') return json({ error: 'not_found' }, 404);
      const path = new URL(request.url).pathname;
      const db = this.env.DB.withSession('first-primary');
      const input = await body(request, 4096);
      if (path === '/ready') {
        z.strictObject({}).parse(input);
        await db.prepare('SELECT key_id FROM vault_recipient_key LIMIT 1').first();
        return json({ ready: true });
      }
      if (path === '/key') {
        const value = z.strictObject({ key_id: opaque, active: z.boolean() }).parse(input);
        const key = await db
          .prepare(keyQuery + (value.active ? " AND state='active'" : ''))
          .bind(value.key_id)
          .first();
        return json(key);
      }
      if (path === '/release') {
        const { access_hash } = z.strictObject({ access_hash: opaque }).parse(input);
        const row = await db
          .prepare(releaseQuery)
          .bind(access_hash)
          .first<Record<string, unknown>>();
        if (!row) return json(null);
        if (typeof row.object_key !== 'string') throw new Error('Invalid head');
        const object = await this.env.VAULT_BLOBS.get(row.object_key);
        if (!object || object.size > 24576) throw new Error('Blob unavailable');
        return json({ ...row, ciphertext: Array.from(new Uint8Array(await object.arrayBuffer())) });
      }
      if (path === '/audit') {
        const value = z
          .strictObject({
            access_hash: opaque,
            storage_version: z.union([z.literal(1), z.literal(2)]),
            source_origin: z.string().max(256),
            vault_id: z.string().max(128),
            collection_id: z.string().max(128),
            record_id: z.string().max(128),
            kind: z.string().max(128),
            envelope_id: opaque,
            key_generation: z.number().int().nonnegative(),
            owner_key_revision: z.number().int().nonnegative(),
            system_grant_version: z.number().int().positive(),
            generation: z.number().int().positive(),
            account_id: z.string().min(1).max(128),
            client_id: z.string().min(1).max(128),
            revision: z.number().int().positive(),
            release_version: z.number().int().positive(),
            ciphertext_sha256: opaque,
            key_id: opaque,
          })
          .parse(input);
        const params: (string | number)[] = [
          value.access_hash,
          value.account_id,
          value.client_id,
          value.revision,
          value.release_version,
          value.ciphertext_sha256,
          value.key_id,
        ];
        if (value.storage_version === 2)
          params.push(
            value.source_origin,
            value.vault_id,
            value.collection_id,
            value.record_id,
            value.kind,
            value.key_generation,
            value.owner_key_revision,
            value.system_grant_version,
            value.generation,
            value.envelope_id,
          );
        const accepted = await db
          .prepare(
            (value.storage_version === 1 ? auditRelease : auditRecord).replace(
              '{ACTIVE_NAME_RELEASE}',
              value.storage_version === 1 ? activeRelease : activeRecord,
            ),
          )
          .bind(...params)
          .first('id');
        return json({ accepted: accepted !== null });
      }
      return json({ error: 'not_found' }, 404);
    } catch (error) {
      console.error(JSON.stringify({ event: 'service_store_failure' }));
      return json({ error: 'store_unavailable_or_denied' }, 503);
    }
  }
}
export default op;
