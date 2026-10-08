/** Native D1/R2 qualification only: synthetic SSO/source/receipt facts, no provider/launcher bindings. */
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import { activateWorkerPolicy } from '../../../scripts/worker-policy-store.ts';
import type { GitDisclosure } from '../../../scripts/work-git-disclosure.ts';
import { schemaSql } from './work-schema.ts';

export async function workStoreFixture(directory: string, bindings: Record<string, string> = {}) {
  const root = new URL('../../..', import.meta.url).pathname;
  const modulesRoot = join(root, 'local/generated/work-store-main');
  const scripts = (await readdir(modulesRoot, { recursive: true })).filter((name) =>
    name.endsWith('.js'),
  );
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          name: 'work-store-owner',
          modulesRoot,
          modules: [
            { type: 'ESModule', path: join(modulesRoot, 'worker.mjs') },
            ...scripts.map((name) => ({
              type: 'ESModule' as const,
              path: join(modulesRoot, name),
            })),
            { type: 'CompiledWasm', path: join(modulesRoot, 'qualification_bg.wasm') },
          ],
          compatibilityDate: '2026-10-03',
          bindings: { ...bindings, LOCAL_WORK_QUALIFICATION: 'true' },
          d1Databases: { DB: 'work-store-qualification' },
          r2Buckets: { WORK_GIT_PAYLOADS: 'private-work-candidate-payloads' },
        },
      ],
      resourcePersistencePath: join(directory, 'op-state'),
      host: '127.0.0.1',
      port: 0,
    }),
  );
  let DB: Awaited<ReturnType<Miniflare['getD1Database']>>;
  try {
    DB = await mf.getD1Database('DB');
  } catch (error) {
    await mf.dispose();
    throw error;
  }
  const account = 'synthetic-delivery-owner',
    session = createHash('sha256').update('synthetic-delivery-session').digest('base64url');
  async function call(values: Record<string, unknown>, status = 200) {
    const response = await mf.dispatchFetch('https://work.test/fixture', {
      method: 'POST',
      body: JSON.stringify({ session, ...values }),
    });
    if (response.status !== status) throw new Error(`fixture_status_${response.status}`);
    return response.json() as Promise<{
      id: string;
      digest: string;
      state: string;
      body: string;
      revision?: number;
      revoked?: boolean;
      actor_expires_at?: number;
      started?: boolean;
      repo_id?: string;
      token_id?: string;
      attempts?: { id: string; state: string; revision: number }[];
      bytes?: string;
      payloads?: unknown[];
      preparation?: { id: string; digest: string; state: string; body: string };
    }>;
  }
  async function initialize(input: GitDisclosure, throughMigration?: string) {
    await DB.batch(splitSqlQuery(await schemaSql(throughMigration)).map((s) => DB.prepare(s)));
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'delivery-probe', reason: 'synthetic local qualification' },
    );
    const now = Math.floor(Date.now() / 1000);
    await DB.batch([
      DB.prepare('INSERT INTO account_security VALUES(?,0,1)').bind(account),
      DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind('delivery-credential', account),
      DB.prepare('INSERT INTO sso_session VALUES(?,?,?,0,?,0)').bind(
        'delivery-sso',
        account,
        'delivery-credential',
        now + 3600,
      ),
      DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind('delivery-sso', session, now),
    ]);
    const code = {
      source_id: input.code.repository,
      source_revision: 1,
      role: 'code',
      label: 'Synthetic code',
      repo_name: 'synthetic-code-source',
      commit: input.code.commit,
      tree: input.code.tree,
      files: [],
      code: {
        commits: input.code.commits.length,
        history_digest: createHash('sha256')
          .update(input.code.commits.join('\n') + '\n')
          .digest('hex'),
        objects: input.code.objects,
        object_bytes: input.code.object_bytes,
        head_files: input.code.head_files,
      },
    };
    const sources = [
      code,
      ...input.contexts.map((c, i) => ({
        source_id: c.repository,
        source_revision: 1,
        role: 'personal',
        label: 'Synthetic context',
        repo_name: `synthetic-context-source-${i}`,
        commit: c.commit,
        tree: c.tree,
        code: null,
        files: c.files.map((f) => ({
          path: f.path,
          blob: f.blob,
          mode: f.mode,
          bytes: Buffer.byteLength(f.content),
          sha256: createHash('sha256').update(f.content).digest('hex'),
        })),
      })),
    ];
    for (const source of sources) {
      const saved = await call({ action: 'source-body', source });
      await DB.batch([
        DB.prepare('INSERT INTO work_source_version VALUES(?,?,?)').bind(
          source.source_id,
          1,
          saved.body,
        ),
        DB.prepare('INSERT INTO work_source_head VALUES(?,?,1)').bind(source.source_id, 1),
        DB.prepare('INSERT INTO work_source_access VALUES(?,?,0,1,1)').bind(
          account,
          source.source_id,
        ),
      ]);
    }
    const d = await call({ action: 'disclosure', disclosure: input, expires_at: now + 3600 });
    return call({
      action: 'reserve-preparation',
      digest: d.digest,
      task_repository: 'synthetic-task',
      task_namespace: 'mikaki-dev',
      snapshot_namespace: 'mikaki-dev',
    });
  }
  async function ownerPreparation(id: string) {
    const response = await mf.dispatchFetch('https://work.test/fixture', {
      method: 'POST',
      body: JSON.stringify({ action: 'owner-preparation', session, id }),
    });
    return { status: response.status, body: (await response.json()) as Record<string, unknown> };
  }
  return {
    DB,
    bucket: await mf.getR2Bucket('WORK_GIT_PAYLOADS'),
    call,
    initialize,
    ownerPreparation,
    account,
    session,
    close: () => mf.dispose(),
  };
}
