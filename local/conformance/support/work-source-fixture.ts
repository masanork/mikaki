import { applyWorkMigrations } from './work-migrations.ts';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTestHarness } from 'wrangler';
import { gitFixture } from '../../../scripts/work-git-fixture.ts';
import { localGit, prepareGitDisclosure } from '../../../scripts/work-git-disclosure.ts';
import { activateWorkerPolicy } from '../../../scripts/worker-policy-store.ts';

export async function createSourceFixture(
  options?: {
    artifacts: { accountId: string; namespace: string };
  },
  preparationReview = false,
  entry: 'qualification' | 'product' | 'product-unenrolled' = 'qualification',
  copyConsent = false,
  ownerSessionSeconds = 3600,
  compose = false,
  operatorBindings: Record<string, string> = {},
) {
  const product = entry !== 'qualification';
  const enrolled = entry === 'product';
  const root = new URL('../../..', import.meta.url).pathname;
  const parent = await mkdtemp(join(tmpdir(), 'mikaki-source-review-'));
  const contents = {
    'preferences/writing.md': '結論から書く。\n',
    'decisions/long.md':
      '<script>globalThis.sourceInjected = true</script>\n' + '長い文脈の確認。'.repeat(250) + '\n',
    'unselected.md': 'SYNTHETIC_UNSELECTED\n',
  };
  const git = await gitFixture(parent, 'personal', contents, 'SYNTHETIC_HISTORICAL_ONLY\n');
  const codeGit = await gitFixture(
    parent,
    'code',
    {
      'README.md': 'Synthetic code\n',
      'src/main.rs': 'fn main() {}\n',
      'docs/guide.md': 'Synthetic guide\n',
    },
    'SYNTHETIC_CODE_HISTORY\n',
  );
  const disclosure = (
    await prepareGitDisclosure(
      { repository: 'code', gitDir: codeGit.dir, commit: codeGit.commit },
      [
        {
          repository: 'personal',
          gitDir: git.dir,
          commit: git.commit,
          paths: ['preferences/writing.md'],
        },
      ],
      parent,
      'unused-snapshot',
    )
  ).input;
  const verified = disclosure.code;
  const code = {
    commits: verified.commits.length,
    history_digest: createHash('sha256')
      .update(verified.commits.join('\n') + '\n')
      .digest('hex'),
    objects: verified.objects,
    object_bytes: verified.object_bytes,
    head_files: verified.head_files,
  };
  const paths = Object.keys(contents).sort((a, b) =>
    Buffer.compare(Buffer.from(a), Buffer.from(b)),
  );
  const files = paths.map((path) => ({
    path,
    blob: git.blobs.get(path)!,
    mode: '100644',
    bytes: Buffer.byteLength(contents[path as keyof typeof contents]),
    sha256: createHash('sha256')
      .update(contents[path as keyof typeof contents])
      .digest('hex'),
  }));
  const blobs = Object.fromEntries(
    files.map((f) => [f.blob, localGit(git.dir, ['cat-file', 'blob', f.blob]).toString()]),
  );
  const checkpointServices = enrolled
    ? [
        {
          binding: 'WORK_AUTHORITY_CHECKPOINT',
          service: 'source-checkpoint',
          entrypoint: 'WorkCheckpointService',
        },
      ]
    : [];
  const config = {
    name: 'source-owner',
    main: product
      ? `${root}/crates/worker/service/entrypoint.ts`
      : `${root}/local/generated/work-store-main/worker.mjs`,
    compatibility_date: '2026-10-06',
    vars: {
      LOCAL_WORK_QUALIFICATION: 'true',
      WORK_OWNER_API_ENABLED: 'true',
      WORK_SOURCE_API_ENABLED: 'true',
      ...(preparationReview ? { WORK_PREPARATION_REVIEW_ENABLED: 'true' } : {}),
      ...(copyConsent
        ? {
            WORK_COPY_CONSENT_ENABLED: 'true',
            WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
            WORK_EFFECT_STORE_ENABLED: 'true',
            WORK_MINT_STORE_ENABLED: 'true',
            WORK_GIT_STORE_ENABLED: 'true',
            WORK_CREDENTIAL_KEY_FLOOR: '1',
            WORK_CREDENTIAL_KEY_V1: Buffer.alloc(32, 1).toString('base64url'),
          }
        : {}),
      ...(compose
        ? {
            WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
            WORK_PREPARATION_COMPOSE_ENABLED: 'true',
            WORK_ARTIFACTS_NAMESPACE: 'mikaki-dev',
            WORK_COPY_RECIPIENT: 'synthetic-client',
            WORK_COPY_WORKLOAD: 'synthetic-workload',
          }
        : {}),
      ...operatorBindings,
    },
    services: [
      ...checkpointServices,
      {
        binding: 'WORK_SOURCE_READER',
        service: 'source-reader',
        entrypoint: options ? 'WorkSourceReader' : 'FixtureSourceReader',
      },
    ],
    d1_databases: [
      {
        binding: 'DB',
        database_name: 'work-source',
        database_id: '00000000-0000-0000-0000-000000000050',
        migrations_dir: `${root}/crates/worker/migrations`,
      },
    ],
  };
  const harness = createTestHarness({
    root,
    workers: [
      { config },
      { config: { ...config, name: 'source-owner-b' } },
      ...(copyConsent
        ? [
            {
              config: {
                ...config,
                name: 'source-other-account',
                vars: { ...config.vars, WORK_ARTIFACTS_ACCOUNT: 'b'.repeat(32) },
              },
            },
          ]
        : []),
      ...(product
        ? [
            {
              config: {
                ...config,
                name: 'source-fixture',
                main: `${root}/local/generated/work-store-main/worker.mjs`,
                services: [
                  ...config.services,
                  {
                    binding: 'CHECKPOINT_ADMIN',
                    service: 'source-checkpoint',
                    entrypoint: 'WorkCheckpointAdmin',
                  },
                  {
                    binding: 'OP_AUTHORITY_ADMIN',
                    service: 'source-owner',
                    entrypoint: 'OpAuthorityAdmin',
                  },
                  ...(copyConsent
                    ? ['WorkEffectStore', 'WorkMintStore', 'WorkGitStore'].map((entrypoint, i) => ({
                        binding: ['OP_EFFECT_STORE', 'OP_MINT_STORE', 'OP_GIT_STORE'][i]!,
                        service: 'source-owner',
                        entrypoint,
                      }))
                    : []),
                ],
              },
            },
            {
              config: {
                ...config,
                name: 'source-unenrolled',
                services: config.services.filter((s) => s.binding !== 'WORK_AUTHORITY_CHECKPOINT'),
              },
            },
            {
              config: {
                name: 'source-checkpoint',
                main: `${root}/crates/work-checkpoint-worker/worker.ts`,
                compatibility_date: '2026-10-08',
                vars: { WORK_AUTHORITY_ID: 'synthetic-source-review' },
                durable_objects: {
                  bindings: [{ name: 'CHECKPOINTS', class_name: 'WorkCheckpoint' }],
                },
                migrations: [{ tag: 'source-test-v1', new_sqlite_classes: ['WorkCheckpoint'] }],
              },
            },
          ]
        : []),
      {
        config: {
          ...config,
          name: 'source-disabled',
          vars: { LOCAL_WORK_QUALIFICATION: 'true', WORK_OWNER_API_ENABLED: 'true' },
        },
      },
      {
        config: options
          ? {
              name: 'source-reader',
              main: `${root}/crates/work-source-worker/src/worker.ts`,
              compatibility_date: '2026-10-06',
              account_id: options.artifacts.accountId,
              workers_dev: false,
              preview_urls: false,
              vars: { WORK_SOURCE_READER_ENABLED: 'true' },
              artifacts: [
                { binding: 'ARTIFACTS', namespace: options.artifacts.namespace, remote: true },
              ],
            }
          : {
              name: 'source-reader',
              main: `${root}/local/conformance/support/work-source-reader.ts`,
              compatibility_date: '2026-10-06',
              vars: {
                GIT_FIXTURE: JSON.stringify({
                  'personal-repo': {
                    commit: git.commit,
                    tree: git.tree,
                    blobs,
                    paths: Object.fromEntries(git.blobs),
                  },
                }),
              },
              d1_databases: config.d1_databases,
              services: checkpointServices,
            },
      },
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('source-owner');
    // Fixture mutation glue is a separate Worker; it is never served by the
    // product entry, even with LOCAL_WORK_QUALIFICATION in the product Env.
    const fixture = product ? harness.getWorker('source-fixture') : worker;
    await worker.applyD1Migrations('DB');
    const { DB } = await worker.getEnv();
    await applyWorkMigrations(DB, compose ? 14 : copyConsent ? 13 : 12);
    await activateWorkerPolicy(
      DB,
      JSON.parse(
        await readFile(new URL('../../generated/worker-policy.json', import.meta.url), 'utf8'),
      ),
      { actor: 'source-test', reason: 'local qualification' },
    );
    await DB.prepare(
      'CREATE TABLE source_reader_fault(source_id TEXT PRIMARY KEY,mode TEXT,owner_id TEXT)',
    ).run();
    await DB.prepare('CREATE TABLE source_reader_calls(source_id TEXT,request TEXT)').run();
    async function checkpoint(input: Record<string, unknown>) {
      return fixture.fetch('https://work.test/checkpoint-fixture', {
        method: 'POST',
        body: JSON.stringify(input),
      });
    }
    async function owner(account: string) {
      const cookie = `synthetic-source-cookie:${account}`,
        hash = createHash('sha256').update(cookie).digest('base64url'),
        now = Math.floor(Date.now() / 1000);
      await DB.batch([
        DB.prepare('INSERT INTO account_security VALUES(?,0,1)').bind(account),
        DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(`credential:${account}`, account),
        DB.prepare('INSERT INTO sso_session VALUES(?,?,?,0,?,0)').bind(
          `sso:${account}`,
          account,
          `credential:${account}`,
          now + ownerSessionSeconds,
        ),
        DB.prepare('INSERT INTO sso_context VALUES(?,?,?)').bind(`sso:${account}`, hash, now),
      ]);
      return { account, cookie, hash };
    }
    async function register(
      source_id: string,
      o: Awaited<ReturnType<typeof owner>>,
      patch: Record<string, unknown> = {},
    ) {
      const source = {
        source_id,
        source_revision: 1,
        role: 'personal',
        label: '個人context / Personal context',
        repo_name: 'personal-repo',
        commit: git.commit,
        tree: git.tree,
        files,
        code: null,
        ...patch,
      };
      const response = await fixture.fetch('https://work.test/fixture', {
        method: 'POST',
        body: JSON.stringify({ action: 'source-body', source }),
      });
      if (!response.ok) throw new Error(await response.text());
      const { body } = (await response.json()) as { body: string };
      await DB.batch([
        DB.prepare('INSERT INTO work_source_version VALUES(?,?,?)').bind(
          source_id,
          source.source_revision,
          body,
        ),
        DB.prepare('INSERT INTO work_source_head VALUES(?,?,1)').bind(
          source_id,
          source.source_revision,
        ),
        DB.prepare('INSERT INTO work_source_access VALUES(?,?,0,1,1)').bind(o.account, source_id),
      ]);
      return { ...source, access_revision: 1 };
    }
    const first = await owner('source-owner-a'),
      foreign = await owner('source-owner-foreign');
    const source = await register('personal', first);
    // Synthetic initial SSO is seeded before enrollment. Thereafter covered OP
    // mutations, including session revocation, must use Native framing.
    if (enrolled) {
      const initial = {
        authority: 'synthetic-source-review',
        epoch: 'a'.repeat(64),
        sequence: 0,
        tip: 'b'.repeat(64),
      };
      const r = await checkpoint({ action: 'bootstrap', checkpoint: initial, floor: 1 });
      if (!r.ok) throw new Error('source_checkpoint_bootstrap_failed');
      await DB.prepare('INSERT INTO work_authority_checkpoint VALUES(1,?,?,?,?)')
        .bind(initial.authority, initial.epoch, initial.sequence, initial.tip)
        .run();
    }
    async function revokeSession(o = first) {
      if (!product) throw new Error('product_session_revocation_required');
      const r = await fixture.fetch('https://work.test/authority-fixture', {
        method: 'POST',
        body: JSON.stringify({
          action: 'revoke-session',
          session: `sso:${o.account}`,
          account: o.account,
          expected_epoch: 0,
          actor: 'source-product-fixture',
          reason: 'local SSO revocation qualification',
        }),
      });
      if (!r.ok) throw new Error('source_session_revocation_failed');
    }
    const input = (id = 'personal', paths = ['preferences/writing.md']) => ({
      format_version: 1,
      source_id: id,
      source_revision: 1,
      access_revision: 1,
      paths,
    });
    async function fault(id: string, mode: string, account = first.account) {
      await DB.prepare(
        'INSERT INTO source_reader_fault VALUES(?,?,?) ON CONFLICT(source_id) DO UPDATE SET mode=excluded.mode,owner_id=excluded.owner_id',
      )
        .bind(id, mode, account)
        .run();
    }
    async function http(
      path: string,
      o = first,
      options: { method?: string; headers?: HeadersInit; body?: string } = {},
      target = worker,
    ) {
      const headers = new Headers(options.headers);
      headers.set('Cookie', `__Host-op-sso=${o.cookie}`);
      if (options.method === 'POST') {
        if (!headers.has('Origin')) headers.set('Origin', 'https://work.test');
        if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
      }
      return target.fetch(`https://work.test${path}`, {
        ...options,
        headers: Object.fromEntries(headers.entries()),
      });
    }
    const close = async () => {
      await harness.close();
      await rm(parent, { recursive: true, force: true });
    };
    return {
      harness,
      worker,
      fixture,
      ...(copyConsent ? { otherAccount: harness.getWorker('source-other-account') } : {}),
      checkpoint,
      revokeSession,
      ...(product ? { unenrolled: harness.getWorker('source-unenrolled') } : {}),
      b: harness.getWorker('source-owner-b'),
      disabled: harness.getWorker('source-disabled'),
      DB,
      owner,
      register,
      first,
      foreign,
      source,
      input,
      fault,
      http,
      files,
      contents,
      codeSource: { repo_name: 'code-repo', commit: verified.commit, tree: verified.tree, code },
      disclosure,
      close,
    };
  } catch (error) {
    await harness.close();
    await rm(parent, { recursive: true, force: true });
    throw error;
  }
}
