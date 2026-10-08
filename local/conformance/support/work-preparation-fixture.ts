import { applyWorkMigrations } from './work-migrations.ts';
/** Persistent local OP qualification: actual Rust/Wasm, synthetic SSO/sources. */
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { Request as MiniflareRequest, Response as MiniflareResponse } from 'miniflare';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import type { V4WorkerOptions } from 'miniflare';
import type { Artifacts } from '@cloudflare/workers-types';
import { activateWorkerPolicy } from '../../../scripts/worker-policy-store.ts';
import type { GitDisclosure } from '../../../scripts/work-git-disclosure.ts';
export type FixtureRequestOptions = {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
};

export async function preparationFixture(
  directory: string,
  bindings: Record<string, string> = {},
  checkpointEnabled = false,
  effectEnabled = false,
  remote?: {
    accountId: string;
    bindings: Pick<V4WorkerOptions, 'artifacts'>;
    loseCreate?: boolean;
  },
  gitExecutor?: (request: Request) => Promise<Response>,
) {
  const root = new URL('../../..', import.meta.url).pathname;
  const modulesRoot = join(root, 'local/generated/work-store-main');
  const scripts = (await readdir(modulesRoot, { recursive: true })).filter((name) =>
    name.endsWith('.js'),
  );
  const ownerWorker = {
    name: 'preparation-owner',
    modulesRoot,
    modules: [
      { type: 'ESModule' as const, path: join(modulesRoot, 'worker.mjs') },
      { type: 'ESModule' as const, path: join(modulesRoot, 'authority-admin-facade.mjs') },
      ...scripts.map((name) => ({ type: 'ESModule' as const, path: join(modulesRoot, name) })),
      { type: 'CompiledWasm' as const, path: join(modulesRoot, 'qualification_bg.wasm') },
    ],
    compatibilityDate: '2026-09-30',
    bindings: {
      MIKAKI_ISSUER: 'https://work.test',
      ...(effectEnabled && !remote ? { WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32) } : {}),
      ...(effectEnabled && !remote ? { WORK_GIT_EXECUTION_ENABLED: 'true' } : {}),
      ...(effectEnabled && !remote ? { WORK_PREPARATION_VERIFY_ENABLED: 'true' } : {}),
      ...bindings,
      LOCAL_WORK_QUALIFICATION: 'true',
      WORK_OWNER_API_ENABLED: 'true',
    },
    d1Databases: { DB: 'preparation-probe' },
    r2Buckets: { WORK_GIT_PAYLOADS: 'private-work-candidate-payloads' },
  };
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      workers: [
        {
          ...ownerWorker,
          serviceBindings: {
            OP_PUBLIC: 'preparation-owner',
            OP_AUTHORITY_ADMIN: { name: 'preparation-owner', entrypoint: 'OpAuthorityAdmin' },
            ...(effectEnabled
              ? {
                  OP_EFFECT_STORE: { name: 'preparation-owner', entrypoint: 'WorkEffectStore' },
                  EFFECT_GATE: { name: 'work-effect', entrypoint: 'WorkEffectGate' },
                  EFFECT_PUBLIC: 'work-effect',
                  ...(!remote
                    ? {
                        MINT_GATE: { name: 'work-mint', entrypoint: 'WorkMintGate' },
                        GIT_GATE: { name: 'work-git', entrypoint: 'WorkGitGate' },
                        GIT_PUBLIC: 'work-git',
                        PREPARATION_GATE: {
                          name: 'work-preparation',
                          entrypoint: 'WorkPreparationGate',
                        },
                        PREPARATION_PUBLIC: 'work-preparation',
                        WORK_PREPARATION_EVIDENCE: {
                          name: 'preparation-owner',
                          entrypoint: 'FixturePreparationEvidence',
                        },
                        PREPARATION_EVIDENCE: {
                          name: 'work-checkpoint',
                          entrypoint: 'WorkPreparationEvidence',
                        },
                        GIT_CHECKPOINT: {
                          name: 'work-checkpoint',
                          entrypoint: 'WorkGitCheckpoint',
                        },
                        WORK_GIT_EXECUTION_CHECKPOINT: {
                          name: 'preparation-owner',
                          entrypoint: 'FixtureGitExecutionCheckpoint',
                        },
                        GIT_LEDGER: { name: 'work-checkpoint', entrypoint: 'WorkGitCheckpoint' },
                        GIT_EXECUTION_CHECKPOINT: {
                          name: 'work-checkpoint',
                          entrypoint: 'WorkGitExecutionCheckpoint',
                        },
                        WORK_GIT_TRANSPORT: {
                          name: 'work-git-transport',
                          entrypoint: 'WorkGitTransport',
                        },
                        MINT_PUBLIC: 'work-mint',
                        MINT_LEDGER: { name: 'work-checkpoint', entrypoint: 'WorkMintCheckpoint' },
                        MINT_LOOKUP: { name: 'work-checkpoint', entrypoint: 'WorkMintLookup' },
                        MINT_MAINTENANCE: {
                          name: 'work-checkpoint',
                          entrypoint: 'WorkMintMaintenance',
                        },
                        MINT_RECONCILER: {
                          name: 'mint-reconcile',
                          entrypoint: 'WorkMintReconciler',
                        },
                        MINT_RECONCILE_PUBLIC: 'mint-reconcile',
                        MINT_ARTIFACTS_MAINTENANCE: {
                          name: 'mint-maintenance',
                          entrypoint: 'WorkMintArtifactsMaintenance',
                        },
                        MINT_MAINTENANCE_PUBLIC: 'mint-maintenance',
                        MINT_CLOSER: { name: 'mint-closure', entrypoint: 'WorkMintCloser' },
                        MINT_CLOSURE_PUBLIC: 'mint-closure',
                        MINT_REFUSAL_CHECKPOINT: {
                          name: 'work-checkpoint',
                          entrypoint: 'WorkMintRefusalCheckpoint',
                        },
                        WORK_MINT_REFUSAL_TRANSPORT: {
                          name: 'mint-refusal-transport',
                          entrypoint: 'WorkMintRefusalTransport',
                        },
                        MINT_REFUSAL_TRANSPORT_PUBLIC: 'mint-refusal-transport',
                      }
                    : {}),
                  EFFECT_RECONCILER: { name: 'work-reconcile', entrypoint: 'WorkEffectReconciler' },
                  RECONCILE_PUBLIC: 'work-reconcile',
                  ARTIFACTS_MAINTENANCE: {
                    name: 'artifacts-maintenance',
                    entrypoint: 'WorkArtifactsMaintenance',
                  },
                  ARTIFACTS_MAINTENANCE_PUBLIC: 'artifacts-maintenance',
                  EFFECT_LOOKUP: { name: 'work-checkpoint', entrypoint: 'WorkEffectLookup' },
                  EFFECT_MAINTENANCE: {
                    name: 'work-checkpoint',
                    entrypoint: 'WorkEffectMaintenance',
                  },
                  EFFECT_LEDGER: { name: 'work-checkpoint', entrypoint: 'WorkEffectCheckpoint' },
                  ARTIFACTS_FIXTURE: 'synthetic-artifacts',
                }
              : {}),
            ...(checkpointEnabled
              ? {
                  WORK_AUTHORITY_CHECKPOINT: {
                    name: 'work-checkpoint',
                    entrypoint: 'WorkCheckpointService',
                  },
                  CHECKPOINT_ADMIN: { name: 'work-checkpoint', entrypoint: 'WorkCheckpointAdmin' },
                  CHECKPOINT_PUBLIC: 'work-checkpoint',
                  ...(bindings.LOCAL_CHECKPOINT_SOURCE_REPLY
                    ? {
                        WORK_SOURCE_READER: {
                          name: 'preparation-owner',
                          entrypoint: 'FixtureCheckpointSourceReader',
                        },
                      }
                    : {}),
                }
              : {}),
          },
        },
        ...(checkpointEnabled
          ? [
              {
                name: 'work-checkpoint',
                modules: true,
                scriptPath: join(modulesRoot, 'checkpoint.mjs'),
                compatibilityDate: '2026-09-30',
                bindings: { WORK_AUTHORITY_ID: 'synthetic-managed-work' },
                durableObjects: { CHECKPOINTS: { className: 'WorkCheckpoint', useSQLite: true } },
              },
            ]
          : []),
        ...(effectEnabled
          ? [
              {
                name: 'work-effect',
                ...(remote && !remote.loseCreate
                  ? remote.bindings
                  : remote
                    ? {}
                    : { outboundService: 'synthetic-artifacts' }),
                modules: true,
                scriptPath: join(modulesRoot, 'effect.mjs'),
                compatibilityDate: '2026-09-30',
                bindings: {
                  WORK_EFFECT_GATE_ENABLED: bindings.WORK_EFFECT_GATE_ENABLED ?? 'true',
                  WORK_AUTHORITY_ID: 'synthetic-managed-work',
                  WORK_ARTIFACTS_ACCOUNT: remote?.accountId ?? 'a'.repeat(32),
                  WORK_ARTIFACTS_NAMESPACE: bindings.WORK_ARTIFACTS_NAMESPACE ?? 'mikaki-dev',
                },
                serviceBindings: {
                  OP_EFFECT_STORE: { name: 'preparation-owner', entrypoint: 'FixtureEffectBridge' },
                  EFFECT_CHECKPOINT: {
                    name:
                      bindings.LOCAL_EFFECT_CLAIM_LOST === 'true'
                        ? 'preparation-owner'
                        : 'work-checkpoint',
                    entrypoint:
                      bindings.LOCAL_EFFECT_CLAIM_LOST === 'true'
                        ? 'FixtureEffectLedger'
                        : 'WorkEffectCheckpoint',
                  },
                  ...(!remote
                    ? {
                        ARTIFACTS: {
                          name: 'synthetic-artifacts',
                          entrypoint: 'SyntheticArtifacts',
                        },
                      }
                    : remote.loseCreate
                      ? { ARTIFACTS: { name: 'lost-create', entrypoint: 'LostCreate' } }
                      : {}),
                },
              },
              ...(!remote
                ? [
                    {
                      name: 'work-git',
                      modules: true,
                      scriptPath: join(modulesRoot, 'git.mjs'),
                      compatibilityDate: '2026-10-08',
                      bindings: { WORK_GIT_GATE_ENABLED: bindings.WORK_GIT_GATE_ENABLED ?? 'true' },
                      serviceBindings: {
                        OP_EFFECT_STORE: {
                          name: 'preparation-owner',
                          entrypoint: 'FixtureEffectBridge',
                        },
                        GIT_CHECKPOINT: {
                          name: 'preparation-owner',
                          entrypoint: 'FixtureGitLedger',
                        },
                      },
                    },
                    {
                      name: 'work-preparation',
                      modules: true,
                      scriptPath: join(modulesRoot, 'preparation.mjs'),
                      // Installed Miniflare rejects 2026-10-09 as future; this
                      // disposable fixture uses its latest supported date.
                      compatibilityDate: '2026-10-08',
                      bindings: {
                        WORK_PREPARATION_GATE_ENABLED:
                          bindings.WORK_PREPARATION_GATE_ENABLED ?? 'true',
                      },
                      serviceBindings: {
                        OP_EFFECT_STORE: {
                          name: 'preparation-owner',
                          entrypoint: 'FixtureEffectBridge',
                        },
                      },
                    },
                    {
                      name: 'work-git-transport',
                      modules: true,
                      scriptPath: join(modulesRoot, 'git-transport.mjs'),
                      compatibilityDate: '2026-10-08',
                      bindings: {
                        WORK_GIT_TRANSPORT_ENABLED: bindings.WORK_GIT_TRANSPORT_ENABLED ?? 'true',
                        WORK_AUTHORITY_ID: 'synthetic-managed-work',
                        WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
                        WORK_ARTIFACTS_NAMESPACE: 'mikaki-dev',
                      },
                      serviceBindings: {
                        MINT_LOOKUP: { name: 'work-checkpoint', entrypoint: 'WorkMintLookup' },
                        GIT_DISPATCH: { name: 'work-checkpoint', entrypoint: 'WorkGitDispatch' },
                        ARTIFACTS: {
                          name: 'synthetic-artifacts',
                          entrypoint: 'SyntheticArtifacts',
                        },
                        GIT_EXECUTOR: async (request: MiniflareRequest) => {
                          if (!gitExecutor) return new MiniflareResponse(null, { status: 409 });
                          const response = await gitExecutor(
                            new Request(request.url, {
                              method: request.method,
                              headers: [...request.headers],
                              body: request.body
                                ? new Uint8Array(await request.arrayBuffer())
                                : undefined,
                            }),
                          );
                          return new MiniflareResponse(
                            new Uint8Array(await response.arrayBuffer()),
                            {
                              status: response.status,
                              headers: [...response.headers],
                            },
                          );
                        },
                      },
                    },
                    {
                      name: 'work-mint',
                      modules: true,
                      scriptPath: join(modulesRoot, 'mint.mjs'),
                      compatibilityDate: '2026-09-30',
                      bindings: {
                        WORK_MINT_GATE_ENABLED: bindings.WORK_MINT_GATE_ENABLED ?? 'true',
                        WORK_AUTHORITY_ID: 'synthetic-managed-work',
                        WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
                        WORK_ARTIFACTS_NAMESPACE: bindings.WORK_ARTIFACTS_NAMESPACE ?? 'mikaki-dev',
                      },
                      serviceBindings: {
                        OP_EFFECT_STORE: {
                          name: 'preparation-owner',
                          entrypoint: 'FixtureEffectBridge',
                        },
                        MINT_CHECKPOINT: Boolean(bindings.LOCAL_MINT_LEDGER_LOST)
                          ? { name: 'preparation-owner', entrypoint: 'FixtureMintLedger' }
                          : { name: 'work-checkpoint', entrypoint: 'WorkMintCheckpoint' },
                        ARTIFACTS: {
                          name: 'synthetic-artifacts',
                          entrypoint: 'SyntheticArtifacts',
                        },
                      },
                    },
                  ]
                : []),
              ...(!remote
                ? [
                    {
                      name: 'mint-maintenance',
                      modules: true,
                      scriptPath: join(modulesRoot, 'mint-maintenance.mjs'),
                      compatibilityDate: '2026-10-08',
                      bindings: {
                        WORK_MINT_MAINTENANCE_ENABLED:
                          bindings.WORK_MINT_MAINTENANCE_ENABLED ?? 'true',
                        WORK_AUTHORITY_ID: 'synthetic-managed-work',
                        WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
                        WORK_ARTIFACTS_NAMESPACE:
                          bindings.WORK_MINT_MAINTENANCE_NAMESPACE ??
                          bindings.WORK_ARTIFACTS_NAMESPACE ??
                          'mikaki-dev',
                      },
                      serviceBindings: {
                        MINT_LOOKUP: { name: 'work-checkpoint', entrypoint: 'WorkMintLookup' },
                        ARTIFACTS: {
                          name: 'synthetic-artifacts',
                          entrypoint: 'SyntheticArtifacts',
                        },
                      },
                    },
                    {
                      name: 'mint-reconcile',
                      modules: true,
                      scriptPath: join(modulesRoot, 'mint-reconcile.mjs'),
                      compatibilityDate: '2026-10-08',
                      bindings: {
                        WORK_MINT_RECONCILE_ENABLED: bindings.WORK_MINT_RECONCILE_ENABLED ?? 'true',
                        WORK_AUTHORITY_ID: 'synthetic-managed-work',
                        WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
                        WORK_ARTIFACTS_NAMESPACE: bindings.WORK_ARTIFACTS_NAMESPACE ?? 'mikaki-dev',
                      },
                      serviceBindings: {
                        MINT_MAINTENANCE: {
                          name: 'work-checkpoint',
                          entrypoint: 'WorkMintMaintenance',
                        },
                        MINT_ARTIFACTS_MAINTENANCE: {
                          name: 'mint-maintenance',
                          entrypoint: 'WorkMintArtifactsMaintenance',
                        },
                        OP_EFFECT_STORE: {
                          name: 'preparation-owner',
                          entrypoint: 'FixtureEffectBridge',
                        },
                      },
                    },
                    {
                      name: 'mint-refusal-transport',
                      outboundService: 'synthetic-artifacts',
                      modules: true,
                      scriptPath: join(modulesRoot, 'mint-refusal-transport.mjs'),
                      compatibilityDate: '2026-10-08',
                      bindings: {
                        WORK_MINT_REFUSAL_TRANSPORT_ENABLED:
                          bindings.WORK_MINT_REFUSAL_TRANSPORT_ENABLED ?? 'true',
                        WORK_AUTHORITY_ID: 'synthetic-managed-work',
                        WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
                        WORK_ARTIFACTS_NAMESPACE: bindings.WORK_ARTIFACTS_NAMESPACE ?? 'mikaki-dev',
                      },
                      serviceBindings: {
                        MINT_LOOKUP: { name: 'work-checkpoint', entrypoint: 'WorkMintLookup' },
                        ARTIFACTS: {
                          name: 'synthetic-artifacts',
                          entrypoint: 'SyntheticArtifacts',
                        },
                      },
                    },
                    {
                      name: 'mint-closure',
                      modules: true,
                      scriptPath: join(modulesRoot, 'mint-closure.mjs'),
                      compatibilityDate: '2026-10-08',
                      bindings: {
                        WORK_MINT_CLOSURE_ENABLED: bindings.WORK_MINT_CLOSURE_ENABLED ?? 'true',
                        WORK_AUTHORITY_ID: 'synthetic-managed-work',
                        WORK_ARTIFACTS_ACCOUNT: 'a'.repeat(32),
                        WORK_ARTIFACTS_NAMESPACE: bindings.WORK_ARTIFACTS_NAMESPACE ?? 'mikaki-dev',
                      },
                      serviceBindings: {
                        MINT_REFUSAL_CHECKPOINT: {
                          name: 'preparation-owner',
                          entrypoint: 'FixtureMintRefusalLedger',
                        },
                        OP_EFFECT_STORE: {
                          name: 'preparation-owner',
                          entrypoint: 'FixtureEffectBridge',
                        },
                      },
                    },
                  ]
                : []),
              {
                name: 'work-reconcile',
                modules: true,
                scriptPath: join(modulesRoot, 'reconcile.mjs'),
                compatibilityDate: '2026-09-30',
                bindings: {
                  WORK_EFFECT_RECONCILE_ENABLED: bindings.WORK_EFFECT_RECONCILE_ENABLED ?? 'true',
                  WORK_AUTHORITY_ID: 'synthetic-managed-work',
                  WORK_ARTIFACTS_ACCOUNT: remote?.accountId ?? 'a'.repeat(32),
                  WORK_ARTIFACTS_NAMESPACE: bindings.WORK_ARTIFACTS_NAMESPACE ?? 'mikaki-dev',
                },
                serviceBindings: {
                  OP_EFFECT_STORE: { name: 'preparation-owner', entrypoint: 'FixtureEffectBridge' },
                  EFFECT_MAINTENANCE: {
                    name: 'work-checkpoint',
                    entrypoint: 'WorkEffectMaintenance',
                  },
                  ARTIFACTS_MAINTENANCE: {
                    name: 'artifacts-maintenance',
                    entrypoint: 'WorkArtifactsMaintenance',
                  },
                },
              },
              {
                name: 'artifacts-maintenance',
                ...(remote ? remote.bindings : {}),
                modules: true,
                scriptPath: join(modulesRoot, 'maintenance.mjs'),
                compatibilityDate: '2026-09-30',
                bindings: {
                  WORK_ARTIFACTS_MAINTENANCE_ENABLED:
                    bindings.WORK_ARTIFACTS_MAINTENANCE_ENABLED ?? 'true',
                  WORK_AUTHORITY_ID: 'synthetic-managed-work',
                  WORK_ARTIFACTS_ACCOUNT: remote?.accountId ?? 'a'.repeat(32),
                  WORK_ARTIFACTS_NAMESPACE:
                    bindings.WORK_MAINTENANCE_NAMESPACE ??
                    bindings.WORK_ARTIFACTS_NAMESPACE ??
                    'mikaki-dev',
                },
                serviceBindings: {
                  EFFECT_LOOKUP: { name: 'work-checkpoint', entrypoint: 'WorkEffectLookup' },
                  ...(!remote
                    ? {
                        ARTIFACTS: {
                          name: 'synthetic-artifacts',
                          entrypoint: 'SyntheticArtifacts',
                        },
                      }
                    : {}),
                },
              },
              {
                name: 'synthetic-artifacts',
                modules: true,
                scriptPath: join(modulesRoot, 'artifacts-fixture.mjs'),
                compatibilityDate: '2026-09-30',
                durableObjects: { REMOTE: { className: 'SyntheticRemote', useSQLite: true } },
                serviceBindings: {
                  CHECKPOINT_ADMIN: { name: 'work-checkpoint', entrypoint: 'WorkCheckpointAdmin' },
                },
              },
              ...(remote?.loseCreate
                ? [
                    {
                      name: 'lost-create',
                      modules: true,
                      scriptPath: join(modulesRoot, 'effect-loss.mjs'),
                      compatibilityDate: '2026-09-30',
                      ...remote.bindings,
                    },
                  ]
                : []),
            ]
          : []),
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
    const migrations = new URL('../../../crates/worker/migrations/', import.meta.url);
    for (const name of (await readdir(migrations)).filter((n) => n.endsWith('.sql')).sort()) {
      if (throughMigration && name.slice(0, 4) > throughMigration) continue;
      const statements = splitSqlQuery(await readFile(new URL(name, migrations), 'utf8'));
      await DB.batch(statements.map((s) => DB.prepare(s)));
    }
    await applyWorkMigrations(DB, throughMigration ? Number(throughMigration) : 12);
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
    if (checkpointEnabled) {
      const checkpoint = {
        authority: 'synthetic-managed-work',
        epoch: 'a'.repeat(64),
        sequence: 0,
        tip: 'b'.repeat(64),
      };
      const initialized = await mf.dispatchFetch('https://work.test/checkpoint-fixture', {
        method: 'POST',
        body: JSON.stringify({ action: 'bootstrap', checkpoint, floor: 1 }),
      });
      if (initialized.status !== 200) throw new Error('checkpoint_bootstrap_failed');
      await DB.prepare('INSERT INTO work_authority_checkpoint VALUES(1,?,?,?,?)')
        .bind(checkpoint.authority, checkpoint.epoch, checkpoint.sequence, checkpoint.tip)
        .run();
    }
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
  async function ownerRead(
    path: string,
    cookie: string | null = 'synthetic-delivery-session',
    options: { method?: string; headers?: Record<string, string> } = {},
  ) {
    const response = await mf.dispatchFetch(`https://work.test${path}`, {
      ...options,
      headers: { ...(cookie ? { Cookie: `__Host-op-sso=${cookie}` } : {}), ...options.headers },
    });
    return {
      status: response.status,
      body: (await response.json()) as Record<string, unknown>,
      headers: response.headers,
    };
  }
  const bucket = await mf.getR2Bucket('WORK_GIT_PAYLOADS');
  const fixtureFetch = (path: string, values: Record<string, unknown>) =>
    mf.dispatchFetch(`https://work.test${path}`, {
      method: 'POST',
      headers: path.startsWith('/work/')
        ? {
            Cookie: '__Host-op-sso=synthetic-delivery-session',
            Origin: 'https://work.test',
            'Content-Type': 'application/json',
          }
        : {},
      body: JSON.stringify(path === '/fixture' ? { session, ...values } : values),
    });
  return {
    DB,
    bucket,
    call,
    initialize,
    ownerRead,
    account,
    session,
    fixtureFetch,
    async inspectRemote(name: string) {
      if (!remote || !/^wk-[a-f0-9]{32}-(code|snapshot)$/.test(name))
        throw new Error('fixture_remote_inspect_denied');
      const env = await mf.getBindings<{ ARTIFACTS: Artifacts }>('artifacts-maintenance');
      const repo = await env.ARTIFACTS.get(name);
      // Node host proxy does not forward disposal symbols; caller closes mf.
      return { info: await repo.info(), inventory: await repo.listTokens() };
    },
    request: (path: string, options: FixtureRequestOptions = {}) =>
      mf.dispatchFetch(`https://work.test${path}`, options),
    async bindingNames(worker: string) {
      return Object.keys(await mf.getBindings(worker)).sort();
    },
    close: () => mf.dispose(),
  };
}
