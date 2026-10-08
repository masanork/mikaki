import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { cp, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { preparationFixture } from './work-preparation-fixture.ts';
import { gitFixture } from '../../../scripts/work-git-fixture.ts';
import { prepareGitDisclosure } from '../../../scripts/work-git-disclosure.ts';
import type { InitialPlan, EffectRecord } from '../../../crates/work-effect-worker/protocol.ts';

export type Result = {
  attempt_id: string;
  state: string;
  repo_id: string | null;
  op_synchronized?: boolean;
  cleanup?: string;
};
export type Remote = {
  counts: Record<string, number>;
  repos: {
    id: string;
    name: string;
    state: string;
    defaultBranch: string;
    tokens: { id: string; scope: string; state: string; expiresAt: string }[];
  }[];
};
export async function effectFixture(overrides: Record<string, string> = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-effect-'));
  const bindings = {
    WORK_CREDENTIAL_KEY_FLOOR: '1',
    WORK_CREDENTIAL_KEY_V1: randomBytes(32).toString('base64url'),
    WORK_EFFECT_STORE_ENABLED: 'true',
    WORK_MINT_STORE_ENABLED: 'true',
    ...overrides,
  };
  let op = await preparationFixture(directory, bindings, true, true),
    stopped = false;
  try {
    const code = await gitFixture(directory, 'code', { 'README.md': 'Synthetic code\n' });
    const selected = await prepareGitDisclosure(
      { repository: 'code', gitDir: code.dir, commit: code.commit },
      [],
      directory,
      'snapshot',
    );
    const p = await op.initialize(selected.input);
    await op.call({ action: 'dispatch-preparation', id: p.id });
    await op.call({ action: 'activate-credential-key' });
    const task = await op.call({
      action: 'reserve-credential',
      credential: { preparation_id: p.id, role: 'task', purpose: 'initial' },
    });
    const snapshot = await op.call({
      action: 'reserve-credential',
      credential: { preparation_id: p.id, role: 'snapshot', purpose: 'initial' },
    });
    async function effect<T>(values: Record<string, unknown>, status = 200): Promise<T> {
      const r = await op.fixtureFetch('/effect-fixture', values);
      assert.equal(r.status, status);
      return JSON.parse((await r.text()) || 'null') as T;
    }
    async function stop() {
      if (!stopped) {
        await op.close();
        stopped = true;
      }
    }
    async function restart(extra: Record<string, string> = {}) {
      await stop();
      op = await preparationFixture(directory, { ...bindings, ...extra }, true, true);
      stopped = false;
    }
    return {
      p,
      call: (input: Record<string, unknown>) => op.call(input),
      task,
      snapshot,
      directory,
      effect,
      bindingNames: (worker: string) => op.bindingNames(worker),
      broker: (
        method: string,
        argument?: unknown,
        extra: Record<string, unknown> = {},
        status = 200,
      ) =>
        effect<Record<string, unknown>>(
          { action: 'broker-call', input: { attempt_id: task.id }, method, argument, ...extra },
          status,
        ),
      execute: (attempt = task.id, status = 200) =>
        effect<Result>({ action: 'execute', input: { attempt_id: attempt } }, status),
      reconcile: (attempt = task.id, status = 200) =>
        effect<Result>({ action: 'reconcile', input: { attempt_id: attempt } }, status),
      plan: (attempt = task.id, status = 200) =>
        effect<InitialPlan>(
          { action: 'plan', input: { action: 'initial-plan', attempt_id: attempt } },
          status,
        ),
      ledger: (attempt = task.id) =>
        effect<EffectRecord | null>({ action: 'ledger-lookup', attempt_id: attempt }),
      remote: () => effect<Remote>({ action: 'inspect' }),
      mode: (mode: string) => effect({ action: 'configure', mode }),
      async row(attempt = task.id) {
        return op.DB.prepare(
          'SELECT state,observation,envelope,key_version,nonce,receipt FROM work_credential_attempt WHERE attempt_id=?',
        )
          .bind(attempt)
          .first<Record<string, unknown>>();
      },
      async backup() {
        await stop();
        await cp(join(directory, 'op-state/d1'), join(directory, 'd1-backup'), { recursive: true });
        await restart();
      },
      async restore() {
        await stop();
        await rm(join(directory, 'op-state/d1'), { recursive: true, force: true });
        await cp(join(directory, 'd1-backup'), join(directory, 'op-state/d1'), { recursive: true });
        await restart();
      },
      restart,
      get DB() {
        return op.DB;
      },
      checkpoint: (values: Record<string, unknown>) =>
        op.fixtureFetch('/checkpoint-fixture', values),
      async close() {
        await stop();
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await op.close();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
