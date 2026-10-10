/** Actual product Rust/Wasm, Workflows, enrolled checkpoint and real loopback Git. */
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { preparationFixture } from './work-preparation-fixture.ts';
import { gitFixture } from '../../../scripts/work-git-fixture.ts';
import { prepareGitDisclosure } from '../../../scripts/work-git-disclosure.ts';
import { gitHttpFixture } from './work-git-http-fixture.ts';
import { fixedGitExecutor } from '../../../scripts/work-git-executor.ts';
export async function copyJobFixture(extra: Record<string, string> = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-copy-job-'));
  let executor: ((r: Request) => Promise<Response>) | undefined;
  let hook: ((r: Request, next: () => Promise<Response>) => Promise<Response>) | undefined;
  const op = await preparationFixture(
    directory,
    {
      WORK_COPY_EXECUTION_ENABLED: 'true',
      WORK_COPY_CONSENT_ENABLED: 'true',
      WORK_PREPARATION_REVIEW_ENABLED: 'true',
      WORK_SOURCE_API_ENABLED: 'true',
      WORK_EFFECT_STORE_ENABLED: 'true',
      WORK_MINT_STORE_ENABLED: 'true',
      WORK_GIT_STORE_ENABLED: 'true',
      WORK_CREDENTIAL_KEY_FLOOR: '1',
      WORK_CREDENTIAL_KEY_V1: Buffer.alloc(32, 1).toString('base64url'),
      ...extra,
    },
    true,
    true,
    undefined,
    (r) => {
      const next = () =>
        executor ? executor(r) : Promise.resolve(new Response(null, { status: 409 }));
      return hook ? hook(r, next) : next();
    },
    true,
  );
  let httpResource: Awaited<ReturnType<typeof gitHttpFixture>> | undefined;
  try {
    const code = await gitFixture(
      directory,
      'code',
      { 'README.md': 'Current code\n' },
      'Reachable historical code\n',
    );
    const personal = await gitFixture(
      directory,
      'personal',
      { 'selected.md': 'Selected context\n', 'private.md': 'Unselected private context\n' },
      'Historical private context\n',
    );
    const selected = await prepareGitDisclosure(
      { repository: 'code', gitDir: code.dir, commit: code.commit },
      [
        {
          repository: 'personal',
          gitDir: personal.dir,
          commit: personal.commit,
          paths: ['selected.md'],
        },
      ],
      directory,
      'snapshot',
    );
    const p = await op.initialize(selected.input, '0014');
    await op.call({ action: 'activate-credential-key' });
    async function product(path: string, method = 'GET', body?: unknown) {
      const r = await op.productFetch(path, {
        method,
        headers:
          method === 'GET'
            ? {}
            : { Origin: 'https://work.test', 'Content-Type': 'application/json' },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const bodyText = await r.text();
      try {
        return { status: r.status, body: JSON.parse(bodyText) as any };
      } catch {
        throw new Error(`${method} ${path}: ${r.status} ${bodyText.slice(0, 256)}`);
      }
    }
    const review = await product(`/work/preparations/${p.id}/copy-consent`);
    assert.equal(review.status, 200);
    const digest = review.body.record.review_digest;
    const approve = () =>
      product(`/work/preparations/${p.id}/copy-consent`, 'POST', {
        format_version: 1,
        review_digest: digest,
      });
    const remote = async () => {
      const r = await op.fixtureFetch('/effect-fixture', { action: 'inspect' });
      assert.equal(r.status, 200);
      return (await r.json()) as any;
    };
    const http = (httpResource = await gitHttpFixture(directory, async (name, token, write) => {
      const repos = (await remote()).repos,
        repo = repos.find((r: any) => r.name === name),
        n = /^SYNTHETIC_MINT_SECRET_(\d+)$/.exec(token)?.[1];
      const t = repo?.tokens.find((t: any) => t.id === `mint-${n}`);
      return Boolean(t && t.state === 'active' && (!write || t.scope === 'write'));
    }));
    const disclosure = (await product(`/work/preparations/${p.id}`)).body.record.preparation
      .disclosure_digest;
    executor = fixedGitExecutor(
      {
        account: 'a'.repeat(32),
        namespace: 'mikaki-dev',
        authority: 'synthetic-managed-work',
        temporaryDirectory: directory,
        registered: [
          {
            disclosure_digest: disclosure,
            role: 'task',
            gitDir: code.dir,
            commit: code.commit,
            tree: code.tree,
          },
          {
            disclosure_digest: disclosure,
            role: 'snapshot',
            gitDir: selected.gitDir,
            commit: selected.input.snapshot.commit,
            tree: selected.input.snapshot.tree,
          },
        ],
      },
      http.http,
    );
    const copy = () => product(`/work/preparations/${p.id}/copy`);
    const start = () =>
      product(`/work/preparations/${p.id}/copy`, 'POST', {
        format_version: 1,
        review_digest: digest,
      });
    const stop = () =>
      product(`/work/preparations/${p.id}/copy`, 'DELETE', {
        format_version: 1,
        review_digest: digest,
      });
    const advance = async (step: number) => {
      const r = await op.copyPrivate({ action: 'advance', preparation_id: p.id, step });
      return { status: r.status, body: (await r.json()) as any };
    };
    async function settled() {
      for (let n = 0; n < 100; n++) {
        const r = await copy();
        if (r.status === 200 && ['verified', 'blocked'].includes(r.body.record.job?.state))
          return r.body.record;
        await new Promise<void>((r) => setTimeout(r, 100));
      }
      throw new Error('copy_did_not_settle: ' + JSON.stringify((await copy()).body));
    }
    return {
      ...op,
      p,
      digest,
      approve,
      copy,
      start,
      stop,
      advance,
      settled,
      product,
      remote,
      http,
      directory,
      setExecutionHook(value: typeof hook) {
        hook = value;
      },
      async close() {
        await http.close();
        await op.close();
        await rm(directory, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await httpResource?.close();
    await op.close();
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
