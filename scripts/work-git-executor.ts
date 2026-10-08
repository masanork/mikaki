/** Private trusted Git host adapter. No listener, source discovery or owner API. */
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { gitPlan, gitResult } from '../crates/work-effect-worker/protocol.ts';
import { oneShotGitHttp, uploadGitPack } from './work-git-upload.ts';
import type { GitHttp } from './work-git-upload.ts';
import { readbackGitPack } from './work-git-readback.ts';
import type { GitResult } from '../crates/work-effect-worker/protocol.ts';
import { inspectGitSource, localGit } from './work-git-disclosure.ts';
import { objectInventory, verifyGitReadback, opaqueGitToken } from './work-artifacts-git.ts';
export type RegisteredGit = {
  disclosure_digest: string;
  role: 'task' | 'snapshot';
  gitDir: string;
  commit: string;
  tree: string;
};
/** The registry/HTTP service are private host capabilities, never request fields. */
export function fixedGitExecutor(
  config: {
    account: string;
    namespace: string;
    authority: string;
    temporaryDirectory: string;
    registered: readonly RegisteredGit[];
  },
  http?: GitHttp,
) {
  if (!/^[a-f0-9]{32}$/.test(config.account) || !/^[a-z0-9-]{1,63}$/.test(config.namespace))
    throw new Error('git_configuration_invalid');
  const registry = config.registered.map((s) => Object.freeze({ ...s }));
  const uploadHttp = http ?? oneShotGitHttp(config.account, config.namespace);
  return async function execute(request: Request): Promise<Response> {
    let temporary: string | undefined;
    try {
      if (request.method !== 'POST' || request.url !== 'https://private.invalid/git-execute')
        throw new Error('git_denied');
      const authorization = request.headers.get('Authorization');
      if (!authorization?.startsWith('Bearer ')) throw new Error('git_denied');
      const token = authorization.slice(7);
      opaqueGitToken(token);
      const reader = request.body?.getReader();
      if (!reader) throw new Error('git_denied');
      let size = 0;
      const chunks: Uint8Array[] = [];
      for (;;) {
        const r = await reader.read();
        if (r.done) break;
        size += r.value.byteLength;
        if (size > 4096) {
          await reader.cancel();
          throw new Error('git_denied');
        }
        chunks.push(r.value);
      }
      const p: unknown = JSON.parse(
        new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)),
      );
      gitPlan(p);
      if (
        p.namespace !== config.namespace ||
        p.checkpoint.authority !== config.authority ||
        p.observation.expires_at <= Math.floor(Date.now() / 1000) + 5
      )
        throw new Error('git_denied');
      const candidates = registry.filter(
        (s) => s.disclosure_digest === p.disclosure_digest && s.role === p.role,
      );
      if (candidates.length !== 1) throw new Error('git_source_unavailable');
      const source = candidates[0]!;
      if (source.commit !== p.commit || source.tree !== p.tree)
        throw new Error('git_source_mismatch');
      const inspected = await inspectGitSource({
        repository: p.role,
        gitDir: source.gitDir,
        commit: p.commit,
      });
      if (inspected.tree !== p.tree) throw new Error('git_source_mismatch');
      const expected = objectInventory(inspected.dir, p.commit);
      const commits = localGit(inspected.dir, ['rev-list', p.commit]).toString().trim().split('\n');
      if (
        commits.length > 4096 ||
        (p.role === 'snapshot' &&
          (commits.length !== 1 ||
            /^parent /m.test(localGit(inspected.dir, ['cat-file', 'commit', p.commit]).toString())))
      )
        throw new Error('git_history_mismatch');
      let facts: Omit<GitResult, 'receipt'>;
      if (p.purpose === 'upload') {
        // Exact commit closure only; no --mirror/--all/tags, source remote,
        // checkout, hooks, inherited auth helper or overwrite of an existing ref.
        await uploadGitPack(p, token, inspected.dir, uploadHttp);
        facts = {
          method: 'git_push_accepted',
          commit: p.commit,
          tree: p.tree,
          branch: p.branch,
          commits: commits.length,
          objects: expected.objects.length,
          object_bytes: expected.bytes,
          inventory_sha256: expected.sha256,
        };
      } else {
        temporary = await mkdtemp(join(config.temporaryDirectory, 'readback-'));
        localGit(temporary, ['init', '--bare', '--quiet', '--template=']);
        const packed = await readbackGitPack(p, token, temporary, uploadHttp);
        const verified = verifyGitReadback(temporary, inspected.dir, p.commit, p.tree, p.branch);
        if (packed !== verified.objects) throw new Error('git_readback_unreachable_objects');
        facts = {
          method: 'git_readback_verified',
          commit: p.commit,
          tree: p.tree,
          branch: p.branch,
          commits: verified.commits,
          objects: verified.objects,
          object_bytes: verified.object_bytes,
          inventory_sha256: verified.inventory_sha256,
        };
      }
      const receipt = createHash('sha256')
        .update(JSON.stringify(['mikaki-git-result-v1', p, facts]))
        .digest('hex');
      const result = { ...facts, receipt };
      gitResult(result, p);
      return Response.json(result, { headers: { 'Cache-Control': 'no-store' } });
    } catch {
      return Response.json(
        { error: 'git_outcome_unknown_or_denied' },
        { status: 409, headers: { 'Cache-Control': 'no-store' } },
      );
    } finally {
      if (temporary) await rm(temporary, { recursive: true, force: true });
    }
  };
}
