/** Test-only Git-backed Artifacts data port and in-flight authority fault hooks. */
import { WorkerEntrypoint } from 'cloudflare:workers';
import { readRegisteredSource } from '../../../crates/work-source-worker/src/core.ts';
import type { ReadableArtifacts } from '../../../crates/work-source-worker/src/core.ts';
type Repo = {
  commit: string;
  tree: string;
  blobs: Record<string, string>;
  paths: Record<string, string>;
};
type Bindings = { DB: D1Database; GIT_FIXTURE: string };
export class FixtureSourceReader extends WorkerEntrypoint<Bindings> {
  async readRegisteredSource(input: string): Promise<string> {
    const i = JSON.parse(input) as { source_id: string; repo_name: string };
    const fault = await this.env.DB.prepare(
      'SELECT mode,owner_id FROM source_reader_fault WHERE source_id=?',
    )
      .bind(i.source_id)
      .first<{ mode: string; owner_id: string }>();
    await this.env.DB.prepare('INSERT INTO source_reader_calls(source_id,request) VALUES(?,?)')
      .bind(i.source_id, input)
      .run();
    if (fault?.mode === 'stall') {
      await new Promise<void>((resolve) => setTimeout(resolve, 13000));
    }
    if (fault?.mode === 'access-revoke')
      await this.env.DB.prepare(
        'UPDATE work_source_access SET active=0,access_revision=access_revision+1 WHERE source_id=? AND owner_id=?',
      )
        .bind(i.source_id, fault.owner_id)
        .run();
    if (fault?.mode === 'access-replace')
      await this.env.DB.prepare(
        'UPDATE work_source_access SET access_revision=access_revision+1 WHERE source_id=? AND owner_id=?',
      )
        .bind(i.source_id, fault.owner_id)
        .run();
    if (fault?.mode === 'head-revoke')
      await this.env.DB.prepare('UPDATE work_source_head SET active=0 WHERE source_id=?')
        .bind(i.source_id)
        .run();
    if (fault?.mode === 'epoch')
      await this.env.DB.prepare('UPDATE account_security SET epoch=epoch+1 WHERE account_id=?')
        .bind(fault.owner_id)
        .run();
    if (fault?.mode === 'session')
      await this.env.DB.prepare('UPDATE sso_session SET revoked=1 WHERE account_id=?')
        .bind(fault.owner_id)
        .run();
    if (fault?.mode === 'policy')
      await this.env.DB.prepare(
        'UPDATE runtime_policy_active SET generation=generation+1 WHERE id=1',
      ).run();
    const repos = JSON.parse(this.env.GIT_FIXTURE) as Record<string, Repo>;
    const artifacts: ReadableArtifacts = {
      async get(name) {
        const repo = repos[name];
        if (!repo) throw new Error('source_unavailable');
        return {
          async readCommit(hash) {
            return hash === repo.commit
              ? { hash, treeHash: fault?.mode === 'wrong-tree' ? '0'.repeat(40) : repo.tree }
              : null;
          },
          async readBlob(hash) {
            const text = repo.blobs[hash];
            if (text === undefined || fault?.mode === 'missing-blob') return null;
            return new Blob([fault?.mode === 'corrupt-blob' ? 'corrupt' : text]);
          },
          async readFile({ ref, path }) {
            const text = repo.blobs[repo.paths[path] ?? ''];
            if (ref !== repo.commit || text === undefined || fault?.mode === 'missing-file')
              return null;
            return new Blob([fault?.mode === 'wrong-file' ? 'different path content' : text]);
          },
          [Symbol.dispose]() {},
        };
      },
    };
    const body = await readRegisteredSource(artifacts, input);
    const reply = JSON.parse(body) as {
      source_id: string;
      files: { content: string }[];
      allow?: boolean;
    };
    if (fault?.mode === 'reply-id') reply.source_id = 'other';
    if (fault?.mode === 'reply-content') reply.files[0]!.content = 'tampered';
    if (fault?.mode === 'reply-unknown') reply.allow = true;
    if (fault?.mode === 'large-reply') return 'x'.repeat(393217);
    return JSON.stringify(reply);
  }
  fetch(): Response {
    return new Response(null, { status: 404 });
  }
}
export default {
  fetch(): Response {
    return new Response(null, { status: 404 });
  },
};
