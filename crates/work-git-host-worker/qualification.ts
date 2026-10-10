/** Isolated infrastructure qualification. No Git dispatch or provider capability. */
import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';
import { readyGitHost } from './worker';

function configured(env: GitHostQualificationEnv) {
  return (
    env.WORK_GIT_PROVISION_ENABLED === 'true' &&
    env.WORK_GIT_HOST_ENABLED === 'false' &&
    /^[a-f0-9]{32}$/.test(env.WORK_ARTIFACTS_ACCOUNT) &&
    env.WORK_ARTIFACTS_NAMESPACE === 'mikaki-dev' &&
    env.WORK_AUTHORITY_ID === 'mikaki-git-host-qualification-v1' &&
    /^[a-f0-9]{64}$/.test(env.WORK_GIT_DISCLOSURE_DIGEST) &&
    /^[a-f0-9]{64}$/.test(env.WORK_GIT_REGISTRY_SHA256)
  );
}
export class WorkGitHostQualification extends WorkerEntrypoint<GitHostQualificationEnv> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  async prepare(...args: unknown[]) {
    if (args.length || !configured(this.env)) throw new Error('qualification_denied');
    return this.env.GIT_HOST.getByName(
      `${this.env.WORK_AUTHORITY_ID}:${this.env.WORK_GIT_DISCLOSURE_DIGEST}`,
    ).prepare();
  }
}
export class GitHostQualificationContainer extends DurableObject<GitHostQualificationEnv> {
  #busy = false;
  constructor(ctx: DurableObjectState, env: GitHostQualificationEnv) {
    super(ctx, env);
    ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS qualification_frame(id INTEGER PRIMARY KEY CHECK(id=1), frame TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS qualification_attempt(ordinal INTEGER PRIMARY KEY CHECK(ordinal BETWEEN 1 AND 3));
      CREATE TRIGGER IF NOT EXISTS qualification_frame_no_update BEFORE UPDATE ON qualification_frame BEGIN SELECT RAISE(ABORT,'immutable'); END;
      CREATE TRIGGER IF NOT EXISTS qualification_frame_no_delete BEFORE DELETE ON qualification_frame BEGIN SELECT RAISE(ABORT,'retained'); END;
      CREATE TRIGGER IF NOT EXISTS qualification_attempt_no_update BEFORE UPDATE ON qualification_attempt BEGIN SELECT RAISE(ABORT,'immutable'); END;
      CREATE TRIGGER IF NOT EXISTS qualification_attempt_no_delete BEFORE DELETE ON qualification_attempt BEGIN SELECT RAISE(ABORT,'retained'); END;
    `);
  }
  fetch() {
    return new Response(null, { status: 404 });
  }
  async prepare(...args: unknown[]) {
    if (args.length || !configured(this.env) || this.#busy) throw new Error('qualification_denied');
    this.#busy = true;
    try {
      const frame = JSON.stringify([
        this.env.WORK_ARTIFACTS_ACCOUNT,
        this.env.WORK_ARTIFACTS_NAMESPACE,
        this.env.WORK_AUTHORITY_ID,
        this.env.WORK_GIT_DISCLOSURE_DIGEST,
        this.env.WORK_GIT_REGISTRY_SHA256,
      ]);
      const ordinal = this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec('INSERT OR IGNORE INTO qualification_frame VALUES(1,?)', frame);
        if (
          this.ctx.storage.sql
            .exec<{ frame: string }>('SELECT frame FROM qualification_frame')
            .one().frame !== frame
        )
          throw new Error('qualification_denied');
        const n =
          this.ctx.storage.sql
            .exec<{ n: number }>('SELECT count(*) AS n FROM qualification_attempt')
            .one().n + 1;
        this.ctx.storage.sql.exec('INSERT INTO qualification_attempt VALUES(?)', n);
        return n;
      });
      await this.ctx.storage.sync();
      const startedAt = Date.now();
      const ready = await readyGitHost(this.env, this.ctx.container, false);
      return {
        kind: 'git_host_infrastructure',
        ready: true,
        registry_sha256: this.env.WORK_GIT_REGISTRY_SHA256,
        disclosure_digest: this.env.WORK_GIT_DISCLOSURE_DIGEST,
        image: ready.image,
        started: ready.started,
        ordinal,
        elapsed_ms: Date.now() - startedAt,
        internet_enabled: false,
        git_dispatches: 0,
      };
    } catch {
      throw new Error('qualification_denied');
    } finally {
      this.#busy = false;
    }
  }
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
};
