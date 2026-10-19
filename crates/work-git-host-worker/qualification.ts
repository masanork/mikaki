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
const RESTART = 'inactive_restart_v1';
export class WorkGitHostQualification extends WorkerEntrypoint<GitHostQualificationEnv> {
  fetch() {
    return new Response(null, { status: 404 });
  }
  async prepare(...args: unknown[]) {
    if (args.length || !configured(this.env)) throw new Error('qualification_denied');
    return await this.env.GIT_HOST.getByName(
      `${this.env.WORK_AUTHORITY_ID}:${this.env.WORK_GIT_DISCLOSURE_DIGEST}`,
    ).prepare();
  }
  async status(...args: unknown[]) {
    if (args.length || !configured(this.env)) throw new Error('qualification_denied');
    return await this.env.GIT_HOST.getByName(
      `${this.env.WORK_AUTHORITY_ID}:${this.env.WORK_GIT_DISCLOSURE_DIGEST}`,
    ).status();
  }
  async qualifyRestart(...args: unknown[]) {
    if (args.length || !configured(this.env)) throw new Error('qualification_denied');
    return await this.env.GIT_HOST.getByName(
      `${this.env.WORK_AUTHORITY_ID}:${this.env.WORK_GIT_DISCLOSURE_DIGEST}`,
    ).qualifyRestart();
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
      CREATE TABLE IF NOT EXISTS qualification_restart(id INTEGER PRIMARY KEY CHECK(id=1), frame TEXT NOT NULL, image TEXT NOT NULL, prior_attempts INTEGER NOT NULL CHECK(prior_attempts=3));
      CREATE TABLE IF NOT EXISTS qualification_outcome(slot TEXT PRIMARY KEY CHECK(slot IN ('1','2','3','inactive_restart_v1')), result TEXT NOT NULL CHECK(length(result) BETWEEN 1 AND 4096));
      CREATE TRIGGER IF NOT EXISTS qualification_restart_no_update BEFORE UPDATE ON qualification_restart BEGIN SELECT RAISE(ABORT,'immutable'); END;
      CREATE TRIGGER IF NOT EXISTS qualification_restart_no_delete BEFORE DELETE ON qualification_restart BEGIN SELECT RAISE(ABORT,'retained'); END;
      CREATE TRIGGER IF NOT EXISTS qualification_outcome_no_update BEFORE UPDATE ON qualification_outcome BEGIN SELECT RAISE(ABORT,'immutable'); END;
      CREATE TRIGGER IF NOT EXISTS qualification_outcome_no_delete BEFORE DELETE ON qualification_outcome BEGIN SELECT RAISE(ABORT,'retained'); END;
    `);
  }
  fetch() {
    return new Response(null, { status: 404 });
  }
  #frame() {
    return JSON.stringify([
      this.env.WORK_ARTIFACTS_ACCOUNT,
      this.env.WORK_ARTIFACTS_NAMESPACE,
      this.env.WORK_AUTHORITY_ID,
      this.env.WORK_GIT_DISCLOSURE_DIGEST,
      this.env.WORK_GIT_REGISTRY_SHA256,
    ]);
  }
  #requireFrame() {
    if (
      this.ctx.storage.sql.exec<{ frame: string }>('SELECT frame FROM qualification_frame').one()
        .frame !== this.#frame()
    )
      throw new Error('qualification_denied');
  }
  #result(slot: string): unknown {
    const rows = this.ctx.storage.sql
      .exec<{ result: string }>('SELECT result FROM qualification_outcome WHERE slot=?', slot)
      .toArray();
    return rows.length ? JSON.parse(rows[0]!.result) : null;
  }
  async #retain(slot: string, result: unknown) {
    this.ctx.storage.sql.exec(
      'INSERT INTO qualification_outcome VALUES(?,?)',
      slot,
      JSON.stringify(result),
    );
    await this.ctx.storage.sync();
  }
  /** Storage and running-state inspection only: never starts or contacts Linux/R2. */
  status(...args: unknown[]) {
    if (args.length || !configured(this.env) || this.#busy) throw new Error('qualification_denied');
    const framePresent =
      this.ctx.storage.sql.exec('SELECT id FROM qualification_frame').toArray().length === 1;
    if (framePresent) this.#requireFrame();
    const restart = this.ctx.storage.sql
      .exec<{ frame: string; image: string }>('SELECT frame,image FROM qualification_restart')
      .toArray()[0];
    if (restart && restart.frame !== this.#frame()) throw new Error('qualification_denied');
    return {
      kind: 'git_host_infrastructure_status',
      registry_sha256: this.env.WORK_GIT_REGISTRY_SHA256,
      disclosure_digest: this.env.WORK_GIT_DISCLOSURE_DIGEST,
      frame_present: framePresent,
      container_available: !!this.ctx.container,
      container_running: !!this.ctx.container?.running,
      image: this.ctx.container?.images.host ?? null,
      attempts: this.ctx.storage.sql
        .exec<{ ordinal: number }>('SELECT ordinal FROM qualification_attempt ORDER BY ordinal')
        .toArray()
        .map(({ ordinal }) => ({ ordinal, result: this.#result(String(ordinal)) })),
      restart: restart ? { image: restart.image, result: this.#result(RESTART) } : null,
      internet_enabled: false,
      git_dispatches: 0,
    };
  }
  /** One independent measurement from a known stopped process; no original slot is reset. */
  async qualifyRestart(...args: unknown[]) {
    if (args.length || !configured(this.env) || this.#busy) throw new Error('qualification_denied');
    this.#busy = true;
    try {
      const c = this.ctx.container;
      if (
        !c ||
        c.running ||
        !c.images.host ||
        c.images.host.length > 512 ||
        !new RegExp(
          `^registry\\.cloudflare\\.com/${this.env.WORK_ARTIFACTS_ACCOUNT}/[a-z0-9_.:/-]+@sha256:[a-f0-9]{64}$`,
        ).test(c.images.host)
      )
        throw new Error('qualification_denied');
      this.ctx.storage.transactionSync(() => {
        this.#requireFrame();
        if (
          this.ctx.storage.sql
            .exec<{ n: number }>('SELECT count(*) AS n FROM qualification_attempt')
            .one().n !== 3
        )
          throw new Error('qualification_denied');
        this.ctx.storage.sql.exec(
          'INSERT INTO qualification_restart VALUES(1,?,?,3)',
          this.#frame(),
          c.images.host,
        );
      });
      await this.ctx.storage.sync();
      const startedAt = Date.now();
      let ready: Awaited<ReturnType<typeof readyGitHost>>;
      try {
        ready = await readyGitHost(this.env, c, false);
        if (!ready.started) throw new Error('qualification_denied');
      } catch {
        await this.#retain(RESTART, {
          kind: 'git_host_infrastructure_failed',
          slot: RESTART,
          reason: 'not_ready',
        });
        throw new Error('qualification_denied');
      }
      const result = {
        kind: 'git_host_infrastructure_restart',
        experiment: RESTART,
        prior_attempts: 3,
        ready: true,
        registry_sha256: this.env.WORK_GIT_REGISTRY_SHA256,
        disclosure_digest: this.env.WORK_GIT_DISCLOSURE_DIGEST,
        image: ready.image,
        started: true,
        elapsed_ms: Date.now() - startedAt,
        internet_enabled: false,
        git_dispatches: 0,
      };
      await this.#retain(RESTART, result);
      return result;
    } catch {
      throw new Error('qualification_denied');
    } finally {
      this.#busy = false;
    }
  }
  async prepare(...args: unknown[]) {
    if (args.length || !configured(this.env) || this.#busy) throw new Error('qualification_denied');
    this.#busy = true;
    try {
      const frame = this.#frame();
      const ordinal = this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec('INSERT OR IGNORE INTO qualification_frame VALUES(1,?)', frame);
        this.#requireFrame();
        const n =
          this.ctx.storage.sql
            .exec<{ n: number }>('SELECT count(*) AS n FROM qualification_attempt')
            .one().n + 1;
        this.ctx.storage.sql.exec('INSERT INTO qualification_attempt VALUES(?)', n);
        return n;
      });
      await this.ctx.storage.sync();
      const startedAt = Date.now();
      let ready: Awaited<ReturnType<typeof readyGitHost>>;
      try {
        ready = await readyGitHost(this.env, this.ctx.container, false);
      } catch {
        await this.#retain(String(ordinal), {
          kind: 'git_host_infrastructure_failed',
          slot: String(ordinal),
          reason: 'not_ready',
        });
        throw new Error('qualification_denied');
      }
      const result = {
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
      await this.#retain(String(ordinal), result);
      return result;
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
