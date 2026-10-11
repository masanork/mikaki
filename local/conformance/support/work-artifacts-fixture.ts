/** Synthetic remote binding over real RPC/SQLite. NEVER a product/deploy target. */
import { DurableObject, RpcTarget, WorkerEntrypoint } from 'cloudflare:workers';
interface Env {
  REMOTE: DurableObjectNamespace<SyntheticRemote>;
  CHECKPOINT_ADMIN: { freeze(): Promise<void> };
}
type CreateOptions = NonNullable<Parameters<Artifacts['create']>[1]>;
type RemoteRepo = {
  id: string;
  name: string;
  defaultBranch: string;
  remote: string;
  description: string | null;
  token: string;
  state: 'active' | 'revoked';
};
type State = { mode: string; repos: RemoteRepo[]; counts: Record<string, number> };
export class SyntheticRemote extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(
      'CREATE TABLE IF NOT EXISTS remote(id INTEGER PRIMARY KEY,body TEXT NOT NULL)',
    );
    ctx.storage.sql.exec(
      'INSERT OR IGNORE INTO remote VALUES(1,?)',
      JSON.stringify({
        mode: 'normal',
        repos: [],
        counts: { create: 0, get: 0, info: 0, list: 0, revoke: 0 },
      }),
    );
  }
  #state(): State {
    return JSON.parse(
      this.ctx.storage.sql.exec<{ body: string }>('SELECT body FROM remote').one().body,
    ) as State;
  }
  #save(s: State) {
    this.ctx.storage.sql.exec('UPDATE remote SET body=? WHERE id=1', JSON.stringify(s));
  }
  #repo(s: State, name: string) {
    const r = s.repos.find((r) => r.name === name);
    if (!r) throw new Error('synthetic_not_found');
    return r;
  }
  async configure(mode: string) {
    const s = this.#state();
    s.mode = mode;
    this.#save(s);
    await this.ctx.storage.sync();
  }
  async inspect() {
    const s = this.#state();
    await this.ctx.storage.sync();
    return { mode: s.mode, counts: s.counts, repos: s.repos.map(({ token, ...r }) => r) };
  }
  async create(name: string, options: CreateOptions) {
    const s = this.#state();
    s.counts.create++;
    if (s.repos.some((r) => r.name === name)) {
      this.#save(s);
      throw new Error('synthetic_exists');
    }
    const r: RemoteRepo = {
      id: `synthetic-${s.counts.create}`,
      name,
      defaultBranch: options.setDefaultBranch ?? 'main',
      remote: `https://${'a'.repeat(32)}.artifacts.cloudflare.net/git/mikaki-dev/${name}.git`,
      token: `SYNTHETIC_INITIAL_SECRET_${s.counts.create}`,
      description: options.description ?? null,
      state: 'active',
    };
    s.repos.push(r);
    this.#save(s);
    await this.ctx.storage.sync();
    if (s.mode === 'create-lost') throw new Error('synthetic_lost_reply');
    if (s.mode === 'freeze-during-create') await this.env.CHECKPOINT_ADMIN.freeze();
    return {
      id: r.id,
      name: r.name,
      defaultBranch: r.defaultBranch,
      remote: s.mode === 'wrong-remote' ? 'https://wrong.invalid/repo.git' : r.remote,
      description: r.description,
      token: r.token,
    };
  }
  async open(name: string) {
    const s = this.#state();
    s.counts.get++;
    this.#repo(s, name);
    this.#save(s);
    await this.ctx.storage.sync();
    if (s.mode === 'get-lost') throw new Error('synthetic_lost_reply');
  }
  async info(name: string) {
    const s = this.#state();
    s.counts.info++;
    const r = this.#repo(s, name);
    this.#save(s);
    await this.ctx.storage.sync();
    return {
      id: s.mode === 'replaced-repo' ? 'replacement' : r.id,
      name: r.name,
      defaultBranch: r.defaultBranch,
      remote: r.remote,
      description: s.mode === 'wrong-description' ? 'unrelated' : r.description,
    };
  }
  async list(name: string) {
    const s = this.#state();
    s.counts.list++;
    const r = this.#repo(s, name);
    this.#save(s);
    await this.ctx.storage.sync();
    if (s.mode === 'list-lost') throw new Error('synthetic_lost_reply');
    const token = {
      id: s.mode === 'replaced-token' ? 'replacement' : `token-${r.id}`,
      scope: 'write' as const,
      state: r.state,
      createdAt: '2026-01-01T00:00:00.000Z',
      expiresAt:
        s.mode === 'fractional-expiry' ? '2030-01-01T00:00:00.125Z' : '9999-12-31T23:59:59.000Z',
    };
    if (
      s.mode === 'empty-inventory' ||
      (s.mode === 'remove-revoked' && r.state === 'revoked') ||
      (s.mode === 'revoke-lost-remove' && r.state === 'revoked')
    )
      return { tokens: [], total: 0 };
    if ((s.mode === 'unexpected-token' && r.state === 'revoked') || s.mode === 'multiple-tokens')
      return {
        tokens: [token, { ...token, id: 'unexpected', state: 'active' as const }],
        total: 2,
      };
    return { tokens: [token], total: s.mode === 'incomplete-inventory' ? 2 : 1 };
  }
  async revoke(name: string, token: string) {
    const s = this.#state();
    s.counts.revoke++;
    const r = this.#repo(s, name);
    const accepted = r.token === token || `token-${r.id}` === token;
    if (accepted) r.state = 'revoked';
    this.#save(s);
    await this.ctx.storage.sync();
    if (s.mode === 'revoke-lost' || s.mode === 'revoke-lost-remove')
      throw new Error('synthetic_lost_reply');
    return accepted;
  }
  async git(name: string, token: string) {
    const s = this.#state();
    s.counts.git = (s.counts.git ?? 0) + 1;
    const r = this.#repo(s, name);
    this.#save(s);
    await this.ctx.storage.sync();
    if (s.mode === 'git-unavailable') return 503;
    if (s.mode === 'git-redirect') return 302;
    if (s.mode === 'git-active') return 200;
    return token === `Bearer ${r.token}` && r.state === 'active' ? 200 : 403;
  }
  async note() {
    const s = this.#state();
    s.counts.http = (s.counts.http ?? 0) + 1;
    this.#save(s);
    await this.ctx.storage.sync();
  }
}
class SyntheticRepo extends RpcTarget {
  #stub: DurableObjectStub<SyntheticRemote>;
  #name: string;
  constructor(stub: DurableObjectStub<SyntheticRemote>, name: string) {
    super();
    this.#stub = stub;
    this.#name = name;
  }
  info() {
    return this.#stub.info(this.#name);
  }
  listTokens() {
    return this.#stub.list(this.#name);
  }
  revokeToken(token: string) {
    return this.#stub.revoke(this.#name, token);
  }
  [Symbol.dispose]() {}
}
export class SyntheticArtifacts extends WorkerEntrypoint<Env> {
  create(name: string, options: CreateOptions) {
    return this.env.REMOTE.getByName('remote').create(name, options);
  }
  async get(name: string) {
    const stub = this.env.REMOTE.getByName('remote');
    await stub.open(name);
    return new SyntheticRepo(stub, name);
  }
}
export default class extends WorkerEntrypoint<Env> {
  async fetch(request: Request) {
    if (request.method === 'GET') {
      await this.env.REMOTE.getByName('remote').note();
      const u = new URL(request.url);
      const match =
        /^\/git\/mikaki-dev\/(wk-[a-f0-9]{32}-(?:code|snapshot))\.git\/info\/refs$/.exec(
          u.pathname,
        );
      if (
        u.hostname !== `${'a'.repeat(32)}.artifacts.cloudflare.net` ||
        !match ||
        u.search !== '?service=git-upload-pack'
      )
        return new Response(null, { status: 404 });
      const status = await this.env.REMOTE.getByName('remote').git(
        match[1]!,
        request.headers.get('Authorization') ?? '',
      );
      return new Response(null, {
        status,
        headers: status === 302 ? { Location: 'https://wrong.invalid/' } : {},
      });
    }
    const input = (await request.json()) as { action: string; mode?: string };
    const stub = this.env.REMOTE.getByName('remote');
    if (input.action === 'configure') {
      await stub.configure(input.mode ?? 'normal');
      return Response.json({});
    }
    return Response.json(await stub.inspect());
  }
}
