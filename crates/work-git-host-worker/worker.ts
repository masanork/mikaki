/** Private Linux host routing. Native and permanent effect gates retain authority. */
import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';
import { gitPlan, gitResult } from '../work-effect-worker/protocol';
import type { GitPlan } from '../work-effect-worker/protocol';
import { jsonBody } from '../work-effect-worker/worker';
import { gitRegistrySchema } from './registry';

function enabled(env: GitHostEnv) {
  return (
    env.WORK_GIT_HOST_ENABLED === 'true' &&
    /^[a-f0-9]{32}$/.test(env.WORK_ARTIFACTS_ACCOUNT) &&
    /^[a-z0-9-]{1,63}$/.test(env.WORK_ARTIFACTS_NAMESPACE) &&
    /^[A-Za-z0-9_.:-]{1,128}$/.test(env.WORK_AUTHORITY_ID) &&
    /^[a-f0-9]{64}$/.test(env.WORK_GIT_DISCLOSURE_DIGEST) &&
    /^[a-f0-9]{64}$/.test(env.WORK_GIT_REGISTRY_SHA256)
  );
}
export async function checkedGitHostPlan(request: Request, env: GitHostEnv) {
  if (
    !enabled(env) ||
    request.method !== 'POST' ||
    request.url !== 'https://private.invalid/git-execute' ||
    !/^Bearer [\x21-\x7e]{16,4096}$/.test(request.headers.get('Authorization') ?? '') ||
    request.headers.get('Content-Type') !== 'application/json'
  )
    throw new Error('git_host_denied');
  const p: unknown = await jsonBody(request);
  gitPlan(p);
  if (
    p.artifacts_account !== env.WORK_ARTIFACTS_ACCOUNT ||
    p.namespace !== env.WORK_ARTIFACTS_NAMESPACE ||
    p.checkpoint.authority !== env.WORK_AUTHORITY_ID ||
    p.disclosure_digest !== env.WORK_GIT_DISCLOSURE_DIGEST ||
    p.observation.expires_at <= Math.floor(Date.now() / 1000) + 5
  )
    throw new Error('git_host_denied');
  return p;
}
const denied = () => new Response(null, { status: 409, headers: { 'Cache-Control': 'no-store' } });

export function initializeGitHostStorage(storage: DurableObjectStorage) {
  storage.sql.exec(`
    CREATE TABLE IF NOT EXISTS host_frame(id INTEGER PRIMARY KEY CHECK(id=1), frame TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS host_attempt(attempt TEXT PRIMARY KEY, role TEXT NOT NULL, purpose TEXT NOT NULL, plan TEXT NOT NULL, UNIQUE(role,purpose));
    CREATE TRIGGER IF NOT EXISTS host_frame_no_update BEFORE UPDATE ON host_frame BEGIN SELECT RAISE(ABORT,'immutable'); END;
    CREATE TRIGGER IF NOT EXISTS host_frame_no_delete BEFORE DELETE ON host_frame BEGIN SELECT RAISE(ABORT,'retained'); END;
    CREATE TRIGGER IF NOT EXISTS host_attempt_no_update BEFORE UPDATE ON host_attempt BEGIN SELECT RAISE(ABORT,'immutable'); END;
    CREATE TRIGGER IF NOT EXISTS host_attempt_no_delete BEFORE DELETE ON host_attempt BEGIN SELECT RAISE(ABORT,'retained'); END;
  `);
}
export async function retainGitHostAttempt(
  storage: DurableObjectStorage,
  env: GitHostEnv,
  p: GitPlan,
) {
  const frame = JSON.stringify([
    env.WORK_ARTIFACTS_ACCOUNT,
    p.namespace,
    p.checkpoint.authority,
    p.disclosure_digest,
    env.WORK_GIT_REGISTRY_SHA256,
  ]);
  storage.transactionSync(() => {
    storage.sql.exec('INSERT OR IGNORE INTO host_frame VALUES(1,?)', frame);
    if (
      storage.sql.exec<{ frame: string }>('SELECT frame FROM host_frame WHERE id=1').one().frame !==
      frame
    )
      throw new Error('git_host_frame_mismatch');
    storage.sql.exec(
      'INSERT INTO host_attempt VALUES(?,?,?,?)',
      p.attempt_id,
      p.role,
      p.purpose,
      JSON.stringify(p),
    );
  });
  await storage.sync();
}

export class WorkGitHost extends WorkerEntrypoint<GitHostEnv> {
  async fetch(request: Request) {
    if (this.env.WORK_GIT_HOST_ENABLED !== 'true') return new Response(null, { status: 404 });
    try {
      const p = await checkedGitHostPlan(request, this.env);
      // Stable across image rollouts. Registry changes cannot erase old attempts.
      return await this.env.GIT_HOST.getByName(
        `${p.checkpoint.authority}:${p.disclosure_digest}`,
      ).fetch('https://private.invalid/git-execute', {
        method: 'POST',
        headers: {
          Authorization: request.headers.get('Authorization')!,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(p),
      });
    } catch {
      return denied();
    }
  }
}

export class GitHostContainer extends DurableObject<GitHostEnv> {
  #busy = false;
  constructor(ctx: DurableObjectState, env: GitHostEnv) {
    super(ctx, env);
    if (enabled(env)) initializeGitHostStorage(ctx.storage);
  }
  async fetch(request: Request) {
    if (this.env.WORK_GIT_HOST_ENABLED !== 'true') return new Response(null, { status: 404 });
    try {
      const p = await checkedGitHostPlan(request, this.env);
      if (this.#busy) throw new Error('git_host_busy');
      this.#busy = true;
      try {
        // A fresh primary attempt cannot repeat the same role/purpose here.
        await retainGitHostAttempt(this.ctx.storage, this.env, p);
        const response = await this.#exchange(request.headers.get('Authorization')!, p);
        if (response.status !== 200) {
          await response.body?.cancel();
          throw new Error('git_host_unknown');
        }
        const value: unknown = await jsonBody(response);
        gitResult(value, p);
        return Response.json(value, { headers: { 'Cache-Control': 'no-store' } });
      } finally {
        this.#busy = false;
      }
    } catch {
      return denied();
    }
  }
  /** Only readiness GETs retry. The productive port POST is called exactly once. */
  async #exchange(authorization: string, p: GitPlan) {
    const c = this.ctx.container;
    if (!c || !c.images.host) throw new Error('git_host_unavailable');
    if (c.running) {
      if ((await c.inspect())?.image !== c.images.host) throw new Error('git_host_old_image');
    } else {
      c.start({
        image: c.images.host,
        instance: 'standard-1',
        enableInternet: true,
        env: {
          WORK_ARTIFACTS_ACCOUNT: this.env.WORK_ARTIFACTS_ACCOUNT,
          WORK_ARTIFACTS_NAMESPACE: this.env.WORK_ARTIFACTS_NAMESPACE,
          WORK_AUTHORITY_ID: this.env.WORK_AUTHORITY_ID,
          WORK_GIT_REGISTRY_SHA256: this.env.WORK_GIT_REGISTRY_SHA256,
        },
      });
    }
    await c.setInactivityTimeout(60000);
    const port = c.getTcpPort(8080),
      deadline = Date.now() + 20000;
    for (;;) {
      let ready: Response | undefined;
      try {
        ready = await port.fetch('http://localhost/health', { signal: AbortSignal.timeout(2000) });
      } catch {
        /* connection not ready */
      }
      if (ready?.status === 200) {
        await ready.body?.cancel();
        break;
      }
      await ready?.body?.cancel();
      if (Date.now() >= deadline) throw new Error('git_host_not_ready');
      await new Promise<void>((resolve) => setTimeout(resolve, 200));
    }
    let ready = await port.fetch('http://localhost/ready', { signal: AbortSignal.timeout(2000) });
    if (ready.status === 503) {
      await ready.body?.cancel();
      await provisionGitHost(this.env, port);
      ready = await port.fetch('http://localhost/ready', { signal: AbortSignal.timeout(2000) });
    }
    if (ready.status !== 200) {
      await ready.body?.cancel();
      throw new Error('git_host_not_ready');
    }
    const value: unknown = await jsonBody(ready);
    if (
      !value ||
      typeof value !== 'object' ||
      Object.keys(value).sort().join(',') !== 'disclosure_digest,registry_sha256' ||
      !('registry_sha256' in value) ||
      !('disclosure_digest' in value) ||
      value.registry_sha256 !== this.env.WORK_GIT_REGISTRY_SHA256 ||
      value.disclosure_digest !== this.env.WORK_GIT_DISCLOSURE_DIGEST
    )
      throw new Error('git_host_readiness_mismatch');
    return port.fetch('http://localhost/git-execute', {
      method: 'POST',
      headers: {
        Authorization: authorization,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(p),
      redirect: 'manual',
      signal: AbortSignal.timeout(60000),
    });
  }
}
export async function provisionGitHost(
  env: Pick<GitHostEnv, 'GIT_SOURCES' | 'WORK_GIT_REGISTRY_SHA256' | 'WORK_GIT_DISCLOSURE_DIGEST'>,
  port: Fetcher,
) {
  const prefix = `registry/${env.WORK_GIT_REGISTRY_SHA256}/`;
  const object = await env.GIT_SOURCES.get(prefix + 'registry.json');
  if (!object || object.size > 4096) throw new Error('git_host_package_unavailable');
  const bytes = await object.arrayBuffer();
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), (x) =>
    x.toString(16).padStart(2, '0'),
  ).join('');
  if (digest !== env.WORK_GIT_REGISTRY_SHA256) throw new Error('git_host_package_mismatch');
  const registry = gitRegistrySchema.parse(
    JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)),
  );
  if (registry.disclosure_digest !== env.WORK_GIT_DISCLOSURE_DIGEST)
    throw new Error('git_host_package_mismatch');
  const send = async (path: string, body?: BodyInit) => {
    const r = await port.fetch('http://localhost/provision/' + path, {
      method: 'POST',
      ...(body === undefined ? {} : { body }),
      redirect: 'manual',
      signal: AbortSignal.timeout(60000),
    });
    await r.body?.cancel();
    if (r.status !== 204) throw new Error('git_host_provision_failed');
  };
  await send('registry', bytes);
  for (const entry of registry.entries) {
    const pack = await env.GIT_SOURCES.get(prefix + entry.role + '.pack');
    if (!pack || pack.size !== entry.pack_bytes) throw new Error('git_host_package_unavailable');
    await send(entry.role, pack.body);
  }
  await send('activate');
}
export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<GitHostEnv>;
