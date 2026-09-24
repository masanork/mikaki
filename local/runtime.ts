// Trusted local runner. It creates ephemeral keys/storage; there is no HTTP bootstrap endpoint.
import { createTestHarness } from 'wrangler';
import { createServer } from 'node:http';
import type { Server } from 'node:http';
import { Readable } from 'node:stream';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, exportJWK } from 'jose';
import { OP, RP, CLIENT, p, random, hash, now, sqlParts } from './shared.ts';

export async function startLocal({ scheduler = true } = {}) {
  async function keys(kid: string) {
    const pair = await generateKeyPair('ES256', { extractable: true });
    return {
      private: JSON.stringify({
        ...(await exportJWK(pair.privateKey)),
        kid,
        alg: 'ES256',
        use: 'sig',
      }),
      public: JSON.stringify({
        ...(await exportJWK(pair.publicKey)),
        kid,
        alg: 'ES256',
        use: 'sig',
      }),
    };
  }
  const opKeys = await keys('local-op-1'),
    rpKeys = await keys('local-rp-1');
  const publicVars = {
    LOCAL_ONLY: 'true',
    OP_PUBLIC_JWK: opKeys.public,
    RP_PUBLIC_JWK: rpKeys.public,
  };
  const servers: Server[] = [];
  let harness: ReturnType<typeof createTestHarness> | undefined;
  const timers: NodeJS.Timeout[] = [],
    pending = new Set();
  const close = async () => {
    for (const timer of timers) clearInterval(timer);
    await Promise.allSettled([...pending]);
    await Promise.all(
      servers.map(
        (s) =>
          new Promise((resolve) => {
            s.closeAllConnections();
            s.close(resolve);
          }),
      ),
    );
    await harness?.close();
  };
  try {
    harness = createTestHarness({
      root: fileURLToPath(new URL('..', import.meta.url)),
      workers: [
        {
          configPath: 'local/wrangler.op.jsonc',
          vars: publicVars,
          secrets: { OP_PRIVATE_JWK: opKeys.private },
        },
        {
          configPath: 'local/wrangler.rp.jsonc',
          vars: publicVars,
          secrets: { RP_PRIVATE_JWK: rpKeys.private },
        },
      ],
    });
    await harness.listen();
    const op = harness.getWorker('mikaki-local-op'),
      rp = harness.getWorker('mikaki-local-rp');
    const opEnv = await op.getEnv(),
      rpEnv = await rp.getEnv();
    async function schema(db: typeof opEnv.DB, name: string) {
      const source = await readFile(new URL(name, import.meta.url), 'utf8');
      for (const statement of sqlParts(source)) await db.prepare(statement).run();
    }
    await schema(opEnv.DB, '../design/sql/oidc-critical-schema.sql');
    await schema(opEnv.DB, 'schema.sql');
    await schema(rpEnv.DB, 'rp-schema.sql');
    const invitation = random();
    await opEnv.DB.batch([
      opEnv.DB.prepare('INSERT INTO client VALUES(?,1,1)').bind(CLIENT),
      opEnv.DB.prepare('INSERT INTO client_key VALUES(?,?,1,1)').bind(CLIENT, 'local-rp-1'),
      opEnv.DB.prepare("INSERT INTO signing_key VALUES('local-op-1',1,1)"),
      opEnv.DB.prepare("INSERT INTO invitation VALUES(?,'bootstrap',?,NULL)").bind(
        await hash(invitation),
        now() + p('registration.bootstrap_invitation_ttl'),
      ),
    ]);
    // Loopback HTTP frontends preserve distinct browser origins. No request URLs/bodies are logged.
    async function listen(origin: string, worker: typeof op) {
      const server = createServer(async (incoming, outgoing) => {
        try {
          if (incoming.headers.host !== new URL(origin).host) {
            outgoing.writeHead(403);
            outgoing.end('local_only');
            return;
          }
          const headers: Record<string, string> = {};
          for (const [name, value] of Object.entries(incoming.headers)) {
            if (Array.isArray(value))
              headers[name] = value.join(name.toLowerCase() === 'cookie' ? '; ' : ', ');
            else if (value !== undefined) headers[name] = value;
          }
          const result = await worker.fetch(new URL(incoming.url ?? '/', origin).href, {
            method: incoming.method,
            headers,
            redirect: 'manual',
            ...(!['GET', 'HEAD'].includes(incoming.method ?? 'GET')
              ? { body: Readable.toWeb(incoming), duplex: 'half' }
              : {}),
          });
          outgoing.writeHead(result.status, Object.fromEntries(result.headers));
          if (result.body) Readable.fromWeb(result.body).pipe(outgoing);
          else outgoing.end();
        } catch {
          outgoing.writeHead(500);
          outgoing.end('local_runtime_error');
        }
      });
      servers.push(server);
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(Number(new URL(origin).port), '127.0.0.1', () => resolve(undefined));
      });
    }
    await listen(OP, op);
    await listen(RP, rp);
    // The harness does not fire cron automatically. The policy controls local
    // intervals; cron strings route to the corresponding Worker handler.
    function schedule(workers: Array<typeof op>, cron: string, seconds: number) {
      let running = false;
      timers.push(
        setInterval(() => {
          if (running) return;
          running = true;
          const task = Promise.all(
            workers.map((worker) => worker.scheduled({ cron, scheduledTime: new Date() })),
          )
            .catch(() => console.error('local_scheduler_failed'))
            .finally(() => {
              running = false;
              pending.delete(task);
            });
          pending.add(task);
        }, seconds * 1000),
      );
    }
    if (scheduler) {
      schedule([op], '* * * * *', p('logout_delivery.scheduler_interval'));
      schedule([op, rp], '0 * * * *', p('retention.gc_interval'));
    }
    return {
      op,
      rp,
      opDB: opEnv.DB,
      rpDB: rpEnv.DB,
      invitation,
      opKeys,
      rpKeys,
      close,
      logs: () => harness!.getLogs(),
    };
  } catch (error) {
    await close();
    throw error;
  }
}
