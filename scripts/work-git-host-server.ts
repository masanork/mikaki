/** Linux-only private port. The Worker binding is the ingress authority. */
import { createServer } from 'node:http';
import { fixedGitExecutor } from './work-git-executor.ts';
import { loadGitRegistry } from './work-git-registry.ts';
import type { GitHttp } from './work-git-upload.ts';
import { gitPlan } from '../crates/work-effect-worker/protocol.ts';

export async function gitHostServer(
  config: {
    account: string;
    namespace: string;
    authority: string;
    directory: string;
    registrySha256: string;
    temporaryParent: string;
  },
  http?: GitHttp,
) {
  const loaded = await loadGitRegistry(
    config.directory,
    config.registrySha256,
    config.temporaryParent,
  );
  const execute = fixedGitExecutor(
    { ...config, registered: loaded.registered, temporaryDirectory: loaded.temporaryDirectory },
    http,
  );
  let busy = false;
  // Covers duplicate TCP deliveries within this process. The Durable Object
  // retains the corresponding slots across process/image restarts.
  const dispatched = new Set<string>();
  const server = createServer(
    { maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000 },
    async (req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      try {
        if (req.method === 'GET' && req.url === '/ready') {
          res.setHeader('Content-Type', 'application/json');
          res.end(
            JSON.stringify({
              registry_sha256: config.registrySha256,
              disclosure_digest: loaded.registry.disclosure_digest,
            }),
          );
          return;
        }
        if (req.method !== 'POST' || req.url !== '/git-execute') {
          res.writeHead(404).end();
          return;
        }
        const auth = req.headers.authorization;
        if (
          busy ||
          req.headersDistinct.authorization?.length !== 1 ||
          !auth ||
          !/^Bearer [\x21-\x7e]{16,4096}$/.test(auth) ||
          req.headers['content-type'] !== 'application/json'
        )
          throw new Error('git_denied');
        busy = true;
        try {
          const parts: Buffer[] = [];
          let size = 0;
          for await (const raw of req) {
            const part = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
            size += part.length;
            if (size > 4096) throw new Error('git_denied');
            parts.push(part);
          }
          const body = Buffer.concat(parts);
          const p: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
          gitPlan(p);
          const slot = p.role + ':' + p.purpose;
          if (
            p.artifacts_account !== config.account ||
            p.namespace !== config.namespace ||
            p.checkpoint.authority !== config.authority ||
            p.disclosure_digest !== loaded.registry.disclosure_digest ||
            dispatched.has(slot)
          )
            throw new Error('git_denied');
          dispatched.add(slot);
          const response = await execute(
            new Request('https://private.invalid/git-execute', {
              method: 'POST',
              headers: { Authorization: auth, 'Content-Type': 'application/json' },
              body,
            }),
          );
          res.writeHead(response.status, { 'Content-Type': 'application/json' });
          res.end(Buffer.from(await response.arrayBuffer()));
        } finally {
          busy = false;
        }
      } catch {
        if (!res.headersSent) res.writeHead(409);
        res.end();
      }
    },
  );
  return {
    server,
    registry: loaded.registry,
    async close() {
      await new Promise<void>((resolve, reject) =>
        server.close((e) =>
          e && !('code' in e && e.code === 'ERR_SERVER_NOT_RUNNING') ? reject(e) : resolve(),
        ),
      );
      await loaded.close();
    },
  };
}
