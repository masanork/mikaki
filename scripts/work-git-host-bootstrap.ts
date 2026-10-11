/** Ephemeral source provisioning. No credentials or source data in image layers. */
import { createServer } from 'node:http';
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { gitRegistrySchema } from '../crates/work-git-host-worker/registry.ts';
import type { GitRegistry } from '../crates/work-git-host-worker/registry.ts';
import { gitHostServer } from './work-git-host-server.ts';
import type { GitHttp } from './work-git-upload.ts';

export async function gitHostBootstrap(
  config: {
    account: string;
    namespace: string;
    authority: string;
    registrySha256: string;
    temporaryParent: string;
  },
  http?: GitHttp,
) {
  if (
    !/^[a-f0-9]{32}$/.test(config.account) ||
    !/^[a-z0-9-]{1,63}$/.test(config.namespace) ||
    !/^[A-Za-z0-9_.:-]{1,128}$/.test(config.authority) ||
    !/^[a-f0-9]{64}$/.test(config.registrySha256)
  )
    throw new Error('git_host_configuration_invalid');
  const directory = await mkdtemp(join(config.temporaryParent, 'git-provision-'));
  let registry: GitRegistry | undefined,
    host: Awaited<ReturnType<typeof gitHostServer>> | undefined,
    busy = false;
  const server = createServer(
    { maxHeaderSize: 8192, requestTimeout: 30000, headersTimeout: 5000 },
    async (req, res) => {
      res.setHeader('Cache-Control', 'no-store');
      try {
        if (req.method === 'GET' && req.url === '/health') {
          res.writeHead(200).end();
          return;
        }
        if (host && (req.url === '/ready' || req.url === '/git-execute')) {
          host.server.emit('request', req, res);
          return;
        }
        if (req.method === 'GET' && req.url === '/ready') {
          res.writeHead(503).end();
          return;
        }
        if (
          req.method !== 'POST' ||
          ![
            '/provision/registry',
            '/provision/task',
            '/provision/snapshot',
            '/provision/activate',
          ].includes(req.url ?? '')
        ) {
          res.writeHead(404).end();
          return;
        }
        if (busy || host || req.headers.authorization) throw new Error('git_host_provision_denied');
        busy = true;
        try {
          if (req.url === '/provision/activate') {
            for await (const part of req)
              if (part.length) throw new Error('git_host_provision_denied');
            if (!registry) throw new Error('git_host_provision_denied');
            host = await gitHostServer({ ...config, directory }, http);
          } else if (req.url === '/provision/registry') {
            const parts: Buffer[] = [];
            let size = 0;
            for await (const part of req) {
              size += part.length;
              if (size > 4096) throw new Error('git_host_provision_denied');
              parts.push(Buffer.from(part));
            }
            const bytes = Buffer.concat(parts);
            if (
              registry ||
              createHash('sha256').update(bytes).digest('hex') !== config.registrySha256
            )
              throw new Error('git_host_provision_denied');
            const parsed = gitRegistrySchema.parse(
              JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
            );
            await writeFile(join(directory, 'registry.json'), bytes, { mode: 0o600, flag: 'wx' });
            registry = parsed;
          } else {
            const role = req.url === '/provision/task' ? 'task' : 'snapshot',
              entry = registry?.entries.find((e) => e.role === role);
            if (!entry) throw new Error('git_host_provision_denied');
            const path = join(directory, role + '.pack'),
              file = await open(path, 'wx', 0o600);
            try {
              const digest = createHash('sha256');
              let size = 0;
              for await (const raw of req) {
                const part = Buffer.from(raw);
                size += part.length;
                if (size > entry.pack_bytes) throw new Error('git_host_provision_denied');
                digest.update(part);
                await file.writeFile(part);
              }
              if (size !== entry.pack_bytes || digest.digest('hex') !== entry.pack_sha256)
                throw new Error('git_host_provision_denied');
              await file.sync();
            } catch (e) {
              await file.close();
              await rm(path, { force: true });
              throw e;
            }
            await file.close();
          }
          res.writeHead(204).end();
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
    async close() {
      await new Promise<void>((resolve, reject) =>
        server.close((e) => (e ? reject(e) : resolve())),
      );
      await host?.close();
      await rm(directory, { recursive: true, force: true });
    },
  };
}
