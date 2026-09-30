import { createServer } from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

type Reply = {
  status: number;
  headers: Iterable<[string, string]> & { getSetCookie(): string[] };
  arrayBuffer(): Promise<ArrayBuffer>;
};
export async function journeyServer(
  dispatch: (
    url: string,
    init: { method: string; headers: Record<string, string>; body?: string },
  ) => Promise<Reply>,
) {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-journey-'));
  let server: ReturnType<typeof createServer> | undefined;
  try {
    await promisify(execFile)('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      join(directory, 'key.pem'),
      '-out',
      join(directory, 'cert.pem'),
      '-days',
      '1',
      '-subj',
      '/CN=mikaki.test',
      '-addext',
      'subjectAltName=DNS:mikaki.test,DNS:journey-rp.test',
    ]);
    server = createServer(
      {
        key: await readFile(join(directory, 'key.pem')),
        cert: await readFile(join(directory, 'cert.pem')),
      },
      async (incoming, outgoing) => {
        try {
          const url = new URL(`https://${incoming.headers.host}${incoming.url}`);
          if (!['mikaki.test', 'journey-rp.test'].includes(url.hostname)) {
            outgoing.writeHead(403);
            outgoing.end();
            return;
          }
          const headers: Record<string, string> = {};
          for (const [name, value] of Object.entries(incoming.headers)) {
            if (value !== undefined)
              headers[name] = Array.isArray(value) ? value.join('; ') : value;
          }
          const chunks: Buffer[] = [];
          let size = 0;
          for await (const chunk of incoming) {
            size += chunk.length;
            if (size > 1_048_576) {
              outgoing.writeHead(413);
              outgoing.end();
              return;
            }
            chunks.push(Buffer.from(chunk));
          }
          const response = await dispatch(url.href, {
            method: incoming.method ?? 'GET',
            headers,
            ...(chunks.length ? { body: Buffer.concat(chunks).toString('utf8') } : {}),
          });
          const replyHeaders: Record<string, string | string[]> = Object.fromEntries(
            response.headers,
          );
          const cookies = response.headers.getSetCookie();
          if (cookies.length) replyHeaders['set-cookie'] = cookies;
          const body = Buffer.from(await response.arrayBuffer());
          outgoing.writeHead(response.status, replyHeaders);
          outgoing.end(body);
        } catch {
          if (!outgoing.headersSent) outgoing.writeHead(500);
          if (!outgoing.destroyed) outgoing.end('local_journey_bridge_failed');
        }
      },
    );
    await new Promise<void>((resolve, reject) => {
      server!.once('error', reject);
      server!.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Journey server address missing');
    return {
      port: address.port,
      async close() {
        await new Promise<void>((resolve) => {
          server!.closeAllConnections();
          server!.close(() => resolve());
        });
        await rm(directory, { recursive: true });
      },
    };
  } catch (error) {
    server?.close();
    await rm(directory, { recursive: true });
    throw error;
  }
}
