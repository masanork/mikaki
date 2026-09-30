// Local dev-mode OIDF suite only. Never use this TLS exception for remote services.
import { request } from 'node:https';
import { writeFile } from 'node:fs/promises';

export const generated = new URL('../../../local/generated/', import.meta.url);
export type RunInfo = { status: string; result: string | null };
export type RunState = { exposed?: Record<string, string> };
export type ModuleResult = RunInfo & { name: string; id: string };

export async function localSuite(path: string, body?: unknown, method = body ? 'POST' : 'GET') {
  return localRequest(`https://localhost:8443${path}`, body, method);
}

export async function localRequest(url: string, body?: unknown, method = body ? 'POST' : 'GET') {
  const target = new URL(url);
  if (
    target.protocol !== 'https:' ||
    target.port !== '8443' ||
    !['localhost', 'suite-frontend'].includes(target.hostname)
  )
    throw new Error('Only the local OIDF suite is allowed');
  target.hostname = 'localhost';
  const encoded = body === undefined ? undefined : JSON.stringify(body);
  return new Promise<any>((resolve, reject) => {
    const req = request(
      target,
      {
        method,
        rejectUnauthorized: false,
        headers: encoded ? { 'content-type': 'application/json' } : {},
        timeout: 30_000,
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > 16 * 1024 * 1024) req.destroy(new Error('Oversized suite response'));
          else chunks.push(chunk);
        });
        response.on('end', async () => {
          if ((response.statusCode ?? 500) >= 400) {
            await writeFile(
              new URL('oidf-credential-api-error.json', generated),
              Buffer.concat(chunks),
              { mode: 0o600 },
            );
            return reject(
              new Error(`Local suite ${method} ${target.pathname}: HTTP ${response.statusCode}`),
            );
          }
          try {
            const text = Buffer.concat(chunks).toString('utf8');
            resolve(text ? JSON.parse(text) : null);
          } catch {
            reject(new Error('Invalid local suite JSON'));
          }
        });
        response.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(new Error('Local suite timeout')));
    req.on('error', reject);
    req.end(encoded);
  });
}

export async function saveRun(planId: string, name: string, id: string): Promise<ModuleResult> {
  const info: RunInfo = await localSuite(`/api/info/${id}`);
  const log = await localSuite(`/api/log/${id}?pretty=true`);
  // Raw logs can contain fixture keys and credentials. Keep them ignored and private.
  await writeFile(
    new URL(`oidf-credential-${name}-${id}.json`, generated),
    JSON.stringify({ planId, id, info, log }, null, 2),
    { mode: 0o600 },
  );
  return { name, id, status: info.status, result: info.result };
}

export const finished = (info: RunInfo) =>
  ['FINISHED', 'INTERRUPTED', 'FAILED', 'SKIPPED'].includes(info.status);
export const pause = () => new Promise((resolve) => setTimeout(resolve, 1000));
