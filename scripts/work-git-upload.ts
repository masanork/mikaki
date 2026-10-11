/** Bounded Git smart HTTP, explicit single POSTs and no redirects or retries. */
import { request as httpsRequest } from 'node:https';
import type { RequestOptions } from 'node:https';
import type { ClientRequest, IncomingMessage } from 'node:http';
import { localGit } from './work-git-disclosure.ts';
import type { GitPlan } from '../crates/work-effect-worker/protocol.ts';
export type GitHttp = (p: GitPlan, token: string, path: string, body?: Buffer) => Promise<Buffer>;
export type GitRequester = (
  url: string,
  options: RequestOptions,
  callback: (response: IncomingMessage) => void,
) => ClientRequest;
export function oneShotGitHttp(
  account: string,
  namespace: string,
  requester: GitRequester = httpsRequest,
): GitHttp {
  return (p, token, path, body) =>
    new Promise((resolve, reject) => {
      if (
        !/^[a-f0-9]{32}$/.test(account) ||
        !/^[a-z0-9-]{1,63}$/.test(namespace) ||
        !/^wk-[a-f0-9]{32}-(code|snapshot)$/.test(p.name) ||
        !/^(?:info\/refs\?service=git-(?:upload|receive)-pack|git-(?:upload|receive)-pack)$/.test(
          path,
        ) ||
        p.observation.expires_at <= Math.floor(Date.now() / 1000) + 5
      ) {
        reject(new Error('git_http_unavailable'));
        return;
      }
      const service = path.includes('receive') ? 'receive' : 'upload';
      const url = `https://${account}.artifacts.cloudflare.net/git/${namespace}/${p.name}.git/${path}`;
      const request = requester(
        url,
        {
          method: body ? 'POST' : 'GET',
          agent: false,
          rejectUnauthorized: true,
          headers: {
            Authorization: `Bearer ${token}`,
            ...(body
              ? {
                  'Content-Type': `application/x-git-${service}-pack-request`,
                  'Content-Length': String(body.length),
                }
              : {}),
          },
        },
        (response) => {
          const parts: Buffer[] = [];
          let size = 0;
          response.on('data', (part: Buffer) => {
            size += part.length;
            if (size > (body && service === 'upload' ? 70 * 1024 * 1024 : 1024 * 1024)) {
              response.destroy();
              reject(new Error('git_http_unavailable'));
            } else parts.push(part);
          });
          response.on('end', () =>
            response.statusCode === 200 &&
            response.headers['content-type'] ===
              `application/x-git-${service}-pack-${body ? 'result' : 'advertisement'}`
              ? resolve(Buffer.concat(parts))
              : reject(new Error('git_http_unavailable')),
          );
          response.on('error', () => reject(new Error('git_http_unavailable')));
        },
      );
      request.setTimeout(30000, () => request.destroy());
      const timer = setTimeout(() => request.destroy(), 30000);
      request.on('close', () => clearTimeout(timer));
      request.on('error', () => reject(new Error('git_http_unavailable')));
      request.end(body);
    });
}
export function packets(bytes: Buffer): (string | null)[] {
  let offset = 0;
  const lines: (string | null)[] = [];
  while (offset < bytes.length) {
    const prefix = bytes.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-f]{4}$/.test(prefix)) throw new Error('git_protocol_invalid');
    const n = parseInt(prefix, 16);
    offset += 4;
    if (n === 0) {
      lines.push(null);
      continue;
    }
    if (n < 4 || n > 65520 || offset + n - 4 > bytes.length)
      throw new Error('git_protocol_invalid');
    const body = bytes.subarray(offset, offset + n - 4);
    if (body.some((c) => c > 127)) throw new Error('git_protocol_invalid');
    lines.push(body.toString('ascii'));
    offset += n - 4;
  }
  return lines;
}
export function packet(text: string) {
  const b = Buffer.from(text);
  return Buffer.concat([Buffer.from((b.length + 4).toString(16).padStart(4, '0')), b]);
}
export async function uploadGitPack(p: GitPlan, token: string, dir: string, http: GitHttp) {
  const ad = packets(await http(p, token, 'info/refs?service=git-receive-pack'));
  if (
    ad.length !== 4 ||
    ad[0] !== '# service=git-receive-pack\n' ||
    ad[1] !== null ||
    ad[3] !== null ||
    typeof ad[2] !== 'string' ||
    !ad[2].startsWith(`${'0'.repeat(40)} capabilities^{}\0`) ||
    !ad[2]
      .slice(ad[2].indexOf('\0') + 1)
      .trim()
      .split(' ')
      .includes('report-status')
  )
    throw new Error('git_destination_not_empty');
  const pack = localGit(
    dir,
    ['pack-objects', '--stdout', '--revs', '--no-reuse-delta', '--no-reuse-object', '--window=0'],
    `${p.commit}\n`,
    {},
    70 * 1024 * 1024,
  );
  const ref = `refs/heads/${p.branch}`;
  const body = Buffer.concat([
    packet(`${'0'.repeat(40)} ${p.commit} ${ref}\0report-status\n`),
    Buffer.from('0000'),
    pack,
  ]);
  if (body.length > 70 * 1024 * 1024) throw new Error('git_pack_capacity');
  const result = packets(await http(p, token, 'git-receive-pack', body));
  if (
    result.length !== 3 ||
    result[0] !== 'unpack ok\n' ||
    result[1] !== `ok ${ref}\n` ||
    result[2] !== null
  )
    throw new Error('git_push_unconfirmed');
}
