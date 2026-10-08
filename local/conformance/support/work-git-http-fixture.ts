/** Loopback-only real Git smart HTTP. Synthetic credentials and bare repositories. */
import { spawn } from 'node:child_process';
import { createServer, request as httpRequest } from 'node:http';
import { oneShotGitHttp } from '../../../scripts/work-git-upload.ts';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { localGit } from '../../../scripts/work-git-disclosure.ts';
export async function gitHttpFixture(
  directory: string,
  authorize: (name: string, token: string, write: boolean) => Promise<boolean>,
) {
  const root = join(directory, 'synthetic-git');
  await mkdir(root, { recursive: true });
  const counts = { requests: 0, pushes: 0, fetches: 0 };
  let mode = 'normal';
  const initialized = new Set<string>();
  const repository = (name: string) => join(root, `${name}.git`);
  function ensure(name: string) {
    if (!initialized.has(name)) {
      localGit(repository(name), ['init', '--bare', '--quiet', '--template=']);
      localGit(repository(name), ['config', 'http.receivepack', 'true']);
      initialized.add(name);
    }
  }
  const server = createServer(async (req, res) => {
    try {
      counts.requests++;
      const url = new URL(req.url!, 'http://localhost');
      const match =
        /^\/git\/(wk-[a-f0-9]{32}-(?:code|snapshot))\.git\/(info\/refs|git-receive-pack|git-upload-pack)$/.exec(
          url.pathname,
        );
      const auth = req.headers.authorization;
      if (
        !match ||
        !auth ||
        !(await authorize(
          match[1]!,
          auth.slice(7),
          url.searchParams.get('service') === 'git-receive-pack' || match[2] === 'git-receive-pack',
        ))
      ) {
        res.writeHead(403);
        res.end();
        return;
      }
      if (mode === 'redirect') {
        res.writeHead(302, { Location: 'http://127.0.0.1:1/forbidden' });
        res.end();
        return;
      }
      if (mode === 'unavailable') {
        res.writeHead(503);
        res.end();
        return;
      }
      ensure(match[1]!);
      if (match[2] === 'git-receive-pack') counts.pushes++;
      if (match[2] === 'git-upload-pack') counts.fetches++;
      const child = spawn('git', ['http-backend'], {
        env: {
          PATH: process.env.PATH,
          LANG: 'C',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_PROJECT_ROOT: root,
          GIT_HTTP_EXPORT_ALL: '1',
          REQUEST_METHOD: req.method,
          PATH_INFO: `/${match[1]}.git/${match[2]}`,
          QUERY_STRING: url.search.slice(1),
          CONTENT_TYPE: req.headers['content-type'] ?? '',
          CONTENT_LENGTH: req.headers['content-length'] ?? '',
          REMOTE_USER: 'synthetic',
        },
        stdio: ['pipe', 'pipe', 'ignore'],
      });
      const parts: Buffer[] = [];
      let size = 0;
      child.stdout.on('data', (part: Buffer) => {
        size += part.length;
        if (size > 70 * 1024 * 1024) child.kill();
        else parts.push(part);
      });
      child.on('error', () => {
        res.writeHead(503);
        res.end();
      });
      child.on('close', () => {
        const bytes = Buffer.concat(parts),
          end = bytes.indexOf('\r\n\r\n');
        if (end < 0 || size > 70 * 1024 * 1024) {
          res.writeHead(503);
          res.end();
          return;
        }
        const headers: Record<string, string> = {};
        let status = 200;
        for (const line of bytes.subarray(0, end).toString().split('\r\n')) {
          const i = line.indexOf(':');
          const key = line.slice(0, i).toLowerCase(),
            value = line.slice(i + 1).trim();
          if (key === 'status') status = Number(value.split(' ')[0]);
          else headers[key] = value;
        }
        if (mode === 'push-lost' && match[2] === 'git-receive-pack') {
          res.destroy();
          return;
        }
        if (mode === 'readback-corrupt' && match[2] === 'git-upload-pack')
          bytes[bytes.length - 1] ^= 1;
        if (mode === 'push-malformed' && match[2] === 'git-receive-pack') {
          res.writeHead(status, headers);
          res.end('0005X0000');
          return;
        }
        res.writeHead(status, headers);
        res.end(bytes.subarray(end + 4));
      });
      req.pipe(child.stdin);
    } catch {
      res.writeHead(503);
      res.end();
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('git_fixture_listen_failed');
  const http = oneShotGitHttp('a'.repeat(32), 'mikaki-dev', (url, options, callback) => {
    const path = new URL(url).pathname.replace('/git/mikaki-dev/', '/git/') + new URL(url).search;
    return httpRequest(`http://127.0.0.1:${address.port}${path}`, options, callback);
  });
  return {
    http,
    counts,
    repository,
    ensure,
    setMode(value: string) {
      mode = value;
    },
    async close() {
      await new Promise<void>((resolve, reject) =>
        server.close((e) => (e ? reject(e) : resolve())),
      );
    },
  };
}
