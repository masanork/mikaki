// Host HTTPS adapter executes the same reqwest retrieval/delivery code as the native app.
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { promisify } from 'node:util';
let built = false;
type Request = { claims: any; jwt: string };
export async function withNativePresentationHttp(
  run: (http: {
    uri: (path: string) => string;
    command: (command: unknown) => Promise<any>;
    onRequest: (handler: (form: [string, string][]) => Promise<Request>) => void;
    onResponse: (handler: (response: string) => Promise<unknown>) => void;
    requests: Request[];
  }) => Promise<void>,
) {
  const cwd = new URL('../../..', import.meta.url).pathname;
  if (!built) {
    execFileSync(
      'cargo',
      [
        'build',
        '-q',
        '--manifest-path',
        'design/probes/native-identity-http/Cargo.toml',
        '--bin',
        'oid4vp_transport',
        '--locked',
        '--offline',
      ],
      { cwd, timeout: 90000 },
    );
    built = true;
  }
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-vp-https-'));
  const cert = join(directory, 'tls.pem');
  const key = join(directory, 'tls.key');
  const ca = join(directory, 'ca.pem');
  const caKey = join(directory, 'ca.key');
  const csr = join(directory, 'tls.csr');
  const ext = join(directory, 'tls.ext');
  const openssl = async (args: string[]) =>
    promisify(execFile)('openssl', [args[0], '-sha256', ...args.slice(1)]);
  await openssl([
    'req',
    '-new',
    '-x509',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-pkeyopt',
    'ec_param_enc:named_curve',
    '-nodes',
    '-days',
    '1',
    '-subj',
    '/CN=Disposable HTTPS CA',
    '-addext',
    'basicConstraints=critical,CA:TRUE,pathlen:0',
    '-addext',
    'keyUsage=critical,keyCertSign',
    '-keyout',
    caKey,
    '-out',
    ca,
  ]);
  await openssl([
    'req',
    '-new',
    '-newkey',
    'ec',
    '-pkeyopt',
    'ec_paramgen_curve:P-256',
    '-pkeyopt',
    'ec_param_enc:named_curve',
    '-nodes',
    '-subj',
    '/CN=Disposable loopback HTTPS server',
    '-keyout',
    key,
    '-out',
    csr,
  ]);
  await writeFile(
    ext,
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n',
    { mode: 0o600 },
  );
  await openssl([
    'x509',
    '-req',
    '-in',
    csr,
    '-CA',
    ca,
    '-CAkey',
    caKey,
    '-set_serial',
    '2',
    '-days',
    '1',
    '-extfile',
    ext,
    '-out',
    cert,
  ]);
  let requestHandler: ((form: [string, string][]) => Promise<Request>) | undefined;
  let responseHandler: ((response: string) => Promise<unknown>) | undefined;
  const requests: Request[] = [];
  const failures: unknown[] = [];
  let redirectHits = 0;
  const server = createServer(
    { cert: await readFile(cert), key: await readFile(key) },
    async (req, res) => {
      try {
        assert.equal(req.method, 'POST');
        assert.match(req.headers['content-type']!, /^application\/x-www-form-urlencoded/);
        let body = '';
        for await (const chunk of req) {
          body += chunk.toString();
          assert.ok(body.length <= 96 * 1024);
        }
        const form = new URLSearchParams(body);
        if (req.url === '/stall') {
          return;
        }
        if (req.url === '/redirect') {
          res.writeHead(302, { Location: '/trap' }).end();
          return;
        }
        if (req.url === '/trap') {
          redirectHits++;
          res.writeHead(500).end();
          return;
        }
        if (req.url === '/reject') {
          res.writeHead(400).end();
          return;
        }
        if (req.url === '/wrong-type') {
          res.writeHead(200, { 'Content-Type': 'text/plain' }).end('jwt');
          return;
        }
        if (req.url === '/oversize') {
          res.writeHead(200, { 'Content-Type': 'application/oauth-authz-req+jwt' });
          // Chunked, without Content-Length: exercises streaming byte bounds.
          res.write('A'.repeat(12 * 1024));
          res.end('A'.repeat(8 * 1024));
          return;
        }
        if (req.url === '/invalid-utf8') {
          res
            .writeHead(200, { 'Content-Type': 'application/oauth-authz-req+jwt' })
            .end(Buffer.from([0xff]));
          return;
        }
        if (req.url === '/fixture') {
          res.writeHead(200, { 'Content-Type': 'application/oauth-authz-req+jwt' }).end('fixture');
          return;
        }
        if (req.url === '/request') {
          assert.equal(req.headers.accept, 'application/oauth-authz-req+jwt');
          assert.ok(requestHandler);
          const request = await requestHandler([...form.entries()]);
          requests.push(request);
          res
            .writeHead(200, { 'Content-Type': 'application/oauth-authz-req+jwt; charset=UTF-8' })
            .end(request.jwt);
          return;
        }
        if (req.url === '/response') {
          assert.deepEqual([...form.keys()], ['response']);
          assert.ok(responseHandler);
          await responseHandler(form.get('response')!);
          res.writeHead(200, { 'Content-Type': 'application/json' }).end('{}');
          return;
        }
        throw Error('unknown fixture route');
      } catch (error) {
        failures.push(error);
        res.writeHead(500).end();
      }
    },
  );
  // Make the peer close an idle connection while the stdio adapter waits for input.
  server.keepAliveTimeout = 100;
  server.keepAliveTimeoutBuffer = 0;
  const child = spawn(
    `${cwd}/design/probes/native-identity-http/target/debug/oid4vp_transport`,
    [],
    { cwd, stdio: ['pipe', 'pipe', 'pipe'] },
  );
  const closed = once(child, 'close');
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  let errors = '';
  child.stderr.on('data', (chunk) => {
    errors = (errors + String(chunk)).slice(-4096);
  });
  const deadline = setTimeout(() => child.kill(), 60000);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const uri = (path: string) => `https://127.0.0.1:${address.port}${path}`;
    child.stdin.write(JSON.stringify({ tls_ca: await readFile(ca, 'utf8') }) + '\n');
    const command = async (command: unknown) => {
      child.stdin.write(JSON.stringify(command) + '\n');
      const line = await lines.next();
      assert.equal(line.done, false, `Native HTTP adapter exited: ${errors}`);
      assert.ok(line.value.length <= 96 * 1024);
      return JSON.parse(line.value);
    };
    for (const path of ['/redirect', '/wrong-type', '/oversize', '/invalid-utf8']) {
      assert.deepEqual(
        await command({ command: 'retrieve', uri: uri(path), form: [] }),
        {
          error: 'invalid_response',
        },
        `${path}: ${errors}`,
      );
    }
    for (const path of ['/redirect', '/reject']) {
      assert.deepEqual(await command({ command: 'deliver', uri: uri(path), response: 'fixture' }), {
        error: 'presentation_rejected',
      });
    }
    assert.deepEqual(
      await command({ command: 'retrieve', uri: uri('/request'), form: [], untrusted_tls: true }),
      { error: 'network_error' },
    );
    assert.deepEqual(await command({ command: 'retrieve', uri: uri('/stall'), form: [] }), {
      error: 'network_error',
    });
    const fixture = { command: 'retrieve', uri: uri('/fixture'), form: [] };
    assert.deepEqual(await command(fixture), { jwt: 'fixture' });
    await new Promise((resolve) => setTimeout(resolve, 250));
    assert.deepEqual(
      await command(fixture),
      { jwt: 'fixture' },
      'retrieval after the HTTPS peer closes an idle connection',
    );
    await run({
      uri,
      command,
      onRequest: (handler) => {
        requestHandler = handler;
      },
      onResponse: (handler) => {
        responseHandler = handler;
      },
      requests,
    });
    assert.equal(redirectHits, 0);
    assert.deepEqual(failures, []);
    child.stdin.end(JSON.stringify({ command: 'finish' }) + '\n');
    const [code] = await closed;
    assert.equal(code, 0, errors);
  } finally {
    clearTimeout(deadline);
    if (child.exitCode === null) child.kill();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
  }
}
