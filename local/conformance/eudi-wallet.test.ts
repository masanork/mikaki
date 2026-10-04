import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { createServer } from 'node:https';
import { createHash, X509Certificate } from 'node:crypto';
import { decodeJwt, decodeProtectedHeader, type JWK } from 'jose';
import { issuedWalletVerifier } from './support/issued-wallet-presentation.ts';
import { decodeCbor, embedded, field } from './support/mdoc-test.ts';

const checkout = process.env.MIKAKI_EUDI_CHECKOUT;
const commit = '7129ed52ab5f39d657f3c48cd595d5343c7f420c';
const run = promisify(execFile);
test(
  'pinned eudi-dev strict HAIP Wallet retrieves signed requests and posts independently verified encrypted SD-JWT/mdoc responses',
  { skip: !checkout, timeout: 180000 },
  async () => {
    assert.ok(checkout!.startsWith('/private/tmp/'));
    assert.equal(
      (await run('git', ['rev-parse', 'HEAD'], { cwd: checkout })).stdout.trim(),
      commit,
    );
    assert.equal(
      (
        await run('git', ['status', '--porcelain', '--untracked-files=no'], { cwd: checkout })
      ).stdout.trim(),
      '',
    );
    const directory = await mkdtemp(join(tmpdir(), 'mikaki-eudi-http-'));
    const env = { ...process.env, EUDI_DEV_HOME: directory };
    const binary = join(directory, 'eudi');
    const cli = async (args: string[]) => {
      try {
        return await run(
          binary,
          [...args, '--wallet-dir', join(directory, 'wallet'), '--remote', 'local', '--no-color'],
          { env, timeout: 45000, maxBuffer: 256 * 1024 },
        );
      } catch {
        throw new Error(`eudi-dev ${args[0]} ${args[1]} failed`);
      }
    };
    let server: ReturnType<typeof createServer> | undefined;
    try {
      await run('go', ['build', '-o', binary, '.'], {
        cwd: checkout,
        timeout: 120000,
        maxBuffer: 65536,
      });
      await run('openssl', [
        'req',
        '-new',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        join(directory, 'tls.key'),
        '-out',
        join(directory, 'tls.pem'),
        '-days',
        '1',
        '-subj',
        '/CN=127.0.0.1',
        '-addext',
        'subjectAltName=IP:127.0.0.1',
      ]);
      let current:
        | {
            jwt: string;
            path: string;
            response: string;
            peer: Awaited<ReturnType<typeof issuedWalletVerifier>>;
            claims: Parameters<Awaited<ReturnType<typeof issuedWalletVerifier>>['accept']>[1];
            holder: JWK;
          }
        | undefined;
      let gets = 0;
      let posts = 0;
      const failures: unknown[] = [];
      server = createServer(
        {
          key: await readFile(join(directory, 'tls.key')),
          cert: await readFile(join(directory, 'tls.pem')),
        },
        async (req, res) => {
          try {
            assert.ok(current);
            if (req.method === 'GET' && req.url === current.path) {
              gets++;
              res
                .writeHead(200, {
                  'Content-Type': 'application/oauth-authz-req+jwt',
                  'Cache-Control': 'no-store',
                })
                .end(current.jwt);
            } else if (req.method === 'POST' && req.url === current.response) {
              posts++;
              assert.equal(
                req.headers['content-type']?.split(';')[0],
                'application/x-www-form-urlencoded',
              );
              let bytes = '';
              for await (const chunk of req) {
                bytes += String(chunk);
                assert.ok(Buffer.byteLength(bytes) <= 96 * 1024);
              }
              const form = new URLSearchParams(bytes);
              assert.deepEqual([...form.keys()], ['response']);
              const values = await current.peer.accept(
                form.get('response')!,
                current.claims,
                current.holder,
              );
              assert.deepEqual(values, { name: 'Fixture Person', birthdate: '1990-02-28' });
              res
                .writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
                .end('{}');
            } else {
              res.writeHead(404).end();
            }
          } catch (error) {
            failures.push(error);
            res.writeHead(400).end();
          }
        },
      );
      await new Promise<void>((resolve, reject) => {
        server!.once('error', reject);
        server!.listen(0, '127.0.0.1', resolve);
      });
      const address = server.address();
      assert.ok(address && typeof address !== 'string');
      const origin = `https://127.0.0.1:${address.port}`;
      const formats: string[] = [];
      for (const format of ['dc+sd-jwt', 'mso_mdoc']) {
        const issued = await cli([
          'issue',
          format === 'dc+sd-jwt' ? 'sdjwt' : 'mdoc',
          '--wallet',
          '--exp',
          '5m',
          '--claims',
          JSON.stringify({
            name: 'Fixture Person',
            birthdate: '1990-02-28',
            address: 'Private fixture address',
            gender: '1',
            document_kind: 'my_number_card',
          }),
          ...(format === 'dc+sd-jwt'
            ? ['--vct', 'https://localhost:8086/types/linked-document']
            : [
                '--doc-type',
                'app.tossa.mikaki.linked_document.1',
                '--namespace',
                'app.tossa.mikaki.linked_document.1',
              ]),
        ]);
        const raw = issued.stdout.trim();
        let holder: JWK;
        let issuerKey: JWK;
        let issuer: string;
        if (format === 'dc+sd-jwt') {
          const jwt = raw.split('~')[0];
          const payload = decodeJwt(jwt);
          holder = (payload.cnf as { jwk: JWK }).jwk;
          issuerKey = new X509Certificate(
            Buffer.from(decodeProtectedHeader(jwt).x5c![0], 'base64'),
          ).publicKey.export({ format: 'jwk' });
          issuer = String(payload.iss);
          assert.equal(payload.vct, `${issuer}/types/linked-document`);
        } else {
          const signed = decodeCbor(Buffer.from(raw, 'base64url'));
          const auth = field(signed, 'issuerAuth') as any[];
          issuerKey = new X509Certificate(field(auth[1], 33) as Buffer).publicKey.export({
            format: 'jwk',
          });
          const mso = embedded(decodeCbor(auth[2]));
          const key = field(field(mso, 'deviceKeyInfo'), 'deviceKey');
          holder = {
            kty: 'EC',
            crv: 'P-256',
            x: (field(key, -2) as Buffer).toString('base64url'),
            y: (field(key, -3) as Buffer).toString('base64url'),
          };
          issuer = 'https://localhost:8086';
        }
        const root = new X509Certificate((await cli(['wallet', 'ca-cert'])).stdout).raw.toString(
          'base64',
        );
        const response = `/response/${formats.length}`;
        const peer = await issuedWalletVerifier(
          format,
          issuer,
          issuerKey,
          root,
          `${origin}${response}`,
        );
        const request = await peer.request();
        current = { ...request, path: `/request/${formats.length}`, response, peer, holder };
        const invoke = async (clientId = peer.registry.client_id) =>
          cli([
            'wallet',
            'accept',
            `openid4vp://authorize?${new URLSearchParams({ client_id: clientId, request_uri: `${origin}${current!.path}` })}`,
            '--auto-accept',
            '--haip',
            '--mode',
            'strict',
            '--no-open',
            '--port',
            '0',
          ]);
        const startGets = gets;
        const startPosts = posts;
        await invoke();
        assert.equal(gets, startGets + 1, 'request_uri must be fetched once');
        assert.equal(posts, startPosts + 1, 'one encrypted HTTP response');
        assert.deepEqual(failures, []);
        // Invalid request signatures and outer client-id substitution must remain silent on direct_post.
        const original = current.jwt;
        const pieces = original.split('.');
        const signature = Buffer.from(pieces[2], 'base64url');
        signature[0] ^= 1;
        current.jwt = `${pieces[0]}.${pieces[1]}.${signature.toString('base64url')}`;
        await assert.rejects(invoke());
        assert.equal(gets, startGets + 2);
        assert.equal(posts, startPosts + 1);
        current.jwt = original;
        await assert.rejects(invoke(`x509_hash:${Buffer.alloc(32, 9).toString('base64url')}`));
        assert.equal(gets, startGets + 3);
        assert.equal(posts, startPosts + 1);
        assert.deepEqual(failures, []);
        formats.push(format);
      }
      assert.deepEqual(formats, ['dc+sd-jwt', 'mso_mdoc']);
      await writeFile(
        'local/generated/eudi-wallet-summary.json',
        JSON.stringify(
          {
            version: 1,
            observed_at: new Date().toISOString(),
            wallet_version: 'v2.3.7',
            wallet_commit: commit,
            binary_sha256: createHash('sha256')
              .update(await readFile(binary))
              .digest('hex'),
            qualification: 'host_cli_http_interop',
            formats,
            encrypted_responses: posts,
            silent_rejections: 4,
            mode: 'strict',
            haip_checks: true,
            issuance_from_mikaki: 'not_run',
            physical_e2e: 'not_run',
          },
          null,
          2,
        ) + '\n',
      );
    } finally {
      if (server) {
        server.closeAllConnections();
        await new Promise<void>((resolve) => server!.close(() => resolve()));
      }
      await rm(directory, { recursive: true, force: true });
    }
  },
);
