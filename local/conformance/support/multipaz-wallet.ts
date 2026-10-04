import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { copyFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { promisify } from 'node:util';
import { decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify } from 'jose';
import type { JWK } from 'jose';
import { verifyMdocIssuer } from './mdoc-test.ts';
import {
  verifyMultipazIssuedPresentation,
  type MultipazChallenge,
} from './multipaz-issued-presentation.ts';

export const multipazCommit = 'b741acd1f2a77ffbe2818b71822841781dd7ad9f';

/** Only the SDK's HTTP transport is bridged. Protocol and key handling stay upstream. */
export async function receiveWithMultipaz(
  worker: {
    fetch: (
      url: string,
      options?: {
        method?: string;
        headers?: Record<string, string>;
        redirect?: 'manual';
        body?: string | Buffer;
      },
    ) => Promise<{
      status: number;
      headers: Iterable<[string, string]> & { get(name: string): string | null };
      text(): Promise<string>;
      arrayBuffer(): Promise<ArrayBuffer>;
    }>;
  },
  document: string,
  issuerKey: JWK,
) {
  const checkout = process.env.MIKAKI_MULTIPAZ_CHECKOUT;
  if (!checkout) return;
  assert.ok(checkout.startsWith('/private/tmp/'), 'Use a disposable checkout in /private/tmp');
  const { stdout } = await promisify(execFile)('git', ['rev-parse', 'HEAD'], { cwd: checkout });
  assert.equal(stdout.trim(), multipazCommit, 'Multipaz version must match the pinned SDK');
  const tracked = await promisify(execFile)(
    'git',
    ['status', '--porcelain', '--untracked-files=no'],
    { cwd: checkout },
  );
  assert.equal(tracked.stdout.trim(), '', 'Upstream tracked SDK sources must be unmodified');
  await copyFile(
    new URL('../multipaz/MikakiIssuanceTest.kt', import.meta.url),
    `${checkout}/multipaz/src/jvmTest/kotlin/org/multipaz/provisioning/openid4vci/MikakiIssuanceTest.kt`,
  );
  const secret = randomBytes(32).toString('base64url');
  const root = 'https://issuer.example';
  const issuer = `${root}/identity/issuer`;
  const verified = new Set<string>();
  const presented = new Set<string>();
  const pending = new Map<
    string,
    { challenge: MultipazChallenge; holder: JWK; values: Record<string, unknown> }
  >();
  const challenged = new Set<string>();
  const asNonces = new Set<string>();
  let nonceBoundTokens = 0;
  const allowed = new Set([
    '/.well-known/openid-credential-issuer/identity/issuer',
    '/.well-known/oauth-authorization-server/identity/issuer',
    '/identity/issuer/par',
    '/identity/issuer/token',
    '/identity/issuer/nonce',
    '/identity/issuer/credential',
    '/identity/issuer/jwks',
  ]);
  const failures: Error[] = [];
  const server = createServer(async (req, res) => {
    try {
      const supplied = Buffer.from(req.headers.authorization ?? '');
      const expected = Buffer.from(`Bearer ${secret}`);
      assert.ok(supplied.length === expected.length && timingSafeEqual(supplied, expected));
      assert.equal(req.method, 'POST');
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        assert.ok(size <= 256 * 1024);
        chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      let result: unknown;
      if (req.url === '/fetch') {
        const url = new URL(body.url);
        assert.equal(url.origin, root);
        assert.ok(allowed.has(url.pathname), `Unexpected SDK endpoint ${url.pathname}`);
        const response = await worker.fetch(url.href, {
          method: body.method,
          headers: body.headers,
          redirect: 'manual',
          ...(body.method === 'GET' ? {} : { body: Buffer.from(body.body, 'base64') }),
        });
        const responseBytes = Buffer.from(await response.arrayBuffer());
        if (url.pathname === '/identity/issuer/token' && response.status === 200) {
          const proof = body.headers.DPoP ?? body.headers.dpop;
          assert.equal(typeof proof, 'string');
          const header = decodeProtectedHeader(proof);
          const { payload } = await jwtVerify(proof, await importJWK(header.jwk!, 'ES256'), {
            algorithms: ['ES256'],
            typ: 'dpop+jwt',
          });
          assert.equal(payload.htm, 'POST');
          assert.equal(payload.htu, `${issuer}/token`);
          assert.ok(
            typeof payload.nonce === 'string' && asNonces.has(payload.nonce),
            'successful SDK token proof must use a previously obtained AS nonce',
          );
          nonceBoundTokens++;
        }
        if (['/identity/issuer/par', '/identity/issuer/token'].includes(url.pathname)) {
          const nonce = response.headers.get('dpop-nonce');
          if (nonce) asNonces.add(nonce);
        }
        if (response.status === 400 || response.status === 401) {
          const error = JSON.parse(responseBytes.toString('utf8'));
          if (error.error === 'use_dpop_nonce') {
            assert.ok(response.headers.get('dpop-nonce'));
            challenged.add(url.pathname);
          }
        }
        if (url.pathname === '/identity/issuer/credential') {
          assert.match(body.headers.Authorization ?? body.headers.authorization ?? '', /^DPoP /);
        }
        result = {
          status: response.status,
          headers: Object.fromEntries(response.headers),
          body: responseBytes.toString('base64'),
        };
      } else if (req.url === '/approve') {
        const url = new URL(body.url);
        assert.equal(url.origin + url.pathname, `${issuer}/authorize`);
        const page = await worker.fetch(url.href, {
          headers: { Cookie: '__Host-op-sso=owner-cookie' },
        });
        assert.equal(page.status, 200);
        const html = await page.text();
        const grant = /name=grant value='([^']+)'/.exec(html)![1];
        const csrf = /name=csrf value='([^']+)'/.exec(html)![1];
        const response = await worker.fetch(`${issuer}/authorize`, {
          method: 'POST',
          redirect: 'manual',
          headers: {
            Cookie: '__Host-op-sso=owner-cookie',
            Origin: root,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({ grant, csrf, document, decision: 'approve' }).toString(),
        });
        assert.equal(response.status, 303);
        result = { callback: response.headers.get('location') };
      } else if (req.url === '/verify') {
        const bytes = Buffer.from(body.credential, 'base64');
        let values: Record<string, unknown>;
        if (body.configuration === 'linked_document') {
          const { payload } = await jwtVerify(bytes.toString('utf8').split('~')[0], issuerKey, {
            issuer,
          });
          assert.deepEqual((payload.cnf as { jwk: JWK }).jwk, body.holder);
          assert.equal(payload.vct, `${issuer}/types/linked-document`);
          assert.ok(payload.exp! > Math.floor(Date.now() / 1000));
          values = {};
          for (const disclosure of bytes.toString('utf8').split('~').slice(1).filter(Boolean)) {
            assert.ok(
              (payload._sd as string[]).includes(
                createHash('sha256').update(disclosure).digest('base64url'),
              ),
            );
            const [, name, value] = JSON.parse(Buffer.from(disclosure, 'base64url').toString());
            assert.equal(Object.hasOwn(values, name), false);
            values[name] = value;
          }
        } else {
          assert.equal(body.configuration, 'linked_document_mdoc');
          values = verifyMdocIssuer(bytes.toString('base64url'), body.holder, issuerKey).values;
        }
        assert.equal(verified.has(body.configuration), false);
        const recipient = await exportJWK(
          (await generateKeyPair('ECDH-ES', { extractable: true })).publicKey,
        );
        const { crv, kty, x, y } = recipient;
        const challenge: MultipazChallenge = {
          nonce: randomBytes(32).toString('base64url'),
          audience: 'https://verifier.example/multipaz',
          response_uri: 'https://verifier.example/multipaz/response',
          recipient_thumbprint: createHash('sha256')
            .update(JSON.stringify({ crv, kty, x, y }))
            .digest('base64url'),
        };
        pending.set(body.configuration, {
          challenge,
          holder: body.holder,
          values: { name: values.name, birthdate: values.birthdate },
        });
        verified.add(body.configuration);
        result = { verified: true, ...challenge };
      } else if (req.url === '/present') {
        const approved = pending.get(body.configuration);
        assert.ok(approved, 'presentation must follow verified SDK receipt and be one-use');
        pending.delete(body.configuration);
        const check = (challenge: MultipazChallenge) =>
          verifyMultipazIssuedPresentation(
            body.configuration,
            body.presentation,
            issuer,
            issuerKey,
            approved.holder,
            challenge,
            approved.values,
          );
        await check(approved.challenge);
        await assert.rejects(check({ ...approved.challenge, nonce: 'wrong-nonce' }));
        await assert.rejects(check({ ...approved.challenge, audience: 'wrong-verifier' }));
        if (body.configuration === 'linked_document_mdoc') {
          await assert.rejects(
            check({ ...approved.challenge, response_uri: 'https://verifier.example/wrong' }),
          );
          await assert.rejects(
            check({
              ...approved.challenge,
              recipient_thumbprint: Buffer.alloc(32).toString('base64url'),
            }),
          );
        }
        presented.add(body.configuration);
        result = { verified: true };
      } else throw new Error('Unknown bridge operation');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (error) {
      failures.push(error instanceof Error ? error : new Error('Bridge failure'));
      res.writeHead(500);
      res.end('Bridge verification failed');
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  try {
    await new Promise<void>((resolve, reject) => {
      const child = spawn(
        './gradlew',
        [
          ':multipaz:jvmTest',
          '--rerun',
          '--tests',
          '*MikakiIssuanceTest',
          '--no-daemon',
          '--max-workers=2',
          '--console=plain',
        ],
        {
          cwd: checkout,
          env: {
            ...process.env,
            MIKAKI_MULTIPAZ_BRIDGE: `http://127.0.0.1:${address.port}`,
            MIKAKI_MULTIPAZ_BRIDGE_SECRET: secret,
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      let output = '';
      const collect = (chunk: Buffer) => {
        output = (output + chunk.toString()).slice(-12000);
      };
      child.stdout.on('data', collect);
      child.stderr.on('data', collect);
      const timer = setTimeout(
        () => {
          child.kill('SIGTERM');
        },
        15 * 60 * 1000,
      );
      child.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code === 0) resolve();
        else reject(new Error(`Multipaz SDK test failed (${code}):\n${output}`));
      });
    });
    assert.deepEqual(failures, []);
    assert.deepEqual([...verified].sort(), ['linked_document', 'linked_document_mdoc']);
    assert.deepEqual([...presented].sort(), ['linked_document', 'linked_document_mdoc']);
    assert.equal(pending.size, 0);
    assert.ok(challenged.has('/identity/issuer/credential'));
    assert.ok(challenged.has('/identity/issuer/par') || challenged.has('/identity/issuer/token'));
    assert.ok(nonceBoundTokens > 0);
    assert.ok(
      [...challenged].every((path) =>
        ['/identity/issuer/par', '/identity/issuer/token', '/identity/issuer/credential'].includes(
          path,
        ),
      ),
    );
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}
