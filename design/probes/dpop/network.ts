// Loopback HTTPS qualification with a fixed logical issuer and pinned fixture certificate.
// Connection routing changes only TCP destination; Host, SNI and proof htu retain the issuer URL.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { chmod, mkdir, readFile } from 'node:fs/promises';
import { createServer, request as httpsRequest } from 'node:https';
import { randomBytes } from 'node:crypto';
import { TLSSocket } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { DpopIssuanceFixture, dpopKey, dpopReceiptTransport, proofHeaders } from './probe.ts';
import { IssuerFixture, makeProof, profile, receiveOffer } from '../oid4vci/probe.ts';
import { FixtureVerifier, formResponse, newRequest, unlockKey } from '../oid4vp/probe.ts';

const exec = promisify(execFile);
async function certificate() {
  const dir = new URL(
    `../../../local/generated/dpop-tls-${randomBytes(6).toString('hex')}/`,
    import.meta.url,
  );
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const key = new URL('key.pem', dir),
    cert = new URL('cert.pem', dir);
  await exec('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-days',
    '1',
    '-keyout',
    fileURLToPath(key),
    '-out',
    fileURLToPath(cert),
    '-subj',
    '/CN=issuer.mikaki.test',
    '-addext',
    'subjectAltName=DNS:issuer.mikaki.test',
  ]);
  await chmod(key, 0o600);
  await chmod(cert, 0o600);
  return { key: await readFile(key), cert: await readFile(cert) };
}
let tlsMaterial: ReturnType<typeof certificate> | undefined;
export async function networkFixture() {
  tlsMaterial ??= certificate();
  const tls = await tlsMaterial;
  const issuer = await IssuerFixture.create();
  const endpoint = new DpopIssuanceFixture(issuer);
  let received = 0,
    verifiedTls = 0;
  const server = createServer(tls, async (req, res) => {
    received++;
    try {
      if (req.headers.host !== new URL(profile.issuer).host) {
        res.writeHead(400);
        res.end();
        return;
      }
      const headerNames = req.rawHeaders.filter((_, i) => i % 2 === 0).map((h) => h.toLowerCase());
      if (
        ['dpop', 'authorization'].some((name) => headerNames.filter((h) => h === name).length > 1)
      ) {
        res.writeHead(400, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        res.end(JSON.stringify({ error: 'invalid_request' }));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 32768) {
          res.writeHead(413);
          res.end();
          return;
        }
        chunks.push(chunk);
      }
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers))
        if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(',') : value);
      const response = await endpoint.transport(
        new Request(`${profile.issuer}${req.url}`, {
          method: req.method,
          headers,
          body: req.method === 'GET' || req.method === 'HEAD' ? undefined : Buffer.concat(chunks),
        }),
      );
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    }
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Missing fixture address');
  const send = async (
    request: Request,
    options: { trustCertificate?: boolean; servername?: string } = {},
  ) => {
    const url = new URL(request.url);
    if (url.origin !== profile.issuer || url.username || url.password)
      throw new Error('Untrusted network issuer');
    const body =
      request.method === 'GET' || request.method === 'HEAD'
        ? undefined
        : Buffer.from(await request.arrayBuffer());
    return new Promise<Response>((resolve, reject) => {
      const req = httpsRequest(
        url,
        {
          port: address.port,
          method: request.method,
          agent: false,
          timeout: 10_000,
          lookup: (_hostname, _options, callback) =>
            callback(null, [{ address: '127.0.0.1', family: 4 }]),
          headers: { ...Object.fromEntries(request.headers), host: url.host },
          servername: options.servername ?? url.hostname,
          rejectUnauthorized: true,
          ca: options.trustCertificate === false ? [] : tls.cert,
        },
        (res) => {
          if (res.socket instanceof TLSSocket && res.socket.authorized) verifiedTls++;
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk) => {
            size += chunk.length;
            if (size > 32768) req.destroy(new Error('Oversized fixture response'));
            else chunks.push(chunk);
          });
          res.on('error', reject);
          res.on('end', () => {
            const headers = new Headers();
            for (const [name, value] of Object.entries(res.headers))
              if (value !== undefined)
                headers.set(name, Array.isArray(value) ? value.join(',') : value);
            // No redirects are followed; the receipt helper rejects a redirect status/location.
            resolve(new Response(Buffer.concat(chunks), { status: res.statusCode, headers }));
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error('Fixture HTTPS timeout')));
      req.on('error', reject);
      req.end(body);
    });
  };
  return {
    issuer,
    endpoint,
    send,
    counts: () => ({ received, verifiedTls }),
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

export const networkScenarios = [
  {
    id: 'tls-receipt-to-presentation',
    layer: 'network' as const,
    async run() {
      const fixture = await networkFixture();
      try {
        const sender = await dpopKey();
        const key = await unlockKey();
        const wallet = await receiveOffer({
          offer: fixture.issuer.offer,
          txCode: fixture.issuer.txCode,
          approved: true,
          transport: await dpopReceiptTransport(fixture.send, sender.privateJwk),
          issuerPublic: fixture.issuer.issuerPublic,
          key,
        });
        assert.ok(wallet);
        assert.equal(fixture.issuer.issued, 1);
        const counts = fixture.counts();
        assert.equal(counts.received, 6);
        assert.equal(counts.verifiedTls, counts.received);
        const request = newRequest();
        const vp = await wallet.present(request, true, key);
        assert.equal(
          (
            await new FixtureVerifier(
              request,
              fixture.issuer.issuerPublic,
              async () => 'good',
            ).receive(formResponse(vp))
          ).accepted,
          true,
        );
      } finally {
        await fixture.close();
      }
    },
  },
  ...(
    [
      'untrusted-certificate',
      'wrong-certificate-hostname',
      'foreign-issuer-before-connect',
    ] as const
  ).map((id) => ({
    id,
    layer: 'network' as const,
    async run() {
      const fixture = await networkFixture();
      try {
        await assert.rejects(
          fixture.send(
            new Request(
              id === 'foreign-issuer-before-connect'
                ? 'https://attacker.test/token'
                : profile.metadataEndpoint,
            ),
            {
              trustCertificate: id !== 'untrusted-certificate',
              servername: id === 'wrong-certificate-hostname' ? 'verifier.mikaki.test' : undefined,
            },
          ),
          (error: unknown) => {
            if (!(error instanceof Error)) return false;
            if (id === 'foreign-issuer-before-connect')
              return error.message === 'Untrusted network issuer';
            const code = 'code' in error ? error.code : undefined;
            return (
              code ===
              (id === 'untrusted-certificate'
                ? 'DEPTH_ZERO_SELF_SIGNED_CERT'
                : 'ERR_TLS_CERT_ALTNAME_INVALID')
            );
          },
        );
        assert.equal(fixture.counts().received, 0);
      } finally {
        await fixture.close();
      }
    },
  })),
  {
    id: 'network-cancellation-no-connect',
    layer: 'network' as const,
    async run() {
      const fixture = await networkFixture();
      try {
        const sender = await dpopKey();
        const wallet = await receiveOffer({
          offer: fixture.issuer.offer,
          txCode: fixture.issuer.txCode,
          approved: false,
          transport: await dpopReceiptTransport(fixture.send, sender.privateJwk),
          issuerPublic: fixture.issuer.issuerPublic,
          key: await unlockKey(),
        });
        assert.equal(wallet, null);
        assert.equal(fixture.counts().received, 0);
      } finally {
        await fixture.close();
      }
    },
  },
  ...(
    [
      'network-bearer-downgrade',
      'network-missing-proof',
      'network-other-sender',
      'network-wrong-ath',
      'network-credential-proof-role-confusion',
      'network-replay',
    ] as const
  ).map((id) => ({
    id,
    layer: 'network' as const,
    async run() {
      const fixture = await networkFixture();
      try {
        const sender = await dpopKey();
        const holder = await dpopKey();
        const grant = (fixture.issuer.offer.grants as Record<string, Record<string, string>>)[
          profile.grantType
        ]!;
        const exchange = () =>
          new Request(profile.tokenEndpoint, {
            method: 'POST',
            body: new URLSearchParams({
              grant_type: profile.grantType,
              'pre-authorized_code': grant['pre-authorized_code']!,
              tx_code: fixture.issuer.txCode,
            }),
          });
        const challenge = await fixture.send(exchange());
        assert.equal(challenge.status, 400);
        assert.equal((await challenge.json()).error, 'use_dpop_nonce');
        const nonce = challenge.headers.get('dpop-nonce')!;
        const tokenRequest = exchange();
        const tokenResponse = await fixture.send(
          new Request(tokenRequest, {
            headers: {
              ...Object.fromEntries(tokenRequest.headers),
              ...(await proofHeaders(sender.privateJwk, tokenRequest, { nonce })),
            },
          }),
        );
        assert.equal(tokenResponse.status, 200);
        const token = (await tokenResponse.json()) as { access_token: string; token_type: string };
        assert.equal(token.token_type, 'DPoP');
        const proofNonce = await fixture.send(
          new Request(profile.nonceEndpoint, { method: 'POST' }),
        );
        const credentialNonce = (await proofNonce.json()).c_nonce as string;
        const holderProof = await makeProof(holder.privateJwk, credentialNonce);
        const base = (credentialProof = holderProof) =>
          new Request(profile.credentialEndpoint, {
            method: 'POST',
            headers: {
              authorization: `DPoP ${token.access_token}`,
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              credential_configuration_id: profile.configurationId,
              proofs: { jwt: [credentialProof] },
            }),
          });
        const request = base();
        const dpop = await proofHeaders(sender.privateJwk, request, {
          nonce,
          accessToken: token.access_token,
        });
        const headers = new Headers(request.headers);
        headers.set('dpop', dpop.DPoP);
        if (id === 'network-bearer-downgrade')
          headers.set('authorization', `Bearer ${token.access_token}`);
        if (id === 'network-missing-proof') headers.delete('dpop');
        if (id === 'network-other-sender')
          headers.set(
            'dpop',
            (
              await proofHeaders((await dpopKey()).privateJwk, request, {
                nonce,
                accessToken: token.access_token,
              })
            ).DPoP,
          );
        if (id === 'network-wrong-ath')
          headers.set(
            'dpop',
            (await proofHeaders(sender.privateJwk, request, { nonce, accessToken: 'wrong-token' }))
              .DPoP,
          );
        const tested = id === 'network-credential-proof-role-confusion' ? base(dpop.DPoP) : request;
        const response = await fixture.send(new Request(tested, { headers }));
        if (id === 'network-replay') {
          assert.equal(response.status, 200);
          assert.equal(fixture.issuer.issued, 1);
          const replay = await fixture.send(new Request(base(), { headers }));
          assert.equal(replay.status, 401);
          assert.equal((await replay.json()).error, 'invalid_dpop_proof');
          assert.equal(fixture.issuer.issued, 1);
        } else {
          assert.ok(response.status === 400 || response.status === 401);
          assert.equal(fixture.issuer.issued, 0);
          const retry = base();
          const freshHeaders = new Headers(retry.headers);
          freshHeaders.set(
            'dpop',
            (
              await proofHeaders(sender.privateJwk, retry, {
                nonce,
                accessToken: token.access_token,
              })
            ).DPoP,
          );
          assert.equal(
            (await fixture.send(new Request(retry, { headers: freshHeaders }))).status,
            200,
          );
          assert.equal(fixture.issuer.issued, 1);
        }
      } finally {
        await fixture.close();
      }
    },
  })),
];
