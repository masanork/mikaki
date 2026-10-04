import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { Agent, createServer, request } from 'node:https';
import { createServer as portReservation } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import { createTestHarness } from 'wrangler';
import {
  decodeProtectedHeader,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  type JWK,
} from 'jose';
import { prepareEudiAttesterFixture } from './support/eudi-attester-fixture.ts';
import { identityFixture } from './support/identity-fixture.ts';
import { credentialPki } from './support/credential-pki.ts';
import { verifyMdocIssuer } from './support/mdoc-test.ts';
import { issuedWalletVerifier } from './support/issued-wallet-presentation.ts';

const checkout = process.env.MIKAKI_EUDI_ISSUANCE_CHECKOUT;
const commit = '7129ed52ab5f39d657f3c48cd595d5343c7f420c';
const run = promisify(execFile);
const hash = (value: string | Buffer) => createHash('sha256').update(value).digest('base64url');
const corruptSignature = (jwt: string) => {
  const parts = jwt.split('.');
  const signature = Buffer.from(parts[2], 'base64url');
  signature[0] ^= 1;
  return `${parts[0]}.${parts[1]}.${signature.toString('base64url')}`;
};

// Only disposable loopback certificates use this client; never disable TLS globally.
async function localHttps(url: string, body?: unknown) {
  assert.equal(new URL(url).hostname, '127.0.0.1');
  return new Promise<{ status: number; body: string; location?: string }>((resolve, reject) => {
    const req = request(
      url,
      {
        method: body === undefined ? 'GET' : 'POST',
        rejectUnauthorized: false,
        agent: new Agent({ rejectUnauthorized: false }),
        headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
        timeout: 30000,
      },
      (res) => {
        let bytes = '';
        res.on('data', (chunk) => {
          bytes += String(chunk);
          if (Buffer.byteLength(bytes) > 256 * 1024)
            req.destroy(new Error('oversized local response'));
        });
        res.on('end', () =>
          resolve({ status: res.statusCode!, body: bytes, location: res.headers.location }),
        );
      },
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('local request timed out')));
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

for (const profile of [
  'public',
  'haip-attestation',
  'haip-dedicated-attester',
  'haip-dedicated-jwt',
] as const)
  test(
    profile === 'public'
      ? 'pinned eudi-dev public actual workerd OID4VCI issuance and persisted presentation'
      : profile === 'haip-attestation'
        ? 'pinned eudi-dev HAIP attestation is rejected at PAR by the local certificate-purpose policy'
        : `patched eudi-dev ${profile} completes HAIP issuance and persisted presentation`,
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
      const directory = await mkdtemp(join(tmpdir(), 'mikaki-eudi-issued-'));
      const binary = join(directory, 'eudi');
      const dedicated = profile.startsWith('haip-dedicated');
      const jwtAttestation = profile === 'haip-dedicated-jwt';
      const haip = profile !== 'public';
      const env = {
        ...process.env,
        EUDI_DEV_HOME: directory,
        ...(dedicated
          ? {
              MIKAKI_EUDI_ATTESTER_DIR: join(directory, 'attester'),
              MIKAKI_EUDI_ATTESTER_PROOF: jwtAttestation ? 'jwt' : 'attestation',
              MIKAKI_EUDI_KEY_NEGATIVES: '1',
            }
          : {}),
      };
      let adapter: Awaited<ReturnType<typeof prepareEudiAttesterFixture>> | undefined;
      let upstreamAttestationTests = 0;
      let wallet: ChildProcess | undefined;
      let harness: Awaited<ReturnType<typeof createTestHarness>> | undefined;
      let server: ReturnType<typeof createServer> | undefined;
      const reservation = portReservation();
      const tlsReservation = portReservation();
      const stopWallet = async () => {
        if (!wallet || wallet.exitCode !== null || wallet.signalCode !== null) return;
        const child = wallet;
        const stopped = new Promise<void>((resolve) => child.once('exit', () => resolve()));
        child.kill('SIGTERM');
        const timer = setTimeout(() => child.kill('SIGKILL'), 5000);
        await stopped;
        clearTimeout(timer);
      };
      try {
        if (dedicated) adapter = await prepareEudiAttesterFixture(checkout!, directory);
        await run('go', ['build', '-o', binary, '.'], {
          cwd: adapter?.checkout ?? checkout,
          timeout: 120000,
          maxBuffer: 65536,
        });
        if (dedicated && !jwtAttestation) {
          const regression = await run(
            'go',
            [
              'test',
              '-json',
              './internal/wallet',
              '-run',
              'TestCreateClientAttestationHeaders|TestCreateCredentialProofHeader_KeyAttestation|TestCredentialProofType',
              '-count=1',
            ],
            {
              cwd: adapter!.checkout,
              env: { ...env, MIKAKI_EUDI_ATTESTER_DIR: '', MIKAKI_EUDI_ATTESTER_PROOF: '' },
              timeout: 90000,
              maxBuffer: 256 * 1024,
            },
          );
          const events = regression.stdout
            .trim()
            .split('\n')
            .map((line) => JSON.parse(line));
          upstreamAttestationTests = events.filter(
            (event) => event.Action === 'pass' && event.Test && !event.Test.includes('/'),
          ).length;
          assert.equal(
            upstreamAttestationTests,
            4,
            'existing upstream attestation/proof tests must still pass with the fixture disabled',
          );
        }
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
        const signing = await generateKeyPair('ES256', { extractable: true });
        const issuerKey = await exportJWK(signing.publicKey);
        const privateKey = { ...(await exportJWK(signing.privateKey)), kid: 'eudi-fixture-issuer' };
        const pki = await credentialPki(pathToFileURL(`${directory}/pki/`), privateKey);
        const fixture = identityFixture();
        const receipts = new Map<
          string,
          { raw: string; holder: JWK; values: Record<string, unknown> }
        >();
        const failures: unknown[] = [];
        const challenged = new Set<string>();
        const asNonces = new Set<string>();
        let attestationRejections = 0;
        let verifiedClientAttestations = 0;
        let verifiedKeyAttestations = 0;
        let negativeClientRequests = 0;
        const probedScopes = new Set<string>();
        const credentialNonces = new Set<string>();
        const resourceNonces = new Set<string>();
        const resourceProofIds = new Set<string>();
        const probedTokenHashes = new Map<string, string>();
        const probedCredentialNonces = new Map<string, string>();
        const rejectedKeyProofs: Array<{ configuration: string; case: string; error: string }> = [];
        let attestationEku: string[] = [];
        let attesterRoot: X509Certificate | undefined;
        let attesterIssuer = '';
        const calls = new Map<string, number>();
        const pushed = new Map<string, { challenge: string; state: string }>();
        let tokenProofs = 0;
        let gets = 0;
        let posts = 0;
        let current:
          | {
              peer: Awaited<ReturnType<typeof issuedWalletVerifier>>;
              jwt: string;
              claims: Parameters<Awaited<ReturnType<typeof issuedWalletVerifier>>['accept']>[1];
              receipt: { holder: JWK; values: Record<string, unknown> };
            }
          | undefined;
        let worker:
          ReturnType<Awaited<ReturnType<typeof createTestHarness>>['getWorker']> | undefined;
        let origin = '';
        const allowed = new Set([
          '/.well-known/openid-credential-issuer/identity/issuer',
          '/.well-known/oauth-authorization-server/identity/issuer',
          '/identity/issuer/par',
          '/identity/issuer/token',
          '/identity/issuer/nonce',
          '/identity/issuer/credential',
          '/identity/issuer/jwks',
        ]);
        server = createServer(
          {
            key: await readFile(join(directory, 'tls.key')),
            cert: await readFile(join(directory, 'tls.pem')),
          },
          async (req, res) => {
            try {
              if (req.method === 'GET' && req.url === '/vp/request' && current) {
                gets++;
                res
                  .writeHead(200, {
                    'Content-Type': 'application/oauth-authz-req+jwt',
                    'Cache-Control': 'no-store',
                  })
                  .end(current.jwt);
                return;
              }
              let bytes = '';
              for await (const chunk of req) {
                bytes += String(chunk);
                assert.ok(Buffer.byteLength(bytes) <= 256 * 1024);
              }
              if (req.method === 'POST' && req.url === '/vp/response' && current) {
                assert.equal(
                  req.headers['content-type']?.split(';')[0],
                  'application/x-www-form-urlencoded',
                );
                const form = new URLSearchParams(bytes);
                assert.deepEqual([...form.keys()], ['response']);
                const values = await current.peer.accept(
                  form.get('response')!,
                  current.claims,
                  current.receipt.holder,
                );
                assert.deepEqual(values, {
                  name: current.receipt.values.name,
                  birthdate: current.receipt.values.birthdate,
                });
                posts++;
                res.writeHead(200, { 'Content-Type': 'application/json' }).end('{}');
                return;
              }
              assert.ok(worker);
              const path = new URL(req.url!, origin).pathname;
              assert.ok(allowed.has(path), `unexpected Wallet endpoint ${path}`);
              assert.ok(['GET', 'POST'].includes(req.method!));
              calls.set(path, (calls.get(path) ?? 0) + 1);
              const headers = Object.fromEntries(
                Object.entries(req.headers)
                  .filter(([name]) => !['host', 'connection', 'content-length'].includes(name))
                  .map(([name, value]) => [name, Array.isArray(value) ? value.join(',') : value!]),
              );
              if (dedicated && path.endsWith('/par')) {
                const scope = new URLSearchParams(bytes).get('scope')!;
                if (!probedScopes.has(scope)) {
                  probedScopes.add(scope);
                  const missing = { ...headers };
                  delete missing['oauth-client-attestation'];
                  delete missing['oauth-client-attestation-pop'];
                  const attestation = headers['oauth-client-attestation'];
                  const parts = attestation.split('.');
                  const certificateHeader = {
                    ...decodeProtectedHeader(attestation),
                    x5c: pki.certificates.sd_jwt.chain,
                  };
                  const substituted = `${Buffer.from(JSON.stringify(certificateHeader)).toString('base64url')}.${parts[1]}.${parts[2]}`;
                  for (const invalid of [
                    missing,
                    { ...headers, 'oauth-client-attestation': corruptSignature(attestation) },
                    {
                      ...headers,
                      'oauth-client-attestation-pop': corruptSignature(
                        headers['oauth-client-attestation-pop'],
                      ),
                    },
                    { ...headers, 'oauth-client-attestation': substituted },
                  ]) {
                    const rejected: { status: number; json(): Promise<unknown> } =
                      await worker.fetch(`${origin}${req.url}`, {
                        method: 'POST',
                        headers: invalid,
                        body: bytes,
                      });
                    assert.equal(rejected.status, 400);
                    assert.equal(
                      ((await rejected.json()) as { error: string }).error,
                      'invalid_client',
                    );
                    negativeClientRequests++;
                  }
                }
              }
              const response = await worker.fetch(`${origin}${req.url}`, {
                method: req.method,
                headers,
                redirect: 'manual',
                ...(req.method === 'GET' ? {} : { body: bytes }),
              });
              const responseBytes = Buffer.from(await response.arrayBuffer());
              if (dedicated && path.endsWith('/credential') && response.status === 400) {
                const requestBody = JSON.parse(bytes);
                const outer = requestBody.proofs.jwt?.[0];
                const attestation = outer
                  ? (decodeProtectedHeader(outer).key_attestation as string)
                  : requestBody.proofs.attestation[0];
                const payload = decodeJwt(attestation);
                const name = payload.mikaki_negative_case;
                if (typeof name === 'string') {
                  const dpop = String(req.headers.dpop);
                  const { payload: transportProof } = await jwtVerify(
                    dpop,
                    await importJWK(decodeProtectedHeader(dpop).jwk!, 'ES256'),
                    { algorithms: ['ES256'], typ: 'dpop+jwt' },
                  );
                  assert.equal(transportProof.htm, 'POST');
                  assert.equal(transportProof.htu, `${origin}/identity/issuer/credential`);
                  assert.ok(resourceNonces.has(String(transportProof.nonce)));
                  assert.equal(typeof transportProof.jti, 'string');
                  assert.equal(resourceProofIds.has(String(transportProof.jti)), false);
                  resourceProofIds.add(String(transportProof.jti));
                  const tokenHash = hash(String(req.headers.authorization).split(' ')[1]);
                  assert.equal(transportProof.ath, tokenHash);
                  const previousToken = probedTokenHashes.get(
                    requestBody.credential_configuration_id,
                  );
                  if (previousToken) assert.equal(tokenHash, previousToken);
                  else probedTokenHashes.set(requestBody.credential_configuration_id, tokenHash);
                  assert.ok(
                    [
                      'wrong_nonce',
                      'bad_signature',
                      'untrusted_chain',
                      'ambiguous_keys',
                      'holder_mismatch',
                    ].includes(name),
                  );
                  const header = decodeProtectedHeader(attestation);
                  assert.equal(header.x5c!.length, 1);
                  const leaf = new X509Certificate(Buffer.from(header.x5c![0], 'base64'));
                  assert.equal(leaf.ca, false);
                  assert.deepEqual(leaf.keyUsage ?? [], []);
                  assert.equal(leaf.verify(attesterRoot!.publicKey), name !== 'untrusted_chain');
                  if (name === 'bad_signature')
                    await assert.rejects(
                      jwtVerify(attestation, leaf.publicKey, {
                        algorithms: ['ES256'],
                        typ: 'key-attestation+jwt',
                      }),
                    );
                  else
                    await jwtVerify(attestation, leaf.publicKey, {
                      algorithms: ['ES256'],
                      typ: 'key-attestation+jwt',
                    });
                  assert.equal(credentialNonces.has(String(payload.nonce)), name !== 'wrong_nonce');
                  if (name !== 'wrong_nonce') {
                    const previous = probedCredentialNonces.get(
                      requestBody.credential_configuration_id,
                    );
                    if (previous) assert.equal(payload.nonce, previous);
                    else
                      probedCredentialNonces.set(
                        requestBody.credential_configuration_id,
                        String(payload.nonce),
                      );
                  }
                  const keys = payload.attested_keys as JWK[];
                  assert.equal(keys.length, name === 'ambiguous_keys' ? 2 : 1);
                  if (outer) {
                    const holder = decodeProtectedHeader(outer).jwk!;
                    const { payload: proof } = await jwtVerify(
                      outer,
                      await importJWK(holder, 'ES256'),
                      {
                        algorithms: ['ES256'],
                        typ: 'openid4vci-proof+jwt',
                        audience: `${origin}/identity/issuer`,
                      },
                    );
                    assert.ok(credentialNonces.has(String(proof.nonce)));
                    assert.equal(
                      holder.x === keys[0].x && holder.y === keys[0].y,
                      name !== 'holder_mismatch',
                    );
                  }
                  const error = JSON.parse(responseBytes.toString());
                  assert.equal(
                    error.error,
                    name === 'wrong_nonce' ? 'invalid_nonce' : 'invalid_proof',
                  );
                  assert.equal(error.credentials, undefined);
                  assert.equal(
                    rejectedKeyProofs.some(
                      (item) =>
                        item.configuration === requestBody.credential_configuration_id &&
                        item.case === name,
                    ),
                    false,
                  );
                  rejectedKeyProofs.push({
                    configuration: requestBody.credential_configuration_id,
                    case: name,
                    error: error.error,
                  });
                }
              }
              if (path.endsWith('/credential')) {
                const nonce = response.headers.get('dpop-nonce');
                if (nonce) resourceNonces.add(nonce);
              }
              if (haip && (path.endsWith('/par') || path.endsWith('/token'))) {
                const attestation = String(req.headers['oauth-client-attestation']);
                const pop = String(req.headers['oauth-client-attestation-pop']);
                const header = decodeProtectedHeader(attestation);
                assert.equal(header.alg, 'ES256');
                assert.equal(header.x5c!.length, 1);
                const leaf = new X509Certificate(Buffer.from(header.x5c![0], 'base64'));
                assert.equal(leaf.ca, false);
                assert.equal(leaf.checkIssued(attesterRoot!), true);
                assert.equal(leaf.verify(attesterRoot!.publicKey), true);
                attestationEku = leaf.keyUsage ?? [];
                assert.deepEqual(attestationEku, dedicated ? [] : ['1.0.18013.5.1.2']);
                assert.notDeepEqual(leaf.publicKey.export({ format: 'jwk' }), issuerKey);
                const { payload } = await jwtVerify(attestation, leaf.publicKey, {
                  algorithms: ['ES256'],
                  typ: 'oauth-client-attestation+jwt',
                  issuer: attesterIssuer,
                  subject: 'eudi-test-wallet',
                });
                if (dedicated)
                  assert.notDeepEqual(
                    leaf.publicKey.export({ format: 'jwk' }).x,
                    (payload.cnf as { jwk: JWK }).jwk.x,
                  );
                await jwtVerify(pop, await importJWK((payload.cnf as { jwk: JWK }).jwk, 'ES256'), {
                  algorithms: ['ES256'],
                  typ: 'oauth-client-attestation-pop+jwt',
                  issuer: 'eudi-test-wallet',
                  audience: `${origin}/identity/issuer`,
                });
                verifiedClientAttestations++;
                if (!dedicated) {
                  assert.equal(response.status, 400);
                  assert.equal(JSON.parse(responseBytes.toString()).error, 'invalid_client');
                  attestationRejections++;
                }
              }
              if (path.endsWith('/par') && response.status === 201) {
                const form = new URLSearchParams(bytes);
                assert.equal(form.get('client_id'), 'eudi-test-wallet');
                assert.equal(form.get('code_challenge_method'), 'S256');
                assert.equal(form.get('response_type'), 'code');
                assert.ok(form.get('state'));
                assert.equal(pushed.has(form.get('scope')!), false);
                pushed.set(form.get('scope')!, {
                  challenge: form.get('code_challenge')!,
                  state: form.get('state')!,
                });
              }
              if (path.endsWith('/par') || path.endsWith('/token')) {
                const nonce = response.headers.get('dpop-nonce');
                if (nonce) asNonces.add(nonce);
              }
              if (
                [400, 401].includes(response.status) &&
                JSON.parse(responseBytes.toString()).error === 'use_dpop_nonce'
              ) {
                assert.ok(response.headers.get('dpop-nonce'));
                challenged.add(path);
              }
              if (path.endsWith('/token') && response.status === 200) {
                const proof = String(req.headers.dpop);
                const header = decodeProtectedHeader(proof);
                const { payload } = await jwtVerify(proof, await importJWK(header.jwk!, 'ES256'), {
                  algorithms: ['ES256'],
                  typ: 'dpop+jwt',
                });
                assert.equal(payload.htm, 'POST');
                assert.equal(payload.htu, `${origin}/identity/issuer/token`);
                assert.ok(asNonces.has(String(payload.nonce)));
                const form = new URLSearchParams(bytes);
                assert.equal(form.get('grant_type'), 'authorization_code');
                assert.equal(form.get('client_id'), 'eudi-test-wallet');
                assert.ok(
                  [...pushed.values()].some(
                    (par) => par.challenge === hash(form.get('code_verifier')!),
                  ),
                );
                tokenProofs++;
                assert.equal(JSON.parse(responseBytes.toString()).token_type, 'DPoP');
              }
              if (path.endsWith('/nonce') && response.status === 200)
                credentialNonces.add(JSON.parse(responseBytes.toString()).c_nonce);
              if (path.endsWith('/credential') && response.status === 200) {
                assert.match(String(req.headers.authorization), /^DPoP /);
                const body = JSON.parse(bytes);
                if (dedicated)
                  assert.equal(
                    hash(String(req.headers.authorization).split(' ')[1]),
                    probedTokenHashes.get(body.credential_configuration_id),
                    'successful issuance must reuse the token exercised by refused key proofs',
                  );
                let holder: JWK;
                if (dedicated) {
                  assert.deepEqual(Object.keys(body.proofs), [
                    jwtAttestation ? 'jwt' : 'attestation',
                  ]);
                  const outerProof = jwtAttestation ? body.proofs.jwt[0] : undefined;
                  const attestation = jwtAttestation
                    ? (decodeProtectedHeader(outerProof).key_attestation as string)
                    : body.proofs.attestation[0];
                  const header = decodeProtectedHeader(attestation);
                  assert.equal(header.x5c!.length, 1);
                  const leaf = new X509Certificate(Buffer.from(header.x5c![0], 'base64'));
                  assert.equal(leaf.ca, false);
                  assert.equal(leaf.verify(attesterRoot!.publicKey), true);
                  assert.deepEqual(leaf.keyUsage ?? [], []);
                  const { payload } = await jwtVerify(attestation, leaf.publicKey, {
                    algorithms: ['ES256'],
                    typ: 'key-attestation+jwt',
                  });
                  assert.ok(credentialNonces.has(String(payload.nonce)));
                  assert.equal(
                    payload.nonce,
                    probedCredentialNonces.get(body.credential_configuration_id),
                    'refused proofs must not consume the legitimate credential nonce',
                  );
                  assert.equal((payload.attested_keys as JWK[]).length, 1);
                  const attested = (payload.attested_keys as JWK[])[0];
                  assert.equal(attested.d, undefined);
                  holder = { kty: attested.kty, crv: attested.crv, x: attested.x, y: attested.y };
                  if (jwtAttestation) {
                    const proofHeader = decodeProtectedHeader(outerProof);
                    const { payload: proofPayload } = await jwtVerify(
                      outerProof,
                      await importJWK(holder, 'ES256'),
                      {
                        algorithms: ['ES256'],
                        audience: `${origin}/identity/issuer`,
                        typ: 'openid4vci-proof+jwt',
                      },
                    );
                    assert.equal(proofPayload.nonce, payload.nonce);
                    assert.equal(proofHeader.jwk!.x, holder.x);
                    assert.equal(proofHeader.jwk!.y, holder.y);
                  }
                  verifiedKeyAttestations++;
                } else {
                  const proof = body.proofs.jwt[0];
                  holder = decodeProtectedHeader(proof).jwk!;
                  await jwtVerify(proof, await importJWK(holder, 'ES256'), {
                    algorithms: ['ES256'],
                    audience: `${origin}/identity/issuer`,
                    typ: 'openid4vci-proof+jwt',
                  });
                }
                const credential = JSON.parse(responseBytes.toString()).credentials[0].credential;
                let values: Record<string, unknown>;
                if (body.credential_configuration_id === 'linked_document') {
                  const { payload } = await jwtVerify(credential.split('~')[0], issuerKey, {
                    issuer: `${origin}/identity/issuer`,
                  });
                  assert.deepEqual((payload.cnf as { jwk: JWK }).jwk, holder);
                  values = {};
                  for (const disclosure of credential.split('~').slice(1).filter(Boolean)) {
                    assert.ok((payload._sd as string[]).includes(hash(disclosure)));
                    const [, name, value] = JSON.parse(
                      Buffer.from(disclosure, 'base64url').toString(),
                    );
                    assert.equal(Object.hasOwn(values, name), false);
                    values[name] = value;
                  }
                } else {
                  assert.equal(body.credential_configuration_id, 'linked_document_mdoc');
                  values = verifyMdocIssuer(credential, holder, issuerKey).values;
                }
                assert.equal(values.name, '試験 太郎');
                assert.equal(values.birthdate, '1990-02-28');
                assert.equal(receipts.has(body.credential_configuration_id), false);
                receipts.set(body.credential_configuration_id, { raw: credential, holder, values });
              }
              res
                .writeHead(response.status, Object.fromEntries(response.headers))
                .end(responseBytes);
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
        origin = `https://127.0.0.1:${address.port}`;
        const issuer = `${origin}/identity/issuer`;
        await new Promise<void>((resolve) => reservation.listen(0, '127.0.0.1', resolve));
        const walletAddress = reservation.address();
        assert.ok(walletAddress && typeof walletAddress !== 'string');
        const walletPort = walletAddress.port;
        await new Promise<void>((resolve, reject) => {
          tlsReservation.once('error', reject);
          tlsReservation.listen(0, '127.0.0.1', resolve);
        });
        const tlsAddress = tlsReservation.address();
        assert.ok(tlsAddress && typeof tlsAddress !== 'string');
        const callback = `https://127.0.0.1:${tlsAddress.port}/callback`;
        if (haip) {
          const exported = await run(
            binary,
            [
              'wallet',
              'ca-cert',
              '--wallet-dir',
              join(directory, 'wallet'),
              '--remote',
              'local',
              '--no-color',
            ],
            { env, timeout: 45000, maxBuffer: 65536 },
          );
          attesterRoot = new X509Certificate(
            dedicated ? await readFile(join(directory, 'attester/ca.pem')) : exported.stdout,
          );
          assert.equal(attesterRoot.ca, true);
          attesterIssuer = `https://127.0.0.1:${tlsAddress.port}`;
        }
        const config = JSON.parse(
          await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
        );
        config.main = new URL(
          '../../crates/worker/build/worker/shim.mjs',
          import.meta.url,
        ).pathname;
        config.d1_databases[0].migrations_dir = new URL(
          '../../crates/worker/migrations',
          import.meta.url,
        ).pathname;
        config.vars = {
          MIKAKI_ISSUER: origin,
          IDENTITY_ENABLED: 'true',
          IDENTITY_TRUSTED_KEYS: JSON.stringify(fixture.trust),
          IDENTITY_ISSUER_JWK: JSON.stringify(privateKey),
          IDENTITY_CREDENTIAL_CERTIFICATES: JSON.stringify(pki.certificates),
          IDENTITY_WALLET_ENABLED: 'true',
          IDENTITY_WALLET_CLIENTS: JSON.stringify([
            {
              client_id: 'eudi-test-wallet',
              name: 'Isolated eudi test Wallet',
              redirect_uri: callback,
              ...(haip ? { attesters: [attesterIssuer] } : {}),
            },
          ]),
          MIKAKI_DPOP_NONCE_MODE: 'required',
          ...(haip
            ? {
                IDENTITY_HAIP_ENABLED: 'true',
                IDENTITY_WALLET_ATTESTERS: JSON.stringify([
                  { issuer: attesterIssuer, trust_anchors: [attesterRoot!.raw.toString('base64')] },
                ]),
                IDENTITY_KEY_ATTESTATION_TRUST: JSON.stringify({
                  trust_anchors: [attesterRoot!.raw.toString('base64')],
                }),
              }
            : {}),
        };
        config.ratelimits[0].simple.limit = 1000;
        harness = await createTestHarness({
          root: new URL('../..', import.meta.url).pathname,
          workers: [{ config }],
        });
        await harness.listen();
        worker = harness.getWorker(config.name);
        const configuredWorker = harness.getWorker(config.name);
        await configuredWorker.applyD1Migrations('DB');
        const { DB } = await configuredWorker.getEnv();
        const now = Math.floor(Date.now() / 1000);
        await DB.batch([
          DB.prepare("INSERT INTO account_security VALUES('owner',1,1)"),
          DB.prepare("INSERT INTO credential VALUES('passkey','owner',1)"),
          DB.prepare("INSERT INTO sso_session VALUES('sso','owner','passkey',1,?,0)").bind(
            now + 3600,
          ),
          DB.prepare("INSERT INTO sso_context VALUES('sso',?,?)").bind(hash('owner-cookie'), now),
        ]);
        const holder = await exportJWK(
          (await generateKeyPair('ES256', { extractable: true })).publicKey,
        );
        const intake = await worker.fetch(`${origin}/identity/intake`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ evidence: fixture.makeMnc(), holder_jwk: holder }),
        });
        assert.equal(intake.status, 200);
        const linked = (await intake.json()) as { transaction_id: string; approval_url: string };
        const page = await worker.fetch(linked.approval_url, {
          headers: { Cookie: '__Host-op-sso=owner-cookie' },
        });
        const csrf = /name=csrf value='([^']+)'/.exec(await page.text())![1];
        const approved = await worker.fetch(`${origin}/identity/approve`, {
          method: 'POST',
          headers: {
            Cookie: '__Host-op-sso=owner-cookie',
            Origin: origin,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            tx: linked.transaction_id,
            csrf,
            decision: 'link',
          }).toString(),
        });
        assert.equal(approved.status, 200);
        const walletOrigin = `http://127.0.0.1:${walletPort}`;
        const api = async (path: string, body?: unknown) => {
          const response = await fetch(`${walletOrigin}${path}`, {
            method: body === undefined ? 'GET' : 'POST',
            headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
            signal: AbortSignal.timeout(30000),
          });
          return { status: response.status, value: (await response.json()) as any };
        };
        const startWallet = async (haip: boolean) => {
          wallet = spawn(
            binary,
            [
              'wallet',
              'serve',
              '--port',
              String(walletPort),
              '--base-url',
              `https://127.0.0.1:${tlsAddress.port}`,
              '--serve-tls',
              '--auto-accept',
              '--no-register',
              '--vci-client-id',
              'eudi-test-wallet',
              '--vci-redirect-uri',
              callback,
              '--mode',
              'strict',
              ...(haip ? ['--haip'] : []),
              '--wallet-dir',
              join(directory, 'wallet'),
              '--remote',
              'local',
              '--no-color',
            ],
            { env, stdio: 'ignore' },
          );
          let ready = false;
          for (let i = 0; i < 100; i++) {
            assert.equal(wallet.exitCode, null, 'eudi-dev server exited before becoming ready');
            try {
              ready = (await api('/api/credentials')).status === 200;
            } catch {}
            if (ready) break;
            await delay(100);
          }
          assert.ok(ready, 'eudi-dev server must become ready');
          assert.equal((await localHttps(`${callback}?state=unknown`)).status, 404);
        };
        await Promise.all(
          [reservation, tlsReservation].map(
            (listener) => new Promise<void>((resolve) => listener.close(() => resolve())),
          ),
        );
        await startWallet(haip);
        for (const configuration of ['linked_document', 'linked_document_mdoc']) {
          const uri = `openid-credential-offer://?${new URLSearchParams({ credential_offer: JSON.stringify({ credential_issuer: issuer, credential_configuration_ids: [configuration], grants: { authorization_code: {} } }) })}`;
          const offer = await api('/api/offers', { uri });
          assert.deepEqual(failures, []);
          if (profile === 'haip-attestation') {
            assert.equal(offer.status, 400);
            assert.match(offer.value.error, /invalid_client/);
            continue;
          }
          assert.equal(offer.status, 202, JSON.stringify(offer.value));
          assert.equal(offer.value.status, 'authorization_required');
          const authorization = new URL(offer.value.authorization_url);
          assert.equal(authorization.origin + authorization.pathname, `${issuer}/authorize`);
          assert.match(
            authorization.searchParams.get('request_uri')!,
            /^urn:ietf:params:oauth:request_uri:/,
          );
          const consent = await worker.fetch(authorization.href, {
            headers: { Cookie: '__Host-op-sso=owner-cookie' },
          });
          assert.equal(consent.status, 200);
          const html = await consent.text();
          const response = await worker.fetch(`${issuer}/authorize`, {
            method: 'POST',
            redirect: 'manual',
            headers: {
              Cookie: '__Host-op-sso=owner-cookie',
              Origin: origin,
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
              grant: /name=grant value='([^']+)'/.exec(html)![1],
              csrf: /name=csrf value='([^']+)'/.exec(html)![1],
              document: linked.transaction_id,
              decision: 'approve',
            }).toString(),
          });
          assert.equal(response.status, 303);
          const destination = new URL(response.headers.get('location')!);
          assert.equal(destination.origin + destination.pathname, callback);
          assert.equal(destination.searchParams.get('iss'), issuer);
          assert.equal(destination.searchParams.get('state'), pushed.get(configuration)!.state);
          const tokensBeforeCallback = tokenProofs;
          const substituted = new URL(destination.href);
          substituted.searchParams.set('state', 'unregistered-state');
          assert.equal((await localHttps(substituted.href)).status, 404);
          assert.equal(tokenProofs, tokensBeforeCallback);
          assert.equal((await localHttps(destination.href)).status, 303);
          let result: any;
          for (let i = 0; i < 100; i++) {
            result = (await api(`/api/offers/${offer.value.offer_id}`)).value;
            if (result.status !== 'authorization_required') break;
            await delay(100);
          }
          assert.deepEqual(failures, []);
          assert.equal(result.status, 'completed', JSON.stringify(result));
          assert.equal(result.result.issuer, issuer);
          assert.equal(
            result.result.format,
            configuration === 'linked_document' ? 'dc+sd-jwt' : 'mso_mdoc',
          );
          assert.ok(receipts.has(configuration));
          assert.equal(
            (await localHttps(destination.href)).status,
            404,
            'callback replay must not exchange another token',
          );
        }
        if (profile === 'haip-attestation') {
          assert.equal(attestationRejections, 2);
          assert.equal(tokenProofs, 0);
          assert.equal(receipts.size, 0);
          assert.equal(calls.get('/identity/issuer/token'), undefined);
          assert.equal(calls.get('/identity/issuer/credential'), undefined);
          await writeFile(
            'local/generated/eudi-haip-attestation-summary.json',
            JSON.stringify(
              {
                version: 1,
                observed_at: new Date().toISOString(),
                wallet_version: 'v2.3.7',
                wallet_commit: commit,
                binary_sha256: createHash('sha256')
                  .update(await readFile(binary))
                  .digest('hex'),
                qualification: 'host_cli_haip_attestation_rejection',
                requested_formats: ['dc+sd-jwt', 'mso_mdoc'],
                phase: 'PAR',
                rejected_requests: attestationRejections,
                issuer_error: 'invalid_client',
                attestation_signature_and_ca_verified: true,
                attestation_certificate_eku: attestationEku,
                policy: 'attester_leaf_with_any_eku_is_unsupported',
                diagnosis_basis: 'verified_x5c_and_existing_mikaki_certificate_policy',
                credentials_received: 0,
                key_attestation: 'not_reached',
                encrypted_presentation: 'not_reached',
                hardware_attestation: 'not_run',
              },
              null,
              2,
            ) + '\n',
          );
          return;
        }
        assert.equal(tokenProofs, 2);
        if (dedicated) {
          assert.ok(verifiedClientAttestations >= 4);
          assert.equal(verifiedKeyAttestations, 2);
          assert.equal(negativeClientRequests, 8);
          assert.equal(rejectedKeyProofs.length, jwtAttestation ? 10 : 8);
        }
        assert.ok(challenged.has('/identity/issuer/par'));
        assert.ok(challenged.has('/identity/issuer/credential'));
        assert.equal(calls.get('/identity/issuer/nonce'), 2);
        // Reopen the same isolated store: no host reimport or private-key transfer.
        await stopWallet();
        await startWallet(true);
        const stored = await api('/api/credentials');
        assert.equal(stored.status, 200);
        assert.equal(stored.value.length, 2);
        for (const configuration of ['linked_document', 'linked_document_mdoc']) {
          const receipt = receipts.get(configuration)!;
          assert.notDeepEqual(receipt.holder, holder, 'external Wallet owns the issuance key');
          const format = configuration === 'linked_document' ? 'dc+sd-jwt' : 'mso_mdoc';
          const persisted = stored.value.find(
            (value: { format: string }) => value.format === format,
          );
          assert.ok(persisted);
          const detail = await api(`/api/credentials/${encodeURIComponent(persisted.id)}`);
          assert.equal(detail.status, 200);
          assert.equal(
            hash(detail.value.raw),
            hash(receipt.raw),
            'restart must preserve the exact received credential',
          );
          const peer = await issuedWalletVerifier(
            format,
            issuer,
            issuerKey,
            new X509Certificate(
              pki.anchors[format === 'dc+sd-jwt' ? 'sd_jwt' : 'mdoc'],
            ).raw.toString('base64'),
            `${origin}/vp/response`,
          );
          current = { peer, ...(await peer.request()), receipt };
          const response = await api('/api/presentations', {
            uri: `openid4vp://authorize?${new URLSearchParams({ client_id: peer.registry.client_id, request_uri: `${origin}/vp/request` })}`,
            auto_accept: true,
          });
          assert.deepEqual(failures, []);
          assert.equal(response.status, 200, JSON.stringify(response.value));
        }
        assert.equal(gets, 2);
        assert.equal(posts, 2);
        await writeFile(
          dedicated
            ? jwtAttestation
              ? 'local/generated/eudi-haip-dedicated-jwt-summary.json'
              : 'local/generated/eudi-haip-dedicated-attester-summary.json'
            : 'local/generated/eudi-issued-wallet-summary.json',
          JSON.stringify(
            {
              version: 1,
              observed_at: new Date().toISOString(),
              wallet_version: 'v2.3.7',
              wallet_commit: commit,
              binary_sha256: createHash('sha256')
                .update(await readFile(binary))
                .digest('hex'),
              qualification: dedicated
                ? 'host_cli_patched_attester_haip_interop'
                : 'host_cli_actual_issuance_http_interop',
              attester_adapter_sha256: adapter?.adapterSha256,
              upstream_attestation_regression_tests: upstreamAttestationTests || undefined,
              verified_client_attestations: dedicated ? verifiedClientAttestations : undefined,
              verified_key_attestations: dedicated ? verifiedKeyAttestations : undefined,
              rejected_client_requests: dedicated ? negativeClientRequests : undefined,
              key_attestation_proof_type: dedicated
                ? jwtAttestation
                  ? 'jwt_with_key_attestation'
                  : 'attestation'
                : undefined,
              patched_source_sha256: adapter?.patchedSourceSha256,
              patched_issuance_sha256: adapter?.patchedIssuanceSha256,
              rejected_key_proofs: dedicated ? rejectedKeyProofs : undefined,
              distinct_nonce_bound_negative_dpop_proofs: dedicated
                ? resourceProofIds.size
                : undefined,
              formats: ['dc+sd-jwt', 'mso_mdoc'],
              authorization_code: {
                par: true,
                pkce: 'S256',
                dpop_nonce_required: true,
                nonce_bound_tokens: tokenProofs,
                client_authentication: dedicated
                  ? 'attest_jwt_client_auth'
                  : 'none_registered_public_client',
              },
              credentials_received: receipts.size,
              persisted_receipts_presented: posts,
              callback_state_substitutions_rejected: 2,
              callback_replays_rejected: 2,
              mode: 'strict',
              presentation_haip_checks: true,
              issuance_haip_attestation: dedicated ? 'software_dedicated_attester' : 'not_run',
              physical_e2e: 'not_run',
            },
            null,
            2,
          ) + '\n',
        );
      } finally {
        await stopWallet();
        if (server) {
          server.closeAllConnections();
          await new Promise<void>((resolve) => server!.close(() => resolve()));
        }
        await harness?.close();
        for (const listener of [reservation, tlsReservation]) {
          if (listener.listening)
            await new Promise<void>((resolve) => listener.close(() => resolve()));
        }
        await rm(directory, { recursive: true, force: true });
      }
    },
  );
