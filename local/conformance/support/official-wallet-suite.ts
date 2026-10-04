// Opt-in adapter to the unmodified, isolated OIDF v5.3.1 HAIP Wallet suite.
import assert from 'node:assert/strict';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { request } from 'node:https';
import { exportJWK, generateKeyPair } from 'jose';
import { readerPki } from './reader-pki.ts';
const revision = '440eec8bac7b12b7389d7ca9cbc459b53507a443';
const planName = 'oid4vp-1final-wallet-haip-test-plan';
const modules = [
  'oid4vp-1final-wallet-request-uri-method-post',
  'oid4vp-1final-wallet-happy-flow',
  'oid4vp-1final-wallet-alternate-happy-flow',
  'oid4vp-1final-wallet-ignores-unusable-encryption-key',
  'oid4vp-1final-wallet-fewer-claims-than-available',
  'oid4vp-1final-wallet-optional-credential-set',
  'oid4vp-1final-wallet-no-claims-in-dcql-query',
];
// Authenticated errors are answered by the Wallet core; silent rejections still
// require real Wallet error-screen evidence and are not official passes.
const rejectionModules = [
  'oid4vp-1final-wallet-negative-test-invalid-request-object-signature',
  'oid4vp-1final-wallet-negative-test-mismatched-client-id',
  'oid4vp-1final-wallet-negative-test-missing-nonce',
  'oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post',
  'oid4vp-1final-wallet-negative-test-unknown-transaction-data-type',
  'oid4vp-1final-wallet-negative-test-required-non-matching-credential',
];
const errorModules = new Map([
  ['oid4vp-1final-wallet-negative-test-required-non-matching-credential', 'access_denied'],
  ['oid4vp-1final-wallet-negative-test-missing-nonce', 'invalid_request'],
  ['oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post', 'invalid_request'],
  ['oid4vp-1final-wallet-negative-test-unknown-transaction-data-type', 'invalid_transaction_data'],
]);
const silentRejectionModules = new Set([
  'oid4vp-1final-wallet-negative-test-invalid-request-object-signature',
  'oid4vp-1final-wallet-negative-test-mismatched-client-id',
]);
const origin = 'https://suite-frontend:8443';
const terminal = ['FINISHED', 'FAILED', 'INTERRUPTED', 'SKIPPED'];
// Only this disposable loopback suite connection permits its self-signed TLS cert.
async function exchange(
  path: string,
  method = 'GET',
  body?: string,
  contentType?: string,
  accept = 'application/json',
) {
  assert.ok(path.startsWith('/') && !path.startsWith('//') && !path.includes('://'));
  return new Promise<{ status: number; text: string; type?: string }>((resolve, reject) => {
    const req = request(
      {
        hostname: 'localhost',
        port: 9443,
        path,
        method,
        rejectUnauthorized: false,
        timeout: 15000,
        headers: {
          Accept: accept,
          ...(contentType ? { 'Content-Type': contentType } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > 16 * 1024 * 1024) req.destroy(Error('Oversized suite response'));
          else chunks.push(chunk);
        });
        res.on('error', reject);
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 500,
            text: Buffer.concat(chunks).toString(),
            type: res.headers['content-type'],
          }),
        );
      },
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(Error('Suite timeout')));
    req.end(body);
  });
}
async function api(path: string, body?: unknown, method = body === undefined ? 'GET' : 'POST') {
  assert.ok(path.startsWith('/api/'));
  const result = await exchange(
    path,
    method,
    body === undefined ? undefined : JSON.stringify(body),
    body === undefined ? undefined : 'application/json',
  );
  assert.ok(
    result.status < 400,
    `Suite ${path.split('?')[0]} HTTP ${result.status}: ${result.text.slice(0, 512)}`,
  );
  return result.text ? JSON.parse(result.text) : null;
}
export async function withOfficialWalletSuite(
  format: string,
  issuer: string,
  credentialRoot: string,
  run: (suite: {
    registry: unknown;
    completion: unknown;
    present: (command: (value: unknown) => Promise<any>) => Promise<void>;
  }) => Promise<void>,
) {
  const server = await api('/api/server');
  assert.equal(server.tag, 'release-v5.3.1');
  assert.equal(server.revision, revision.slice(0, 7));
  const definition = (await api('/api/plan/available')).find((p: any) => p.planName === planName);
  for (const module of [...modules, ...rejectionModules])
    assert.ok(definition?.modules.some((m: any) => m.testModule === module));
  const directory = new URL(
    `../../generated/haip-wallet-${Date.now()}-${randomBytes(4).toString('hex')}/`,
    import.meta.url,
  );
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const signing = await generateKeyPair('ES256', { extractable: true });
  const reader = await readerPki(await exportJWK(signing.privateKey));
  const encryption = await generateKeyPair('ECDH-ES', { extractable: true });
  const kid = 'disposable-suite-reader';
  const signingJwk = {
    ...(await exportJWK(signing.privateKey)),
    kid,
    alg: 'ES256',
    use: 'sig',
    x5c: reader.chain,
  };
  const alias = `mikaki-vp-${randomBytes(6).toString('hex')}`;
  const responseUri = `${origin}/test/a/${alias}/responseuri`;
  const clientId = `x509_hash:${createHash('sha256').update(Buffer.from(reader.chain[0], 'base64')).digest('base64url')}`;
  const namespace = 'app.tossa.mikaki.linked_document.1';
  const query = {
    credentials: [
      {
        id: 'identity',
        format,
        meta:
          format === 'dc+sd-jwt'
            ? { vct_values: [`${issuer}/types/linked-document`] }
            : { doctype_value: namespace },
        claims: ['name', 'birthdate'].map((name) => ({
          path: format === 'dc+sd-jwt' ? [name] : [namespace, name],
        })),
      },
    ],
  };
  const variant = {
    credential_format: format === 'dc+sd-jwt' ? 'sd_jwt_vc' : 'iso_mdl',
    credential_type: 'custom',
    response_mode: 'direct_post.jwt',
  };
  const moduleVariant = {
    ...variant,
    vp_profile: 'haip',
    client_id_prefix: 'x509_hash',
    request_method: 'request_uri_signed',
  };
  const pem = new X509Certificate(Buffer.from(credentialRoot, 'base64')).toString();
  const config = {
    alias,
    description:
      'Actual workerd issued custom linked-document; host Rust Wallet; not full certification',
    publish: 'No',
    server: { authorization_endpoint: 'openid4vp://' },
    client: {
      client_id: clientId,
      jwks: {
        keys: [
          signingJwk,
          {
            ...(await exportJWK(encryption.privateKey)),
            kid: 'disposable-suite-encryption',
            alg: 'ECDH-ES',
            use: 'enc',
          },
        ],
      },
      dcql: query,
    },
    credential: { trust_anchor_pem: pem, status_list_trust_anchor_pem: pem },
  };
  await writeFile(
    new URL('private-config.json', directory),
    JSON.stringify({ variant, config }, null, 2),
    { mode: 0o600 },
  );
  await writeFile(new URL('plan-definition.json', directory), JSON.stringify(definition, null, 2), {
    mode: 0o600,
  });
  const plan = await api(
    `/api/plan?${new URLSearchParams({ planName, variant: JSON.stringify(variant) })}`,
    config,
  );
  const registry = {
    client_id: clientId,
    name: 'Pinned disposable official suite reader',
    response_uri: responseUri,
    kid,
    jwk: await exportJWK(signing.publicKey),
    profile: 'oid4vp_final_x509_hash',
    certificate_trust: { trust_anchors: reader.trust_anchors },
  };
  const results: any[] = [];
  async function executeModule(command: (value: unknown) => Promise<any>, module: string) {
    const active = await api(
      `/api/runner?${new URLSearchParams({ test: module, plan: plan.id, variant: JSON.stringify(moduleVariant) })}`,
      undefined,
      'POST',
    );
    const expectedError = errorModules.get(module);
    const expectedRejection = rejectionModules.includes(module) && !expectedError;
    let protocolErrorSent = false;
    let rejectionObserved = false;
    let presented = false;
    let responseEndpointCalled = false;
    let adapterError: string | undefined;
    let passed = false;
    try {
      let invocation: URL | undefined;
      const deadline = Date.now() + 15000;
      do {
        const info = await api(`/api/info/${active.id}`);
        const entries = await api(`/api/log/${active.id}?pretty=true`);
        const redirect = entries.findLast(
          (e: any) => typeof e.redirect_to_authorization_endpoint === 'string',
        )?.redirect_to_authorization_endpoint;
        if (redirect) {
          invocation = new URL(redirect);
          break;
        }
        if (terminal.includes(info.status))
          throw Error(`Suite stopped before invocation: ${info.status}`);
        await new Promise((resolve) => setTimeout(resolve, 200));
      } while (Date.now() < deadline);
      assert.ok(invocation, 'Suite did not expose a Wallet invocation');
      assert.equal(invocation.protocol, 'openid4vp:');
      assert.equal(invocation.searchParams.get('client_id'), clientId);
      const method = invocation.searchParams.get('request_uri_method') ?? 'get';
      assert.equal(method, module.endsWith('request-uri-method-post') ? 'post' : 'get');
      const uri = new URL(invocation.searchParams.get('request_uri')!);
      assert.equal(uri.origin, origin);
      assert.ok(uri.pathname.startsWith(`/test/a/${alias}/`));
      const retrieval = await command({ command: 'request_uri', client_id: clientId, method });
      const fetched = await exchange(
        uri.pathname + uri.search,
        method.toUpperCase(),
        method === 'post' ? new URLSearchParams(retrieval.form).toString() : undefined,
        method === 'post' ? 'application/x-www-form-urlencoded' : undefined,
        'application/oauth-authz-req+jwt',
      );
      assert.equal(fetched.status, 200);
      assert.match(fetched.type!, /^application\/oauth-authz-req\+jwt/);
      assert.ok(Buffer.byteLength(fetched.text) <= 16 * 1024);
      const response = await command({
        command: 'present',
        request: fetched.text,
        consent: true,
      });
      if (expectedRejection) {
        assert.deepEqual(
          response,
          { state: 'rejected' },
          'Negative suite request must produce no credential response',
        );
        rejectionObserved = true;
      } else {
        if (expectedError) {
          assert.equal(response.state, 'protocol_error');
          assert.equal(response.error, expectedError);
          assert.equal(response.response_uri, responseUri);
          assert.deepEqual(Object.keys(response).sort(), [
            'error',
            'response',
            'response_uri',
            'state',
          ]);
          protocolErrorSent = true;
        } else {
          assert.equal(
            response.state,
            'presented',
            'Production Wallet core rejected official suite request',
          );
          presented = true;
        }
        responseEndpointCalled = true;
        const accepted = await exchange(
          new URL(responseUri).pathname,
          'POST',
          new URLSearchParams({ response: response.response }).toString(),
          'application/x-www-form-urlencoded',
        );
        if (accepted.status !== 200)
          adapterError = `Suite presentation response HTTP ${accepted.status}`;
        if (accepted.status === 200 && accepted.text) {
          const ack = JSON.parse(accepted.text);
          if (ack.redirect_uri && !expectedError) {
            const approved = await command({
              command: 'completion',
              acknowledgement: accepted.text,
              client_id: clientId,
            });
            const completion = new URL(approved.uri);
            assert.equal(completion.origin, origin);
            assert.equal(completion.pathname, `/test/a/${alias}/callback`);
            assert.match(completion.hash.slice(1), /^[A-Za-z0-9._~-]{43,128}$/);
            // Emulate the pinned suite callback page's fragment XHR; do not execute
            // arbitrary page JavaScript or fetch any other destination.
            const page = await exchange(
              completion.pathname,
              'GET',
              undefined,
              undefined,
              'text/html',
            );
            assert.equal(page.status, 200);
            const submission = /xhr\.open\('POST',\s*("[^"]+"),\s*true\)/.exec(page.text)?.[1];
            assert.ok(submission, 'Suite callback must expose its fragment submission endpoint');
            const submit = new URL(JSON.parse(submission));
            assert.equal(submit.origin, origin);
            assert.match(
              submit.pathname,
              new RegExp(`^/test/a/${alias}/implicit/[A-Za-z0-9]{20}$`),
            );
            assert.equal(submit.search, '');
            assert.equal(submit.hash, '');
            const completed = await exchange(
              submit.pathname,
              'POST',
              completion.hash,
              'text/plain',
            );
            assert.equal(completed.status, 204);
          }
        }
      }
    } catch (error) {
      adapterError = error instanceof Error ? error.message : String(error);
    } finally {
      let info = await api(`/api/info/${active.id}`);
      const deadline = Date.now() + (rejectionObserved ? 0 : adapterError ? 1500 : 10000);
      while (!terminal.includes(info.status) && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 200));
        info = await api(`/api/info/${active.id}`);
      }
      const log = await api(`/api/log/${active.id}?pretty=true`);
      const counts = Object.fromEntries(
        ['FAILURE', 'ERROR', 'WARNING'].map((level) => [
          level,
          log.filter((entry: any) => entry.result === level).length,
        ]),
      );
      const summary = {
        server,
        sourceRevision: revision,
        planName,
        module,
        format,
        variant,
        planId: plan.id,
        testId: active.id,
        presented,
        protocolErrorSent,
        responseEndpointCalled,
        rejectionObserved,
        hostProbe: expectedRejection
          ? rejectionObserved && !adapterError
            ? 'REJECTED'
            : 'FAILED'
          : undefined,
        officialEvidence: expectedRejection
          ? silentRejectionModules.has(module)
            ? 'PENDING_REAL_WALLET_ERROR_SCREEN'
            : 'PENDING_REAL_WALLET_ERROR_SCREEN_OR_PROTOCOL_ERROR_RESPONSE'
          : undefined,
        status: info.status,
        result: info.result,
        counts,
        adapterError,
        scope:
          'Selected official module; custom linked-document, host Wallet; not full Wallet or physical mDL conformance',
      };
      // Retain the official pre-stop snapshot and separately record harness cleanup.
      // Cancellation is not a conformance result and cannot satisfy the UI placeholder.
      let cleanupInfo: any;
      if (!terminal.includes(info.status)) {
        await api(`/api/runner/${active.id}`, undefined, 'DELETE');
        cleanupInfo = await api(`/api/info/${active.id}`);
      }
      await writeFile(
        new URL(`${module}.json`, directory),
        JSON.stringify({ summary, info, log, cleanupInfo }, null, 2),
        { mode: 0o600 },
      );
      console.log(`Official Wallet evidence: ${directory.pathname} ${JSON.stringify(summary)}`);
      passed =
        !adapterError &&
        Object.values(counts).every((count) => count === 0) &&
        (expectedRejection
          ? rejectionObserved &&
            !presented &&
            !responseEndpointCalled &&
            info.status === 'WAITING' &&
            info.result == null
          : info.status === 'FINISHED' && info.result === 'PASSED');
      results.push(summary);
    }
    return passed;
  }
  const failures: string[] = [];
  await run({
    registry,
    completion: { client_id: clientId, redirect_uri: `${origin}/test/a/${alias}/callback` },
    present: async (command) => {
      for (const module of [...modules, ...rejectionModules])
        if (!(await executeModule(command, module))) failures.push(module);
    },
  });
  await writeFile(
    new URL('summary.json', directory),
    JSON.stringify(
      {
        server,
        revision,
        format,
        planName,
        results,
        failures,
        officialPasses: results.filter(
          (r) =>
            r.status === 'FINISHED' &&
            r.result === 'PASSED' &&
            !r.adapterError &&
            Object.values(r.counts).every((count) => count === 0),
        ).length,
        hostRejections: results.filter((r) => r.hostProbe === 'REJECTED').length,
        evidencePending: results.filter((r) => r.officialEvidence).map((r) => r.module),
      },
      null,
      2,
    ),
    { mode: 0o600 },
  );
  assert.deepEqual(failures, [], 'Selected official Wallet modules failed');
}
