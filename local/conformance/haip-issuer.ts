// Local, isolated official-suite baseline against the actual Rust workerd Issuer.
import assert from 'node:assert/strict';
import { createECDH, createHash, createPrivateKey, randomBytes } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer, request } from 'node:https';
import { Readable } from 'node:stream';
import { promisify } from 'node:util';
import { createTestHarness } from 'wrangler';
import { exportJWK, generateKeyPair } from 'jose';
import {
  parseHaipIssuerSelection,
  resolveOfficialHaipFormats,
  selectOfficialHaipModules,
} from './haip-issuer-selection.ts';
import { identityFixture } from './support/identity-fixture.ts';
import { credentialPki } from './support/credential-pki.ts';

const sourceRevision = '440eec8bac7b12b7389d7ca9cbc459b53507a443';
const suiteImage =
  'registry.gitlab.com/openid/conformance-suite@sha256:69495f453a920c262f66e5e72abd12501c33e05ce88051cddf300c00621a4d70';
const planName = 'oid4vci-1_0-issuer-haip-test-plan';
const selection = parseHaipIssuerSelection(process.argv.slice(2));
const positive = selection.legacyFlags.includes('--positive');
const encrypted = positive || selection.legacyFlags.includes('--encrypted');
const keyAttestation = encrypted || selection.legacyFlags.includes('--key-attestation');
const resource = keyAttestation || selection.legacyFlags.includes('--resource');
const lifecycle = resource || selection.legacyFlags.includes('--lifecycle');
const fapi = lifecycle || selection.legacyFlags.includes('--fapi');
const negative = fapi || selection.legacyFlags.includes('--negative');
const selectedFapiModules = new Set(
  [
    'discovery-end-point-verification',
    'ensure-authorization-request-without-state-success',
    'ensure-dpopproof-with-iat-10seconds-before-succeeds',
    'ensure-dpopproof-with-iat-10seconds-after-succeeds',
    'ensure-mismatched-dpop-jkt-fails',
    'ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt',
    'ensure-token-endpoint-fails-with-mismatched-dpop-jkt',
    'ensure-dpopproof-at-par-endpoint-binding-success',
    'ensure-dpop-auth-code-binding-success',
    'ensure-authorization-request-with-long-state',
    'ensure-authorization-code-is-bound-to-client',
    'attempt-reuse-authorization-code-after-one-second',
    'par-authorization-request-containing-request_uri-form-param',
    'par-attempt-invalid-http-method',
    'par-ensure-pkce-required',
    'ensure-pkce-code-verifier-required',
    'incorrect-pkce-code-verifier-rejected',
    'par-plain-pkce-rejected',
    'par-without-duplicate-parameters',
  ].map((name) => `fapi2-security-profile-final-${name}`),
);
const deferredModules: Record<string, string> = {
  'oid4vci-1_0-issuer-fail-invalid-key-attestation-signature':
    'Key-attestation proof profile is not implemented yet; this is outstanding work, not a pass',
  'oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm':
    'Plain credential response variant; the official module requires encrypted responses',
};
if (keyAttestation)
  delete deferredModules['oid4vci-1_0-issuer-fail-invalid-key-attestation-signature'];
if (encrypted) delete deferredModules['oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm'];
if (lifecycle) {
  for (const name of [
    'check-dpop-proof-nbf-exp',
    'par-attempt-reuse-request_uri',
    'par-attempt-to-use-expired-request_uri',
  ]) {
    selectedFapiModules.add(`fapi2-security-profile-final-${name}`);
  }
}
if (resource) {
  for (const name of ['dpop-negative-tests', 'access-token-type-header-case-sensitivity']) {
    selectedFapiModules.add(`fapi2-security-profile-final-${name}`);
  }
}
const origin = 'https://host.docker.internal:8794';
const issuer = `${origin}/identity/issuer`;
const directory = new URL(
  `../generated/haip-${Date.now()}-${randomBytes(4).toString('hex')}/`,
  import.meta.url,
);
await mkdir(directory, { recursive: true, mode: 0o700 });

// The self-signed TLS exception is scoped to the disposable suite on loopback.
async function api(
  path: string,
  body?: unknown,
  method = body === undefined ? 'GET' : 'POST',
): Promise<any> {
  assert.ok(path.startsWith('/api/') && !path.includes('://'));
  return new Promise((resolve, reject) => {
    const req = request(
      {
        hostname: 'localhost',
        port: 9443,
        path,
        method,
        rejectUnauthorized: false,
        timeout: 15000,
        headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > 16 * 1024 * 1024) req.destroy(new Error('Oversized suite response'));
          else chunks.push(chunk);
        });
        res.on('error', reject);
        res.on('end', () => {
          if ((res.statusCode ?? 500) >= 400)
            return reject(
              new Error(`Suite ${method} ${path.split('?')[0]} HTTP ${res.statusCode}`),
            );
          try {
            const text = Buffer.concat(chunks).toString();
            resolve(text ? JSON.parse(text) : null);
          } catch {
            reject(new Error('Invalid suite JSON'));
          }
        });
      },
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('Suite timeout')));
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}
const buildEvidence = {
  gitRevision: (await promisify(execFile)('git', ['rev-parse', 'HEAD'])).stdout.trim(),
  dirty: !!(await promisify(execFile)('git', ['status', '--porcelain'])).stdout.trim(),
  javascriptSha256: createHash('sha256')
    .update(await readFile(new URL('../../crates/worker/build/index.js', import.meta.url)))
    .digest('hex'),
  wasmSha256: createHash('sha256')
    .update(await readFile(new URL('../../crates/worker/build/index_bg.wasm', import.meta.url)))
    .digest('hex'),
};
const suite = await api('/api/server');
assert.equal(suite.tag, 'release-v5.3.1');
assert.equal(suite.revision, sourceRevision.slice(0, 7));
const available = await api('/api/plan/available');
const definition = available.find((p: any) => p.planName === planName);
assert.ok(definition, 'Official HAIP Issuer plan is required');
const selectedModules = selection.moduleNames.length
  ? selectOfficialHaipModules(definition.modules, selection.moduleNames)
  : definition.modules.filter(
      (module: any) =>
        ['oid4vci-1_0-issuer-metadata-test', 'oid4vci-1_0-issuer-happy-flow'].includes(
          module.testModule,
        ) ||
        (positive &&
          [
            'oid4vci-1_0-issuer-happy-flow-additional-requests',
            'oid4vci-1_0-issuer-happy-flow-multiple-clients',
          ].includes(module.testModule)) ||
        (negative &&
          module.testModule.startsWith('oid4vci-1_0-issuer-fail-') &&
          !Object.hasOwn(deferredModules, module.testModule)) ||
        (fapi && selectedFapiModules.has(module.testModule)),
    );
assert.ok(selectedModules.length > 0, 'At least one official HAIP issuer module must be selected');
const selectedFormats = resolveOfficialHaipFormats(selection.formats);
await writeFile(new URL('plan-definition.json', directory), JSON.stringify(definition, null, 2), {
  mode: 0o600,
});

await promisify(execFile)('openssl', [
  'req',
  '-x509',
  '-sha256',
  '-newkey',
  'rsa:2048',
  '-nodes',
  '-days',
  '2',
  '-subj',
  '/CN=host.docker.internal',
  '-addext',
  'subjectAltName=DNS:host.docker.internal',
  '-keyout',
  new URL('tls.key', directory).pathname,
  '-out',
  new URL('tls.crt', directory).pathname,
]);
// Known disposable key matching the existing public DS fixture; never production material.
const ec = createECDH('prime256v1');
ec.setPrivateKey(Buffer.alloc(32, 4));
const point = ec.getPublicKey();
const issuerPrivate = createPrivateKey({
  format: 'jwk',
  key: {
    kty: 'EC',
    crv: 'P-256',
    d: Buffer.alloc(32, 4).toString('base64url'),
    x: point.subarray(1, 33).toString('base64url'),
    y: point.subarray(33).toString('base64url'),
  },
});
const signing = { ...(await exportJWK(issuerPrivate)), kid: 'haip-disposable-issuer' };
const evidence = identityFixture();
const now = Math.floor(Date.now() / 1000);
const config = JSON.parse(
  await readFile(new URL('../../crates/worker/wrangler.jsonc', import.meta.url), 'utf8'),
);
config.main = new URL('../../crates/worker/build/worker/shim.mjs', import.meta.url).pathname;
config.d1_databases[0].migrations_dir = new URL(
  '../../crates/worker/migrations',
  import.meta.url,
).pathname;
config.vars = {
  MIKAKI_ISSUER: origin,
  IDENTITY_ENABLED: 'true',
  IDENTITY_WALLET_ENABLED: 'true',
  IDENTITY_TRUSTED_KEYS: JSON.stringify(evidence.trust),
  IDENTITY_ISSUER_JWK: JSON.stringify(signing),
  MIKAKI_DPOP_NONCE_MODE: 'required',
  IDENTITY_WALLET_CLIENTS: JSON.stringify(
    [1, 2].map((n) => ({
      client_id: `haip-wallet-${n}`,
      name: `Disposable suite wallet ${n}`,
      redirect_uri:
        'https://suite-frontend:8443/test/a/mikaki-haip/callback' +
        (positive && n === 2 ? '?dummy1=lorem&dummy2=ipsum' : ''),
    })),
  ),
};
config.ratelimits = [
  { name: 'IDENTITY_RATE_LIMIT', namespace_id: '1030', simple: { limit: 1000, period: 60 } },
];
// A real disposable CA and non-self-signed attester leaf avoid harness-only trust failures.
await promisify(execFile)('openssl', [
  'req',
  '-x509',
  '-sha256',
  '-newkey',
  'ec',
  '-pkeyopt',
  'ec_paramgen_curve:P-256',
  '-pkeyopt',
  'ec_param_enc:named_curve',
  '-nodes',
  '-days',
  '2',
  '-subj',
  '/CN=Mikaki disposable HAIP CA',
  '-addext',
  'basicConstraints=critical,CA:TRUE',
  '-addext',
  'keyUsage=critical,keyCertSign,cRLSign',
  '-addext',
  'subjectKeyIdentifier=hash',
  '-keyout',
  new URL('ca.key', directory).pathname,
  '-out',
  new URL('ca.crt', directory).pathname,
]);
const attester = await generateKeyPair('ES256', { extractable: true });
const attesterJwk = {
  ...(await exportJWK(attester.privateKey)),
  kid: 'disposable-attester',
  alg: 'ES256',
};
await writeFile(
  new URL('attester.key', directory),
  createPrivateKey({ key: attesterJwk, format: 'jwk' }).export({ format: 'pem', type: 'pkcs8' }),
  { mode: 0o600 },
);
await promisify(execFile)('openssl', [
  'req',
  '-new',
  '-key',
  new URL('attester.key', directory).pathname,
  '-subj',
  '/CN=Mikaki disposable wallet attester',
  '-out',
  new URL('attester.csr', directory).pathname,
]);
await writeFile(
  new URL('attester.ext', directory),
  'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n',
  { mode: 0o600 },
);
await promisify(execFile)('openssl', [
  'x509',
  '-sha256',
  '-req',
  '-in',
  new URL('attester.csr', directory).pathname,
  '-CA',
  new URL('ca.crt', directory).pathname,
  '-CAkey',
  new URL('ca.key', directory).pathname,
  '-set_serial',
  `0x${randomBytes(16).toString('hex')}`,
  '-days',
  '2',
  '-extfile',
  new URL('attester.ext', directory).pathname,
  '-outform',
  'DER',
  '-out',
  new URL('attester.der', directory).pathname,
]);
const trustAnchor = await readFile(new URL('ca.crt', directory), 'utf8');
const attesterCertificate = (await readFile(new URL('attester.der', directory))).toString('base64');
config.vars.IDENTITY_HAIP_ENABLED = 'true';
config.vars.IDENTITY_WALLET_ATTESTERS = JSON.stringify([
  {
    issuer: 'https://disposable-attester.example',
    trust_anchors: [trustAnchor.replace(/-----[^-]+-----|\s/g, '')],
  },
]);
config.vars.IDENTITY_WALLET_CLIENTS = JSON.stringify(
  JSON.parse(config.vars.IDENTITY_WALLET_CLIENTS).map((c: object) => ({
    ...c,
    attesters: ['https://disposable-attester.example'],
  })),
);
const credentialTrust = await credentialPki(new URL('credential-pki/', directory), signing);
config.vars.IDENTITY_CREDENTIAL_CERTIFICATES = JSON.stringify(credentialTrust.certificates);
const keyAttesterKey = await generateKeyPair('ES256', { extractable: true });
const keyAttesterJwk = {
  ...(await exportJWK(keyAttesterKey.privateKey)),
  kid: 'disposable-key-attester',
  alg: 'ES256',
  use: 'sig',
};
const keyAttesterPki = await credentialPki(
  new URL('key-attestation-pki/', directory),
  keyAttesterJwk,
  undefined,
  { criticalLeafBasicConstraints: true },
);
config.vars.IDENTITY_KEY_ATTESTATION_TRUST = JSON.stringify({
  trust_anchors: keyAttesterPki.certificates.sd_jwt.trust_anchors,
});
if (encrypted) {
  const recipient = await generateKeyPair('ECDH-ES', { extractable: true });
  config.vars.IDENTITY_CREDENTIAL_ENCRYPTION_JWK = JSON.stringify({
    ...(await exportJWK(recipient.privateKey)),
    kid: 'disposable-issuer-encryption',
    alg: 'ECDH-ES',
    use: 'enc',
  });
}
const harness = createTestHarness({
  root: new URL('../..', import.meta.url).pathname,
  workers: [{ config }],
});
let relay: ReturnType<typeof createServer> | undefined;
const runs: {
  format: string;
  configuration: string;
  planId: string;
  id: string;
  module: string;
  status: string;
  result: string | null;
  failures: { condition: string; message: string }[];
  halted: string | null;
  variant: Record<string, string>;
  moduleVariant: Record<string, string>;
  ownerApproval: boolean;
  milestones: { tokenExchange: boolean; holderNonce: boolean; credentialReceived: boolean };
}[] = [];
let active: string | undefined;
try {
  await harness.listen();
  const worker = harness.getWorker(config.name);
  await worker.applyD1Migrations('DB');
  const { DB } = await worker.getEnv();
  const cookie = randomBytes(32).toString('base64url');
  const digest = (s: string) => createHash('sha256').update(s).digest('base64url');
  const ownerHeaders = { Cookie: `__Host-op-sso=${cookie}` };
  // Synthetic live session only; production passkey login is a separate E2E target.
  await DB.batch([
    DB.prepare("INSERT INTO account_security VALUES('suite-owner',1,1)"),
    DB.prepare("INSERT INTO credential VALUES('suite-passkey','suite-owner',1)"),
    DB.prepare(
      "INSERT INTO sso_session VALUES('suite-sso','suite-owner','suite-passkey',1,?,0)",
    ).bind(now + 3600),
    DB.prepare("INSERT INTO sso_context VALUES('suite-sso',?,?)").bind(digest(cookie), now),
  ]);
  const holder = await generateKeyPair('ES256', { extractable: true });
  const documents: Record<string, string> = {};
  for (const [format, card] of [
    ['sd_jwt_vc', evidence.makeMnc()],
    ['mdoc', evidence.makeLicense()],
  ] as const) {
    const intake = await worker.fetch(`${origin}/identity/intake`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ evidence: card, holder_jwk: await exportJWK(holder.publicKey) }),
    });
    assert.equal(intake.status, 200, 'Synthetic card evidence must pass the real backend');
    const tx = (await intake.json()) as any;
    const page = await worker.fetch(tx.approval_url, { headers: ownerHeaders });
    assert.equal(page.status, 200);
    const csrf = /name=csrf value='([^']+)'/.exec(await page.text())?.[1];
    assert.ok(csrf);
    const approved = await worker.fetch(`${origin}/identity/approve`, {
      method: 'POST',
      headers: {
        ...ownerHeaders,
        Origin: origin,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ tx: tx.transaction_id, csrf, decision: 'link' }).toString(),
    });
    assert.equal(approved.status, 200, 'Synthetic owner must explicitly approve account linkage');
    documents[format] = tx.transaction_id;
  }
  async function approveAuthorization(destination: string, format: string) {
    const url = new URL(destination);
    assert.equal(url.origin + url.pathname, `${issuer}/authorize`);
    assert.ok(url.searchParams.has('client_id') && url.searchParams.has('request_uri'));
    assert.ok(['haip-wallet-1', 'haip-wallet-2'].includes(url.searchParams.get('client_id')!));
    const page = await worker.fetch(url, { headers: ownerHeaders, redirect: 'manual' });
    let approved = page;
    if (page.status === 200) {
      assert.equal(page.status, 200, 'Real owner authorization screen must load');
      const html = await page.text();
      const grant = /name=grant value='([^']+)'/.exec(html)?.[1];
      const csrf = /name=csrf value='([^']+)'/.exec(html)?.[1];
      assert.ok(grant && csrf);
      assert.ok(html.includes(`value='${documents[format]}'`));
      approved = await worker.fetch(`${issuer}/authorize`, {
        method: 'POST',
        redirect: 'manual',
        headers: {
          ...ownerHeaders,
          Origin: origin,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          grant,
          csrf,
          document: documents[format],
          decision: 'approve',
        }).toString(),
      });
    }
    assert.equal(approved.status, 303, 'Real CSRF-protected owner approval must produce a code');
    const callback = new URL(approved.headers.get('location')!);
    assert.equal(
      callback.origin + callback.pathname,
      'https://suite-frontend:8443/test/a/mikaki-haip/callback',
    );
    assert.ok(
      callback.searchParams.get('code') ||
        callback.searchParams.get('error') === 'invalid_request_uri',
    );
    assert.equal(callback.searchParams.get('iss'), issuer);
    // Connect via the pinned local suite port while preserving its registered callback path/query.
    // No third-party redirect is followed and the original issuer/callback URLs are unchanged.
    async function callbackRequest(url: URL, method = 'GET'): Promise<string> {
      assert.equal(url.origin, 'https://suite-frontend:8443');
      assert.ok(url.pathname.startsWith('/test/a/mikaki-haip/'));
      return new Promise((resolve, reject) => {
        const req = request(
          {
            hostname: 'localhost',
            port: 9443,
            path: url.pathname + url.search,
            method,
            rejectUnauthorized: false,
            timeout: 15000,
            headers: method === 'POST' ? { 'Content-Type': 'text/plain' } : {},
          },
          (res) => {
            let size = 0;
            const chunks: Buffer[] = [];
            res.on('data', (chunk: Buffer) => {
              size += chunk.length;
              if (size > 1024 * 1024) req.destroy(new Error('Oversized callback response'));
              else chunks.push(chunk);
            });
            res.on('error', reject);
            res.on('end', () => {
              if ((res.statusCode ?? 500) >= 400)
                reject(new Error(`Suite callback HTTP ${res.statusCode}`));
              else resolve(Buffer.concat(chunks).toString());
            });
          },
        );
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('Suite callback timeout')));
        req.end();
      });
    }
    const callbackHtml = await callbackRequest(callback);
    // The suite callback page sends the browser fragment to a one-use endpoint,
    // even for query-mode responses. Its fragment is empty for this profile.
    const submission = /xhr\.open\('POST',\s*("[^"]+"),\s*true\)/.exec(callbackHtml)?.[1];
    assert.ok(submission, 'Pinned suite callback must expose its fragment submission endpoint');
    const submitUrl = new URL(JSON.parse(submission));
    assert.match(submitUrl.pathname, /^\/test\/a\/mikaki-haip\/implicit\/[A-Za-z0-9]{20}$/);
    assert.equal(submitUrl.search, '');
    await callbackRequest(submitUrl, 'POST');
    return callback.searchParams.has('code');
  }

  relay = createServer(
    {
      key: await readFile(new URL('tls.key', directory)),
      cert: await readFile(new URL('tls.crt', directory)),
      minVersion: 'TLSv1.2',
      ciphers:
        'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
      honorCipherOrder: true,
      handshakeTimeout: 10000,
      requestTimeout: 20000,
      headersTimeout: 15000,
      keepAliveTimeout: 1000,
    },
    async (incoming, outgoing) => {
      try {
        if (incoming.headers.host !== 'host.docker.internal:8794') {
          outgoing.writeHead(403).end();
          return;
        }
        const url = new URL(incoming.url ?? '/', origin);
        if (url.origin !== origin) {
          outgoing.writeHead(403).end();
          return;
        }
        const response = await worker.fetch(url, {
          method: incoming.method,
          redirect: 'manual',
          headers: Object.fromEntries(
            Object.entries(incoming.headers).map(([k, v]) => [
              k,
              Array.isArray(v) ? v.join(', ') : (v ?? ''),
            ]),
          ),
          ...(!['GET', 'HEAD'].includes(incoming.method ?? 'GET')
            ? { body: Readable.toWeb(incoming), duplex: 'half' }
            : {}),
        });
        outgoing.writeHead(response.status, Object.fromEntries(response.headers));
        if (response.body) Readable.fromWeb(response.body).pipe(outgoing);
        else outgoing.end();
      } catch {
        outgoing.writeHead(500).end();
      }
    },
  );
  await new Promise<void>((resolve, reject) => {
    relay!.once('error', reject);
    relay!.listen(8794, '0.0.0.0', resolve);
  });
  const configurations = [
    ['sd_jwt_vc', 'linked_document'],
    ['mdoc', 'linked_document_mdoc'],
  ] as const;
  for (const [format, configuration] of configurations.filter(([format]) =>
    selectedFormats.includes(format),
  )) {
    const variant = {
      credential_format: format,
      grant_management: 'disabled',
      vci_authorization_code_flow_variant: 'wallet_initiated',
    };
    const pair = await generateKeyPair('ES256', { extractable: true });
    const clientKey = {
      ...(await exportJWK(pair.privateKey)),
      kid: 'disposable-client',
      alg: 'ES256',
    };
    const client2Key = {
      ...(await exportJWK((await generateKeyPair('ES256', { extractable: true })).privateKey)),
      kid: 'disposable-client-2',
      alg: 'ES256',
    };
    // Disposable configuration measures the actual Worker without replacing suite assertions.
    const planConfig = {
      alias: 'mikaki-haip',
      description: `Mikaki actual workerd baseline, ${format}; not certification`,
      publish: 'No',
      vci: { credential_issuer_url: issuer, credential_configuration_id: configuration },
      client: { client_id: 'haip-wallet-1', jwks: { keys: [clientKey] } },
      client2: { client_id: 'haip-wallet-2', jwks: { keys: [client2Key] } },
      credential: {
        trust_anchor_pem: credentialTrust.anchors[format === 'mdoc' ? 'mdoc' : 'sd_jwt'],
        status_list_trust_anchor_pem:
          credentialTrust.anchors[format === 'mdoc' ? 'mdoc' : 'sd_jwt'],
      },
      client_attestation: {
        issuer: 'https://disposable-attester.example',
        attester_jwks: { keys: [{ ...attesterJwk, x5c: [attesterCertificate] }] },
        key_attestation_jwks: {
          keys: [{ ...keyAttesterJwk, x5c: keyAttesterPki.certificates.sd_jwt.chain }],
        },
      },
    };
    await writeFile(
      new URL(`${format}-private-config.json`, directory),
      JSON.stringify({ variant, config: planConfig }, null, 2),
      { mode: 0o600 },
    );
    const plan = await api(
      `/api/plan?${new URLSearchParams({ planName, variant: JSON.stringify(variant) })}`,
      planConfig,
    );
    for (const selected of selectedModules) {
      const module: string = selected.testModule;
      const moduleVariant = selected.variant ?? {
        sender_constrain: 'dpop',
        fapi_profile: 'vci_haip',
        fapi_request_method: 'unsigned',
        client_auth_type: 'client_attestation',
        vci_grant_type: 'authorization_code',
        authorization_request_type: 'simple',
        vci_credential_encryption: encrypted ? 'encrypted' : 'plain',
        openid: 'plain_oauth',
        fapi_response_mode: 'plain_response',
      };
      const run = await api(
        `/api/runner?${new URLSearchParams({ test: module, plan: plan.id, variant: JSON.stringify(moduleVariant) })}`,
        undefined,
        'POST',
      );
      active = run.id;
      let info: any;
      let approved = false;
      const handledRedirects = new Set<string>();
      let halted: string | null = null;
      const deadline =
        Date.now() + (module.endsWith('par-attempt-to-use-expired-request_uri') ? 150000 : 90000);
      do {
        info = await api(`/api/info/${run.id}`);
        if (['FINISHED', 'INTERRUPTED', 'FAILED', 'SKIPPED'].includes(info.status)) break;
        if (info.status === 'WAITING') {
          const entries = await api(`/api/log/${run.id}?pretty=true`);
          const redirectEvent = entries.findLast(
            (e: any) => typeof e.redirect_to_authorization_endpoint === 'string',
          );
          const redirect = redirectEvent?.redirect_to_authorization_endpoint;
          const eventId = redirectEvent?._id;
          if (redirect && eventId && !handledRedirects.has(eventId)) {
            try {
              approved = (await approveAuthorization(redirect, format)) || approved;
              handledRedirects.add(eventId);
            } catch (failure) {
              halted = `Owner/callback adapter failed: ${failure instanceof Error ? failure.message : 'unknown'}`;
              break;
            }
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 500));
      } while (Date.now() < deadline);
      const log = await api(`/api/log/${run.id}?pretty=true`);
      await writeFile(
        new URL(`${format}-${module}-${run.id}.json`, directory),
        JSON.stringify({ planId: plan.id, info, log }, null, 2),
        { mode: 0o600 },
      );
      const failures = log
        .filter((entry: any) => entry.result === 'FAILURE' || entry.result === 'WARNING')
        .map((entry: any) => ({
          condition: entry.src ?? '',
          message: String(entry.msg ?? '')
            .replace(/[A-Za-z0-9_-]{32,}/g, '[redacted]')
            .slice(0, 500),
        }));
      runs.push({
        format,
        configuration,
        planId: plan.id,
        id: run.id,
        module,
        status: info.status,
        result: info.result,
        failures,
        variant,
        moduleVariant,
        halted:
          halted ??
          (['FINISHED', 'INTERRUPTED', 'FAILED', 'SKIPPED'].includes(info.status)
            ? null
            : 'Polling deadline reached'),
        ownerApproval: approved,
        milestones: {
          tokenExchange: log.some(
            (e: any) =>
              e.http === 'response' &&
              e.src === 'CallTokenEndpointAllowingDpopNonceErrorAndReturnFullResponse' &&
              e.response_status_code === '200 OK',
          ),
          holderNonce: log.some(
            (e: any) =>
              e.http === 'response' &&
              e.src === 'CallCredentialIssuerNonceEndpoint' &&
              e.response_status_code === '200 OK',
          ),
          credentialReceived: log.some(
            (e: any) =>
              e.http === 'response' &&
              e.src === 'CallProtectedResourceAllowingDpopNonceError' &&
              e.response_status_code === '200 OK',
          ),
        },
      });
      console.log(`${format} ${module}: ${info.status}/${info.result}`);
      if (!['FINISHED', 'INTERRUPTED', 'FAILED', 'SKIPPED'].includes(info.status))
        await api(`/api/runner/${run.id}`, undefined, 'DELETE');
      active = undefined;
    }
  }
  const expectedTuples = selectedFormats.flatMap((format) =>
    selectedModules.map((module: any) => ({ format, module: module.testModule })),
  );
  const executedTuples = runs.map(({ format, module }) => ({ format, module }));
  assert.deepEqual(
    executedTuples,
    expectedTuples,
    `Expected all ${expectedTuples.length} official module/format tuples to execute exactly once`,
  );
  const report = {
    generatedAt: new Date().toISOString(),
    suite,
    buildEvidence,
    sourceRevision,
    suiteImage,
    planName,
    scope: selection.moduleNames.length
      ? `Selected official HAIP issuer modules against actual workerd; no full-plan pass claim`
      : `Official HAIP Final metadata and first issuance${negative ? ' plus selected negative modules' : ''}${fapi ? ' and selected inherited FAPI modules' : ''} against actual workerd; no full-plan pass claim`,
    selectedModules: selectedModules.map((m: any) => m.testModule),
    requestedModules: selection.moduleNames,
    selectedFormats,
    expectedRunTuples: expectedTuples,
    executedRunTuples: executedTuples,
    unselectedModules: definition.modules
      .filter((m: any) => !selectedModules.includes(m))
      .map((m: any) => m.testModule),
    deferredModules: negative ? deferredModules : {},
    limitations: [
      'Local dev-mode TLS',
      'No real cards',
      'Synthetic live SSO fixture; real passkey login not exercised',
      'Disposable credential PKI; production trust and revocation operation not qualified',
      'Single attested key per request; platform hardware assurance and attestation status mechanisms not qualified',
    ],
    runs,
  };
  await writeFile(new URL('summary.json', directory), JSON.stringify(report, null, 2), {
    mode: 0o600,
  });
  console.log(`Private report: ${new URL('summary.json', directory).pathname}`);
  if (runs.some((run) => run.status !== 'FINISHED' || run.result !== 'PASSED'))
    process.exitCode = 1;
} finally {
  try {
    if (active) await api(`/api/runner/${active}`, undefined, 'DELETE');
  } finally {
    if (relay) await new Promise<void>((resolve) => relay!.close(() => resolve()));
    await harness.close();
  }
}
