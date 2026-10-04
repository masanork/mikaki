import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createECDH, createHash } from 'node:crypto';
import { before, test } from 'node:test';
import {
  selectDevice,
  verifiedLinks,
  walletDevicePreflight,
} from './check-identity-wallet-device.ts';
const root = 'https://auth.mikaki.org';
const issuer = `${root}/identity/issuer`;
const fingerprint = Array(32).fill('AB').join(':');
before(() =>
  execFileSync(
    'cargo',
    [
      'build',
      '--quiet',
      '-p',
      'mikaki-identity',
      '--example',
      'wallet_device_preflight',
      '--offline',
      '--locked',
    ],
    { stdio: 'pipe', timeout: 60000 },
  ),
);
function fixture() {
  const cert = (purpose: string) =>
    readFileSync(
      new URL(`../crates/identity/tests/fixtures/${purpose}.der`, import.meta.url),
    ).toString('base64');
  const configuration = JSON.stringify({
    client_id: 'private-fixture-registration',
    client_trust: [{ issuer: `${root}/identity/attester`, trust_anchors: [cert('trust/root')] }],
    key_trust: { trust_anchors: [cert('trust/root')] },
    credential_trust: {
      sd_jwt: { trust_anchors: [cert('credential/sd-ca')] },
      mdoc: { trust_anchors: [cert('credential/mdoc-ca')] },
    },
  });
  const jwk = (n: number) => {
    const ec = createECDH('prime256v1');
    ec.setPrivateKey(Buffer.alloc(32, n));
    const p = ec.getPublicKey();
    return {
      kty: 'EC',
      crv: 'P-256',
      x: p.subarray(1, 33).toString('base64url'),
      y: p.subarray(33).toString('base64url'),
    };
  };
  const metadata = {
    credential_issuer: issuer,
    credential_endpoint: `${issuer}/credential`,
    nonce_endpoint: `${issuer}/nonce`,
    credential_configurations_supported: {
      linked_document: {
        scope: 'linked_document',
        format: 'dc+sd-jwt',
        vct: `${issuer}/types/linked-document`,
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: {
          jwt: { proof_signing_alg_values_supported: ['ES256'], key_attestations_required: {} },
        },
      },
      linked_document_mdoc: {
        scope: 'linked_document_mdoc',
        format: 'mso_mdoc',
        doctype: 'app.tossa.mikaki.linked_document.1',
        cryptographic_binding_methods_supported: ['cose_key'],
        credential_signing_alg_values_supported: [-7],
        proof_types_supported: {
          jwt: { proof_signing_alg_values_supported: ['ES256'], key_attestations_required: {} },
        },
      },
    },
    credential_request_encryption: {
      jwks: { keys: [{ ...jwk(6), kid: 'encryption', alg: 'ECDH-ES', use: 'enc' }] },
      enc_values_supported: ['A256GCM'],
      encryption_required: true,
    },
    credential_response_encryption: {
      alg_values_supported: ['ECDH-ES'],
      enc_values_supported: ['A256GCM'],
      encryption_required: true,
    },
  };
  const oauth = {
    issuer,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    authorization_endpoint: `${issuer}/authorize`,
    pushed_authorization_request_endpoint: `${issuer}/par`,
    require_pushed_authorization_requests: true,
    authorization_response_iss_parameter_supported: true,
    pre_authorized_grant_anonymous_access_supported: false,
    'pre-authorized_grant_anonymous_access_supported': false,
    token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
    grant_types_supported: ['authorization_code'],
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    dpop_signing_alg_values_supported: ['ES256'],
    client_attestation_signing_alg_values_supported: ['ES256'],
    client_attestation_pop_signing_alg_values_supported: ['ES256'],
  };
  const documents = new Map<string, string>([
    [`${root}/.well-known/openid-credential-issuer/identity/issuer`, JSON.stringify(metadata)],
    [`${root}/.well-known/oauth-authorization-server/identity/issuer`, JSON.stringify(oauth)],
    [
      `${issuer}/jwks`,
      JSON.stringify({ keys: [{ ...jwk(4), kid: 'issuer', alg: 'ES256', use: 'sig' }] }),
    ],
    [
      'https://app.mikaki.org/.well-known/assetlinks.json',
      JSON.stringify([
        {
          relation: ['delegate_permission/common.handle_all_urls'],
          target: {
            namespace: 'android_app',
            package_name: 'app.tossa.mikaki',
            sha256_cert_fingerprints: [fingerprint],
          },
        },
      ]),
    ],
  ]);
  const deps = {
    read: (path: string) => Buffer.from(path === 'config' ? configuration : 'fixture APK'),
    list: () => ['36.0.0'],
    run: (path: string, args: string[], input?: string) => {
      if (path === 'cargo')
        return execFileSync('target/debug/examples/wallet_device_preflight', [], {
          input,
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'pipe'],
        });
      if (path.endsWith('apksigner'))
        return `Signer #1 certificate SHA-256 digest: ${'ab'.repeat(32)}\n`;
      if (path.endsWith('apkanalyzer')) return 'app.tossa.mikaki\n';
      if (args[0] === 'devices') return 'List of devices attached\nprivate-device-id device\n';
      if (args.includes('get-app-links'))
        return 'app.mikaki.org: verified\nVerification link handling allowed: true\nDisabled:\n';
      if (args.includes('path')) return 'package:/data/app/fixture/base.apk';
      if (args.includes('sha256sum'))
        return `${createHash('sha256').update('fixture APK').digest('hex')}  /data/app/fixture/base.apk\n`;
      throw new Error('unexpected subprocess');
    },
    fetch: (async (url: string | URL | Request, init?: RequestInit) => {
      assert.equal(init?.redirect, 'manual');
      assert.equal(init?.body, undefined);
      assert.equal(new Headers(init?.headers).get('Authorization'), null);
      const key = String(url);
      assert.equal(new URL(key).search, '');
      if (key.endsWith('/identity/issuance/callback'))
        return new Response(null, {
          status: 303,
          headers: {
            location: '/native-link-help',
            'cache-control': 'no-store',
            'referrer-policy': 'no-referrer',
          },
        });
      assert.ok(documents.has(key), 'only fixed public endpoints');
      return new Response(documents.get(key), { headers: { 'content-type': 'application/json' } });
    }) as typeof fetch,
  };
  return { deps, documents };
}
test('actual Rust profile validator gates a redacted device preflight without claiming E2E qualification', async () => {
  const { deps } = fixture();
  const report = await walletDevicePreflight(
    { sdk: '/fixture/sdk', apk: 'apk', configuration: 'config', online: true },
    deps,
  );
  assert.equal(report.prerequisites_ready, true);
  assert.equal(report.qualification, 'not_run');
  assert.ok(!JSON.stringify(report).includes('private-device-id'));
  assert.ok(!JSON.stringify(report).includes('private-fixture-registration'));
});
test('ambiguous JSON from a public endpoint cannot bypass native parsing', async () => {
  const { deps, documents } = fixture();
  const url = `${root}/.well-known/openid-credential-issuer/identity/issuer`;
  documents.set(
    url,
    documents.get(url)!.replace('{', '{"credential_issuer":"https://substituted.example",'),
  );
  const report = await walletDevicePreflight(
    { sdk: '/fixture/sdk', apk: 'apk', configuration: 'config', online: true },
    deps,
  );
  assert.equal(report.prerequisites_ready, false);
  assert.ok(report.checks.some((c) => c.name === 'native_profile' && c.status === 'blocked'));
  assert.ok(!JSON.stringify(report).includes('substituted.example'));
});
test('no online check, unauthorized or ambiguous devices and disabled links fail closed', async () => {
  for (const s of ['List of devices attached\n', 'a unauthorized\n', 'a device\nb device\n'])
    assert.throws(() => selectDevice(s));
  assert.equal(selectDevice('a device\nb device\n', 'b'), 'b');
  assert.equal(
    verifiedLinks('app.mikaki.org: verified\nVerification link handling allowed: false'),
    false,
  );
  assert.equal(
    verifiedLinks(
      'app.mikaki.org: verified\nVerification link handling allowed: true\nDisabled:\n app.mikaki.org',
    ),
    false,
  );
  const { deps } = fixture();
  deps.fetch = async () => {
    throw new Error('unexpected fetch');
  };
  const report = await walletDevicePreflight({ sdk: '/fixture/sdk' }, deps);
  assert.equal(report.prerequisites_ready, false);
  assert.ok(report.checks.some((c) => c.name === 'public_endpoints' && c.status === 'blocked'));
  assert.equal(report.artifact, undefined);
});
test('redirects and oversized public documents are rejected without leaking response data', async () => {
  for (const mode of ['redirect', 'oversized']) {
    const { deps } = fixture();
    const ordinary = deps.fetch;
    deps.fetch = async (url, init) =>
      String(url).includes('openid-credential-issuer')
        ? mode === 'redirect'
          ? new Response(null, {
              status: 302,
              headers: { location: 'https://unexpected.example/private' },
            })
          : new Response('private-response-content'.repeat(3000), {
              headers: { 'content-type': 'application/json' },
            })
        : ordinary(url, init);
    const report = await walletDevicePreflight(
      { sdk: '/fixture/sdk', online: true, configuration: 'config', apk: 'apk' },
      deps,
    );
    assert.equal(report.prerequisites_ready, false);
    assert.ok(report.checks.some((c) => c.name === 'public_metadata' && c.status === 'blocked'));
    assert.ok(!JSON.stringify(report).includes('private-response-content'));
    assert.ok(!JSON.stringify(report).includes('unexpected.example'));
  }
});

test('installed artifact must exactly match the selected verified APK; split or unsafe paths fail closed', async () => {
  for (const mode of ['different', 'unreadable', 'split', 'unsafe', 'no_apk']) {
    const { deps } = fixture();
    const run = deps.run;
    let hashCalls = 0;
    deps.run = (path, args, input) => {
      if (args.includes('path')) {
        if (mode === 'split')
          return 'package:/data/app/fixture/base.apk\npackage:/data/app/fixture/split.apk';
        if (mode === 'unsafe') return 'package:/data/app/private;echo-secret/base.apk';
      }
      if (args.includes('sha256sum')) {
        hashCalls++;
        if (mode === 'unreadable') throw new Error('private-device-error');
        if (mode === 'different') return `${'00'.repeat(32)}  /data/app/fixture/base.apk`;
      }
      return run(path, args, input);
    };
    const report = await walletDevicePreflight(
      {
        sdk: '/fixture/sdk',
        apk: mode === 'no_apk' ? undefined : 'apk',
        configuration: 'config',
        online: true,
      },
      deps,
    );
    assert.equal(report.prerequisites_ready, false);
    assert.ok(!report.checks.some((c) => c.name === 'installed_artifact' && c.status === 'pass'));
    if (['split', 'unsafe', 'no_apk'].includes(mode)) assert.equal(hashCalls, 0);
    for (const secret of ['private-device-id', 'private-device-error', '/data/app/', 'echo-secret'])
      assert.ok(!JSON.stringify(report).includes(secret));
    assert.ok(
      report.checks.some(
        (c) =>
          c.reason ===
          {
            different: 'installed_apk_differs_from_selected_artifact',
            unreadable: 'installed_apk_hash_unavailable',
            split: 'installed_split_apks_require_separate_qualification',
            unsafe: 'package_missing_or_unreadable',
            no_apk: 'selected_apk_not_verified',
          }[mode],
      ),
    );
  }
});

test('device blockers distinguish missing, ambiguous, unauthorized and unavailable ADB without identifiers', async () => {
  for (const mode of ['missing', 'ambiguous', 'unauthorized', 'adb']) {
    const { deps } = fixture();
    const run = deps.run;
    deps.run = (path, args, input) => {
      if (args[0] === 'devices') {
        if (mode === 'adb') throw new Error('private-tool-error');
        if (mode === 'missing') return 'List of devices attached\n';
        if (mode === 'ambiguous') return 'private-a device\nprivate-b device\n';
        return 'private-a unauthorized\n';
      }
      return run(path, args, input);
    };
    const report = await walletDevicePreflight({ sdk: '/fixture/sdk' }, deps);
    assert.ok(
      report.checks.some(
        (c) =>
          c.name === 'android_device' &&
          c.reason ===
            {
              missing: 'device_not_connected',
              ambiguous: 'device_ambiguous',
              unauthorized: 'device_not_authorized_or_offline',
              adb: 'adb_unavailable',
            }[mode],
      ),
    );
    assert.ok(!JSON.stringify(report).includes('private-'));
  }
});
