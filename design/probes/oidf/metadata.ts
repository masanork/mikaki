// Network adapter for the existing synthetic issuer metadata; not an issuer service.
import { createServer } from 'node:https';
import { readFile, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { IssuerFixture, profile } from '../oid4vci/probe.ts';
import { finished, generated, localSuite, pause, saveRun, type RunInfo } from './suite.ts';

const origin = 'https://host.docker.internal:8793';
const fixture = await IssuerFixture.create();
const rewrite = (value: unknown) =>
  JSON.parse(JSON.stringify(value).replaceAll(profile.issuer, origin));
const server = createServer(
  {
    key: await readFile(new URL('oidf-local.key', generated)),
    cert: await readFile(new URL('oidf-local.crt', generated)),
  },
  (req, res) => {
    let metadata: unknown;
    if (req.method === 'GET' && req.url === '/.well-known/openid-credential-issuer')
      metadata = fixture.metadata.credentialIssuer;
    else if (req.method === 'GET' && req.url === '/.well-known/oauth-authorization-server')
      metadata = fixture.metadata.authorizationServers[0];
    res.writeHead(metadata ? 200 : 404, {
      'content-type': 'application/json',
      'cache-control': 'no-store',
    });
    res.end(JSON.stringify(metadata ? rewrite(metadata) : { error: 'unsupported_fixture_route' }));
  },
);
await new Promise<void>((resolve, reject) => {
  server.once('error', reject);
  server.listen(8793, '0.0.0.0', resolve);
});
let runId: string | undefined;
try {
  const suiteVersion = await localSuite('/api/server');
  const plan = await localSuite(
    `/api/plan?${new URLSearchParams({
      planName: 'oid4vci-1_0-issuer-test-plan',
      variant: JSON.stringify({
        fapi_profile: 'vci',
        client_auth_type: 'private_key_jwt',
        sender_constrain: 'dpop',
        credential_format: 'sd_jwt_vc',
        vci_grant_type: 'pre_authorization_code',
        authorization_request_type: 'simple',
        fapi_request_method: 'unsigned',
        fapi_response_mode: 'plain_response',
        vci_authorization_code_flow_variant: 'issuer_initiated',
        vci_credential_encryption: 'plain',
        openid: 'plain_oauth',
      }),
    })}`,
    {
      alias: `mikaki-vci-metadata-${randomBytes(6).toString('hex')}`,
      description: 'Synthetic metadata only; no authenticated or DPoP issuance claim',
      vci: { credential_issuer_url: origin, credential_configuration_id: profile.configurationId },
    },
  );
  const name = 'oid4vci-1_0-issuer-metadata-test';
  const run = await localSuite(
    `/api/runner?${new URLSearchParams({ test: name, plan: plan.id })}`,
    undefined,
    'POST',
  );
  runId = run.id;
  let info: RunInfo = { status: 'CREATED', result: null };
  for (let i = 0; i < 60 && !finished(info); i++) {
    info = await localSuite(`/api/info/${run.id}`);
    if (!finished(info)) await pause();
  }
  const result = await saveRun(plan.id, name, run.id);
  if (finished(result)) runId = undefined;
  const report = {
    generatedAt: new Date().toISOString(),
    suite: suiteVersion,
    planId: plan.id,
    scope: 'Synthetic issuer credential metadata over local HTTPS only',
    exclusions: [
      'Token endpoint',
      'DPoP',
      'Client authentication',
      'Issuance',
      'HAIP certification',
      'Product issuer',
    ],
    results: [result],
  };
  await writeFile(
    new URL('oidf-vci-metadata-summary.json', generated),
    JSON.stringify(report, null, 2),
    { mode: 0o600 },
  );
  console.log(JSON.stringify(report, null, 2));
  if (result.status !== 'FINISHED' || result.result !== 'PASSED') process.exitCode = 1;
} finally {
  try {
    if (runId) await localSuite(`/api/runner/${runId}`, undefined, 'DELETE');
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}
