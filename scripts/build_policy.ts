/** Compile a validated deployment policy for the local slice. */
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ROOT, canonicalJson, policyPath, readToml, revision, validate } from './policy-design.ts';

export async function buildPolicy(source = policyPath()) {
  const policy = await readToml(source);
  const normalized = validate(policy);
  const policyRevision = revision(policy);
  const output = resolve(ROOT, 'local/generated/policy.json');
  await mkdir(dirname(output), { recursive: true });
  await writeFile(
    output,
    `${JSON.stringify({ ...normalized, policy_revision: policyRevision }, null, 2)}\n`,
  );
  const workerPolicy: Record<string, number | string> = {
    schema_version: 5,
    policy_revision: policyRevision,
    assertion_ttl_seconds: normalized['oidc.client_authentication.assertion_ttl'],
    clock_skew_seconds: normalized['oidc.validation.clock_skew'],
    authorization_code_ttl_seconds: normalized['oidc.authorization_code_ttl'],
    request_target_bytes: normalized['limits.request_target_bytes'],
    parameter_count: normalized['limits.parameter_count'],
    state_bytes: normalized['limits.state_bytes'],
    nonce_bytes: normalized['limits.nonce_bytes'],
    access_token_ttl_seconds: normalized['oidc.access_token.ttl'],
    id_token_ttl_seconds: normalized['oidc.id_token_ttl'],
    response_bytes: normalized['limits.response_bytes'],
    jwt_bytes: normalized['limits.jwt_bytes'],
    form_body_bytes: normalized['limits.form_body_bytes'],
    token_rate_window_seconds: normalized['rate_limit.window'],
    token_attempts_per_client: normalized['rate_limit.token_per_authenticated_client'],
    sso_absolute_ttl_seconds: normalized['session.sso_absolute_ttl'],
  };
  workerPolicy.projection_revision = createHash('sha256')
    .update(canonicalJson(workerPolicy), 'ascii')
    .digest('hex');
  await writeFile(
    resolve(ROOT, 'local/generated/worker-policy.json'),
    `${canonicalJson(workerPolicy)}\n`,
  );
  return policyRevision;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(`Validated policy compiled: ${await buildPolicy(process.argv[2] ?? policyPath())}`);
}
