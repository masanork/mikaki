import assert from 'node:assert/strict';
import test from 'node:test';
import { checkDocsBindings } from './deploy-docs-production.ts';

test('Docs requires its own database, assets, limiter and secret with no extra authority', () => {
  const config: Parameters<typeof checkDocsBindings>[1] = {
    name: 'docs-fixture',
    account_id: 'fixture',
    compatibility_date: '2026-10-03',
    vars: {
      ISSUER: 'https://op.example',
      RP_ORIGIN: 'https://docs.example',
      CLIENT_ID: 'docs-client',
    },
    d1_databases: [{ binding: 'DB', database_id: 'docs-db' }],
    secrets: { required: ['RP_PRIVATE_JWK'] },
    version_metadata: { binding: 'CF_VERSION_METADATA' },
    assets: { binding: 'DOCS_ASSETS', directory: 'dist' },
    ratelimits: [{ name: 'AUTH_LIMITER', namespace_id: '17', simple: { limit: 60, period: 60 } }],
  };
  const bindings: Record<string, unknown>[] = [
    ...Object.entries(config.vars).map(([name, text]) => ({ name, type: 'plain_text', text })),
    { name: 'DB', type: 'd1', database_id: 'docs-db' },
    { name: 'RP_PRIVATE_JWK', type: 'secret_text' },
    { name: 'CF_VERSION_METADATA', type: 'version_metadata' },
    { name: 'DOCS_ASSETS', type: 'assets' },
    {
      name: 'AUTH_LIMITER',
      type: 'ratelimit',
      namespace_id: '17',
      simple: { limit: 60, period: 60 },
    },
  ];
  const version = {
    resources: { bindings, script_runtime: { compatibility_date: config.compatibility_date } },
  };
  checkDocsBindings(version, config);
  for (const extra of [
    { name: 'OP_PRIVATE_JWK', type: 'secret_text' },
    { name: 'CLAIM_STORE', type: 'service', service: 'op' },
    { name: 'OWNER_DB', type: 'd1', database_id: 'owner-db' },
    { name: 'VAULT_BLOBS', type: 'r2_bucket', bucket_name: 'owner-vault' },
  ])
    assert.throws(() =>
      checkDocsBindings(
        { resources: { ...version.resources, bindings: [...bindings, extra] } },
        config,
      ),
    );
  for (const [name, key, value] of [
    ['DB', 'database_id', 'owner-db'],
    ['AUTH_LIMITER', 'namespace_id', 'wrong-limiter'],
    ['DOCS_ASSETS', 'type', 'service'],
  ]) {
    const changed = structuredClone(version);
    changed.resources.bindings.find((binding) => binding.name === name)![key!] = value;
    assert.throws(() => checkDocsBindings(changed, config));
  }
});
