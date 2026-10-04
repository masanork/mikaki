import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { checkBindings, sourceIsCurrent } from './deploy-production.ts';

test('only bot metrics descendants may deploy an older source revision', () => {
  assert.equal(sourceIsCurrent([]), true);
  assert.equal(sourceIsCurrent(['metrics/history.json', 'metrics/coverage.svg']), true);
  assert.equal(sourceIsCurrent(['crates/worker/src/lib.rs']), false);
  assert.equal(sourceIsCurrent(['metrics/history.json', '.github/workflows/ci.yml']), false);
});

test('activation requires all configured native, Vault and runtime secret bindings', () => {
  const config = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
  const bindings: Record<string, unknown>[] = [
    { name: 'DB', type: 'd1', database_id: config.d1_databases[0].database_id },
    { name: 'VAULT_BLOBS', type: 'r2_bucket', bucket_name: 'mikaki-auth-vault' },
    { name: 'USERINFO_CLAIMS', type: 'service', service: 'mikaki-auth-claims' },
    { name: 'CF_VERSION_METADATA', type: 'version_metadata' },
    { name: 'OP_PRIVATE_JWK', type: 'secret_text' },
    { name: 'MIKAKI_READY_TOKEN', type: 'secret_text' },
    ...Object.entries(config.vars).map(([name, text]) => ({ name, text, type: 'plain_text' })),
  ];
  const version = {
    resources: { bindings, script_runtime: { compatibility_date: config.compatibility_date } },
  };
  checkBindings(version, config);
  for (const removed of [
    'DB',
    'VAULT_BLOBS',
    'USERINFO_CLAIMS',
    'MIKAKI_READY_TOKEN',
    'MIKAKI_ANDROID_SHA256_CERT_FINGERPRINT',
  ]) {
    assert.throws(
      () =>
        checkBindings(
          {
            resources: {
              ...version.resources,
              bindings: bindings.filter((binding) => binding.name !== removed),
            },
          },
          config,
        ),
      /Missing binding/,
    );
  }
  const changed = structuredClone(version);
  changed.resources.bindings.find((binding) => binding.name === 'DB')!.database_id = 'wrong-db';
  assert.throws(() => checkBindings(changed, config), /Binding DB/);
});

test('Claim Worker must retain its Secrets Store key binding', () => {
  const config = JSON.parse(
    readFileSync('crates/userinfo-claim-worker/wrangler.production.jsonc', 'utf8'),
  );
  const version = {
    resources: {
      script_runtime: { compatibility_date: config.compatibility_date },
      bindings: [
        { name: 'CLAIM_STORE', type: 'service', service: 'mikaki-auth', entrypoint: 'ClaimStore' },
        { name: 'MIKAKI_ISSUER', type: 'plain_text', text: 'https://auth.mikaki.org' },
        {
          name: 'VAULT_USERINFO_MLKEM_A',
          type: 'secrets_store_secret',
          store_id: config.secrets_store_secrets[0].store_id,
          secret_name: 'VAULT_USERINFO_MLKEM_A',
        },
      ],
    },
  };
  checkBindings(version, config);
  version.resources.bindings[2]!.secret_name = 'wrong-key';
  assert.throws(() => checkBindings(version, config), /Binding VAULT_USERINFO_MLKEM_A/);
});

test('downstream production bindings exclude raw storage and preserve exact named authority', () => {
  for (const path of [
    'crates/agent-worker/wrangler.example.jsonc',
    'crates/userinfo-claim-worker/wrangler.production.jsonc',
  ]) {
    const config = JSON.parse(readFileSync(path, 'utf8').replace(/,\s*([}\]])/g, '$1'));
    assert.equal(config.d1_databases, undefined);
    assert.equal(config.r2_buckets, undefined);
    assert.equal(config.vars?.MIKAKI_LEGACY_CLAIM_STORE, undefined);
  }
  const config = JSON.parse(
    readFileSync('crates/userinfo-claim-worker/wrangler.production.jsonc', 'utf8'),
  );
  const version = {
    resources: {
      script_runtime: { compatibility_date: config.compatibility_date },
      bindings: [{ name: 'DB', type: 'd1', database_id: 'unapproved' }],
    },
  };
  assert.throws(() => checkBindings(version, config), /Unexpected storage binding DB/);
});
