import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { checkBindings, sourceIsCurrent } from './deploy-production.ts';

test('OP Queue producer/consumer config is source-bound and isolated from local queues', () => {
  const production = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
  assert.deepEqual(production.queues.producers, [
    { binding: 'LOGOUT_QUEUE', queue: 'mikaki-logout-wakeups' },
  ]);
  assert.deepEqual(production.queues.consumers, [
    {
      queue: 'mikaki-logout-wakeups',
      max_batch_size: 1,
      max_batch_timeout: 1,
      max_retries: 3,
      dead_letter_queue: 'mikaki-logout-wakeups-dlq',
      max_concurrency: 2,
      retry_delay: 30,
    },
  ]);
  assert.equal(production.observability.traces.enabled, true);
  for (const path of [
    'crates/worker/wrangler.jsonc',
    'crates/worker/wrangler.conformance.jsonc',
    'crates/worker/wrangler.recipient-local.jsonc',
  ]) {
    const local = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(local.queues.producers[0].binding, 'LOGOUT_QUEUE');
    assert.notEqual(local.queues.producers[0].queue, 'mikaki-logout-wakeups');
    assert.equal(local.queues.consumers[0].queue, local.queues.producers[0].queue);
    assert.notEqual(local.queues.consumers[0].dead_letter_queue, 'mikaki-logout-wakeups-dlq');
    assert.equal(local.queues.producers[0].remote, false);
  }
});

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
    { name: 'LOGOUT_QUEUE', type: 'queue', queue_name: 'mikaki-logout-wakeups' },
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
    'LOGOUT_QUEUE',
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

test('activation rejects unknown and duplicate bindings and exacts default service entrypoints', () => {
  const config = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
  const bindings: Record<string, unknown>[] = [
    { name: 'DB', type: 'd1', database_id: config.d1_databases[0].database_id },
    { name: 'VAULT_BLOBS', type: 'r2_bucket', bucket_name: 'mikaki-auth-vault' },
    { name: 'USERINFO_CLAIMS', type: 'service', service: 'mikaki-auth-claims' },
    { name: 'LOGOUT_QUEUE', type: 'queue', queue_name: 'mikaki-logout-wakeups' },
    { name: 'CF_VERSION_METADATA', type: 'version_metadata' },
    { name: 'OP_PRIVATE_JWK', type: 'secret_text' },
    { name: 'MIKAKI_READY_TOKEN', type: 'secret_text' },
    ...Object.entries(config.vars).map(([name, text]) => ({ name, text, type: 'plain_text' })),
  ];
  const version = {
    resources: { bindings, script_runtime: { compatibility_date: config.compatibility_date } },
  };
  for (const extra of [
    { name: 'EXTRA_KV', type: 'kv_namespace', namespace_id: 'unapproved' },
    { name: 'EXTRA_SERVICE', type: 'service', service: 'unapproved-worker' },
    { name: 'EXTRA_SECRET', type: 'secret_text' },
    { name: 'EXTRA_ASSETS', type: 'assets' },
    { name: 'EXTRA_LIMITER', type: 'ratelimit', namespace_id: '17' },
  ]) {
    assert.throws(
      () =>
        checkBindings(
          { resources: { ...version.resources, bindings: [...bindings, extra] } },
          config,
        ),
      new RegExp(`Unexpected binding ${extra.name}`),
    );
  }
  assert.throws(
    () =>
      checkBindings(
        { resources: { ...version.resources, bindings: [...bindings, bindings[0]] } },
        config,
      ),
    /Duplicate binding DB/,
  );
  assert.throws(
    () => checkBindings(version, { ...config, secrets: { required: ['DB'] } }),
    /Duplicate configured binding DB/,
  );
  const extraEntrypoint = structuredClone(version);
  extraEntrypoint.resources.bindings.find(
    (binding) => binding.name === 'USERINFO_CLAIMS',
  )!.entrypoint = 'UnexpectedEntrypoint';
  assert.throws(
    () => checkBindings(extraEntrypoint, config),
    /Binding USERINFO_CLAIMS: entrypoint/,
  );
  const wrongQueue = structuredClone(version);
  wrongQueue.resources.bindings.find((binding) => binding.name === 'LOGOUT_QUEUE')!.queue_name =
    'unapproved-queue';
  assert.throws(() => checkBindings(wrongQueue, config), /Binding LOGOUT_QUEUE: queue_name/);
  const wrongConsumer = structuredClone(config);
  wrongConsumer.queues.consumers[0].dead_letter_queue = 'unapproved-dlq';
  assert.throws(() => checkBindings(version, wrongConsumer), /strictly deep-equal/);
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
  version.resources.bindings[2]!.secret_name = 'VAULT_USERINFO_MLKEM_A';
  const defaultEntrypoint = structuredClone(version);
  delete defaultEntrypoint.resources.bindings[0]!.entrypoint;
  assert.throws(() => checkBindings(defaultEntrypoint, config), /Binding CLAIM_STORE: entrypoint/);
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
