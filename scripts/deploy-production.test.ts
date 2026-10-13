import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  assertWaitlistMailKey,
  checkBindings,
  checkCheckpointExposure,
  productionRuntimeSecrets,
  sourceIsCurrent,
} from './deploy-production.ts';
import { productionWorkPacketDigest } from './production-work-packet.ts';

test('existing checkpoint rollout requires explicit private subdomain and preview state', () => {
  checkCheckpointExposure({ enabled: false, previews_enabled: false });
  for (const value of [
    undefined,
    null,
    {},
    { enabled: false },
    { enabled: true, previews_enabled: false },
    { enabled: false, previews_enabled: true },
    { enabled: 'false', previews_enabled: false },
  ])
    assert.throws(() => checkCheckpointExposure(value), /disabled/);
});

test('private production checkpoint config pins scope and verifies its concrete SQLite namespace', () => {
  const config = JSON.parse(
    readFileSync('crates/work-checkpoint-worker/wrangler.production.jsonc', 'utf8'),
  );
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.equal(config.vars.WORK_BOOTSTRAP_PACKET_SHA256, productionWorkPacketDigest());
  assert.deepEqual(config.migrations, [
    { tag: 'production-checkpoint-v1', new_sqlite_classes: ['WorkCheckpoint'] },
  ]);
  const version = {
    resources: {
      script_runtime: { compatibility_date: config.compatibility_date },
      bindings: [
        ...Object.entries(config.vars).map(([name, text]) => ({ name, type: 'plain_text', text })),
        {
          name: 'CHECKPOINTS',
          type: 'durable_object_namespace',
          class_name: 'WorkCheckpoint',
          namespace_id: '1'.repeat(32),
        },
      ],
    },
  };
  checkBindings(version, config);
  const changed = structuredClone(version);
  Object.assign(changed.resources.bindings.at(-1)!, { namespace_id: '0'.repeat(32) });
  assert.throws(() => checkBindings(changed, config));
  Object.assign(changed.resources.bindings.at(-1)!, {
    namespace_id: '1'.repeat(32),
    class_name: 'OtherCheckpoint',
  });
  assert.throws(() => checkBindings(changed, config));
});

test('mail provisioning rejects malformed or noncanonical keys without exposing their value', () => {
  assertWaitlistMailKey(Buffer.alloc(32, 7).toString('base64url'));
  for (const value of [
    undefined,
    '',
    Buffer.alloc(31).toString('base64url'),
    Buffer.alloc(32).toString('base64'),
    'a'.repeat(43),
    'do-not-print-this-secret',
  ]) {
    assert.throws(
      () => assertWaitlistMailKey(value),
      (error: unknown) =>
        error instanceof Error &&
        error.message.includes('WAITLIST_MAIL_KEY must be 32 bytes') &&
        (value === '' || !error.message.includes(String(value))),
    );
  }
});

test('promotion preserves only reviewed runtime secrets and requires initial Work custody without leaking values', () => {
  const config = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
  const env = {
    OP_PRIVATE_JWK: 'synthetic signing key',
    MIKAKI_READY_TOKEN: 'synthetic readiness token',
    WAITLIST_MAIL_KEY: Buffer.alloc(32, 1).toString('base64url'),
    WORK_CREDENTIAL_KEY_V1: Buffer.alloc(32, 7).toString('base64url'),
    UNREVIEWED_SECRET: 'never include this value',
  };
  assert.deepEqual(
    Object.keys(productionRuntimeSecrets(config, env)).sort(),
    [...config.secrets.required].sort(),
  );
  assert.equal(config.vars.WORK_COPY_EXECUTION_ENABLED, 'false');
  assert.equal(config.vars.WORK_CREDENTIAL_KEY_ADMIN_ENABLED, 'true');
  for (const value of [
    undefined,
    '',
    Buffer.alloc(31).toString('base64url'),
    Buffer.alloc(32).toString('base64'),
    'do-not-print-this-secret',
  ]) {
    assert.throws(
      () => productionRuntimeSecrets(config, { ...env, WORK_CREDENTIAL_KEY_V1: value }),
      (error: unknown) =>
        error instanceof Error && (value === '' || !error.message.includes(String(value))),
    );
  }
  for (const floor of [undefined, '0', '2'])
    assert.throws(
      () =>
        productionRuntimeSecrets(
          { ...config, vars: { ...config.vars, WORK_CREDENTIAL_KEY_FLOOR: floor } },
          env,
        ),
      /floor 1/,
    );
  assert.throws(
    () =>
      productionRuntimeSecrets(
        { ...config, secrets: { required: [...config.secrets.required, 'UNREVIEWED_SECRET'] } },
        env,
      ),
    /Unreviewed/,
  );
  assert.throws(
    () =>
      productionRuntimeSecrets(
        {
          ...config,
          secrets: {
            required: config.secrets.required.filter(
              (name: string) => name !== 'WORK_CREDENTIAL_KEY_V1',
            ),
          },
        },
        env,
      ),
    /reviewed secret custody/,
  );
});

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
  assert.deepEqual(production.compatibility_flags, ['global_fetch_strictly_public']);
  for (const path of [
    'crates/worker/wrangler.jsonc',
    'crates/worker/wrangler.conformance.jsonc',
    'crates/worker/wrangler.recipient-local.jsonc',
  ]) {
    const local = JSON.parse(readFileSync(path, 'utf8'));
    assert.deepEqual(local.compatibility_flags, production.compatibility_flags);
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
    ...config.services.map(
      ({ binding, ...service }: { binding: string; service: string; entrypoint?: string }) => ({
        name: binding,
        type: 'service',
        ...service,
      }),
    ),
    { name: 'LOGOUT_QUEUE', type: 'queue', queue_name: 'mikaki-logout-wakeups' },
    { name: 'CF_VERSION_METADATA', type: 'version_metadata' },
    { name: 'OP_PRIVATE_JWK', type: 'secret_text' },
    { name: 'MIKAKI_READY_TOKEN', type: 'secret_text' },
    { name: 'WAITLIST_MAIL_KEY', type: 'secret_text' },
    { name: 'WORK_CREDENTIAL_KEY_V1', type: 'secret_text' },
    {
      name: 'ENROLLMENT_EMAIL',
      type: 'send_email',
      allowed_sender_addresses: config.send_email[0].allowed_sender_addresses,
    },
    ...Object.entries(config.vars).map(([name, text]) => ({ name, text, type: 'plain_text' })),
  ];
  const version = {
    resources: {
      bindings,
      script_runtime: {
        compatibility_date: config.compatibility_date,
        compatibility_flags: config.compatibility_flags,
      },
    },
  };
  checkBindings(version, config);
  for (const flags of [undefined, [], ['global_fetch_private_origin']]) {
    const changed = structuredClone(version);
    changed.resources.script_runtime.compatibility_flags = flags;
    assert.throws(() => checkBindings(changed, config), /compatibility flags/);
  }
  for (const removed of [
    'DB',
    'VAULT_BLOBS',
    'USERINFO_CLAIMS',
    'WORK_AUTHORITY_CHECKPOINT',
    'LOGOUT_QUEUE',
    'MIKAKI_READY_TOKEN',
    'WAITLIST_MAIL_KEY',
    'WORK_CREDENTIAL_KEY_V1',
    'ENROLLMENT_EMAIL',
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
  const wrongSender = structuredClone(version);
  wrongSender.resources.bindings.find(
    (binding) => binding.name === 'ENROLLMENT_EMAIL',
  )!.allowed_sender_addresses = ['other@example.test'];
  assert.throws(() => checkBindings(wrongSender, config), /Binding ENROLLMENT_EMAIL/);
  const changed = structuredClone(version);
  changed.resources.bindings.find((binding) => binding.name === 'DB')!.database_id = 'wrong-db';
  assert.throws(() => checkBindings(changed, config), /Binding DB/);
});

test('activation rejects unknown and duplicate bindings and exacts default service entrypoints', () => {
  const config = JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));
  const bindings: Record<string, unknown>[] = [
    { name: 'DB', type: 'd1', database_id: config.d1_databases[0].database_id },
    { name: 'VAULT_BLOBS', type: 'r2_bucket', bucket_name: 'mikaki-auth-vault' },
    ...config.services.map(
      ({ binding, ...service }: { binding: string; service: string; entrypoint?: string }) => ({
        name: binding,
        type: 'service',
        ...service,
      }),
    ),
    { name: 'LOGOUT_QUEUE', type: 'queue', queue_name: 'mikaki-logout-wakeups' },
    { name: 'CF_VERSION_METADATA', type: 'version_metadata' },
    { name: 'OP_PRIVATE_JWK', type: 'secret_text' },
    { name: 'MIKAKI_READY_TOKEN', type: 'secret_text' },
    { name: 'WAITLIST_MAIL_KEY', type: 'secret_text' },
    { name: 'WORK_CREDENTIAL_KEY_V1', type: 'secret_text' },
    {
      name: 'ENROLLMENT_EMAIL',
      type: 'send_email',
      allowed_sender_addresses: config.send_email[0].allowed_sender_addresses,
    },
    ...Object.entries(config.vars).map(([name, text]) => ({ name, text, type: 'plain_text' })),
  ];
  const version = {
    resources: {
      bindings,
      script_runtime: {
        compatibility_date: config.compatibility_date,
        compatibility_flags: config.compatibility_flags,
      },
    },
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
      script_runtime: {
        compatibility_date: config.compatibility_date,
        compatibility_flags: config.compatibility_flags,
      },
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
      script_runtime: {
        compatibility_date: config.compatibility_date,
        compatibility_flags: config.compatibility_flags,
      },
      bindings: [{ name: 'DB', type: 'd1', database_id: 'unapproved' }],
    },
  };
  assert.throws(() => checkBindings(version, config), /Unexpected storage binding DB/);
});
