/** Fixed-origin GET metadata only. Never request script content or secret endpoints. */
const ORIGIN = 'https://api.cloudflare.com/client/v4';
const MAX_WORKERS = 100;
const MAX_BYTES = 2 * 1024 * 1024;
const namePattern = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const bindingTypes = new Set([
  'd1',
  'service',
  'plain_text',
  'json',
  'secret_text',
  'secrets_store_secret',
  'version_metadata',
  'r2_bucket',
  'kv_namespace',
  'durable_object_namespace',
  'assets',
  'analytics_engine',
  'queue',
  'ratelimit',
  'ai',
  'hyperdrive',
  'dispatch_namespace',
  'mtls_certificate',
  'logfwdr',
  'wasm_module',
  'text_blob',
  'data_blob',
  'send_email',
  'pipelines',
  'images',
  'browser',
  'worker_loader',
  'vectorize',
  'workflow',
]);
type Row = Record<string, unknown>;
export type MetadataGet = (path: string) => Promise<unknown>;
export type InventoryTarget = {
  account: string;
  database_id: string;
  qualified_source: string;
  op: string;
  claim: string;
  logout_queue: string;
  logout_dlq: string;
  versions: { op: string; claim: string };
};
type Bindings = {
  databases: { name: string; database_id: string }[];
  services: { name: string; service: string; environment?: string; entrypoint?: string }[];
  r2_buckets: { name: string; bucket_name: string }[];
  queues: { name: string; queue_name: string }[];
};
type Worker = { name: string; settings: Bindings; versions: ({ id: string } & Bindings)[] };
type LogoutQueues = {
  producer: { name: string; queue_id: string; queue_name: string };
  dead_letter: { name: string; queue_id: string; queue_name: string };
  consumer: {
    script_name: string;
    batch_size: number;
    max_batch_timeout_ms: number;
    max_retries: number;
    max_concurrency: number;
    retry_delay: number;
    dead_letter_queue: string;
  };
};
export class InventoryError extends Error {}
function gate(ok: unknown, message: string): asserts ok {
  if (!ok) throw new InventoryError(message);
}
function row(value: unknown): value is Row {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function safeName(value: unknown): string {
  gate(typeof value === 'string' && namePattern.test(value), 'Malformed Worker/binding name.');
  return value;
}
function uuid(value: unknown): string {
  gate(typeof value === 'string' && uuidPattern.test(value), 'Malformed metadata resource ID.');
  return value;
}
const same = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);
function result(value: unknown): unknown {
  gate(
    row(value) && value.success === true && 'result' in value,
    'Cloudflare metadata did not succeed.',
  );
  return value.result;
}

/** Never access binding text/json/secret values or copy whole binding objects. */
export function projectBindings(value: unknown, requireAgentAbsent = false): Bindings {
  gate(Array.isArray(value) && value.length <= 256, 'Missing or excessive Worker bindings.');
  const names = new Set<string>();
  const projected: Bindings = { databases: [], services: [], r2_buckets: [], queues: [] };
  for (const binding of value) {
    gate(row(binding), 'Malformed Worker binding.');
    const name = safeName(binding.name);
    gate(!names.has(name), 'Duplicate Worker binding.');
    names.add(name);
    gate(
      !requireAgentAbsent || name !== 'AGENT_ACCESS',
      'AGENT_ACCESS binding is present; dormant rollout requires review.',
    );
    gate(
      typeof binding.type === 'string' && bindingTypes.has(binding.type),
      'Unknown Worker binding type; review required.',
    );
    if (binding.type === 'd1')
      projected.databases.push({ name, database_id: uuid(binding.database_id) });
    if (binding.type === 'r2_bucket')
      projected.r2_buckets.push({ name, bucket_name: safeName(binding.bucket_name) });
    if (binding.type === 'queue')
      projected.queues.push({ name, queue_name: safeName(binding.queue_name) });
    if (binding.type === 'service') {
      const service = safeName(binding.service);
      const environment =
        binding.environment === undefined ? undefined : safeName(binding.environment);
      projected.services.push({
        name,
        service,
        ...(environment === undefined ? {} : { environment }),
        ...(binding.entrypoint === undefined ? {} : { entrypoint: safeName(binding.entrypoint) }),
      });
    }
  }
  const order = (a: { name: string }, b: { name: string }) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  projected.databases.sort(order);
  projected.services.sort(order);
  projected.r2_buckets.sort(order);
  projected.queues.sort(order);
  return projected;
}

async function roster(get: MetadataGet, base: string): Promise<string[]> {
  // The official list endpoint is SinglePage and returns all uploaded Workers.
  // Search pagination metadata is optional and cannot establish completeness.
  // https://developers.cloudflare.com/api/typescript/resources/workers/subresources/scripts/methods/list/
  const envelope = await get(`${base}/scripts`);
  const items = result(envelope);
  gate(Array.isArray(items) && items.length <= MAX_WORKERS, 'Missing or excessive Worker roster.');
  gate(
    row(envelope) && envelope.result_info === undefined,
    'Unexpected Worker roster pagination; review required.',
  );
  const names: string[] = [];
  for (const item of items) {
    gate(row(item), 'Malformed Worker roster entry.');
    const name = safeName(item.id);
    gate(!names.includes(name), 'Duplicate Worker roster entry.');
    gate(
      item.environment_is_default === undefined || item.environment_is_default === true,
      'Nondefault/unknown Worker environment requires review.',
    );
    if (item.environment_name !== undefined || item.service_name !== undefined) {
      gate(item.environment_is_default === true, 'Unqualified Worker environment requires review.');
      if (item.environment_name !== undefined) safeName(item.environment_name);
      if (item.service_name !== undefined)
        gate(
          safeName(item.service_name) === name,
          'Worker service identity differs; review required.',
        );
    }
    names.push(name);
  }
  return names.sort();
}

async function activeVersions(get: MetadataGet, path: string): Promise<string[]> {
  // The documented first deployment is the one serving traffic, not the latest upload.
  // https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/deployments/methods/list/
  const value = result(await get(`${path}/deployments?page=1&per_page=1`));
  gate(
    row(value) && Array.isArray(value.deployments) && value.deployments.length === 1,
    'No unambiguous active Worker deployment; review required.',
  );
  const deployment = value.deployments[0];
  gate(
    row(deployment) && deployment.strategy === 'percentage' && Array.isArray(deployment.versions),
    'Unknown Worker deployment strategy.',
  );
  gate(
    deployment.versions.length >= 1 && deployment.versions.length <= 2,
    'Unexpected active Worker version count.',
  );
  const ids: string[] = [];
  let total = 0;
  for (const version of deployment.versions) {
    gate(
      row(version) &&
        typeof version.percentage === 'number' &&
        Number.isFinite(version.percentage) &&
        version.percentage > 0 &&
        version.percentage <= 100,
      'Malformed active Worker percentage.',
    );
    total += version.percentage;
    const id = uuid(version.version_id);
    gate(!ids.includes(id), 'Duplicate active Worker version.');
    ids.push(id);
  }
  gate(Math.abs(total - 100) < 0.000001, 'Active Worker percentages do not total 100.');
  return ids.sort();
}
function checkConsumer(name: string, bindings: Bindings, target: InventoryTarget) {
  const consumers = bindings.databases.filter(
    (binding) => binding.database_id === target.database_id,
  );
  if (name === target.op)
    gate(
      consumers.length === 1 &&
        consumers[0]!.name === 'DB' &&
        bindings.queues.length === 1 &&
        bindings.queues[0]!.name === 'LOGOUT_QUEUE' &&
        bindings.queues[0]!.queue_name === target.logout_queue,
      'Declared OP D1 or logout Queue binding differs.',
    );
  else if (name === target.claim) {
    gate(bindings.databases.length === 0, 'Claim Worker must not bind raw D1 storage.');
    gate(bindings.r2_buckets.length === 0, 'Claim Worker must not bind raw R2 storage.');
    gate(
      bindings.services.length === 1 &&
        bindings.services[0]!.name === 'CLAIM_STORE' &&
        bindings.services[0]!.service === target.op &&
        bindings.services[0]!.entrypoint === 'ClaimStore',
      'Claim Worker must use the named OP ClaimStore service.',
    );
  } else
    gate(
      consumers.length === 0,
      'Another ordinary Worker consumes production D1; compatibility review required.',
    );
}

async function logoutQueueMetadata(
  get: MetadataGet,
  account: string,
  target: InventoryTarget,
): Promise<LogoutQueues> {
  const pageSize = 100;
  const maxPages = 20;
  const queues: Row[] = [];
  let totalPages: number | undefined;
  let totalCount: number | undefined;
  for (let page = 1; page <= (totalPages ?? 1); page++) {
    const path = `/accounts/${account}/queues?page=${page}&per_page=${pageSize}`;
    const envelope = await get(path);
    const values = result(envelope);
    gate(Array.isArray(values) && values.length <= pageSize, 'Malformed Queue metadata page.');
    gate(row(envelope) && row(envelope.result_info), 'Queue list lacks pagination metadata.');
    const info = envelope.result_info;
    gate(
      Number.isSafeInteger(info.page) &&
        info.page === page &&
        Number.isSafeInteger(info.total_pages) &&
        Number(info.total_pages) >= 1 &&
        Number(info.total_pages) <= maxPages &&
        Number.isSafeInteger(info.total_count) &&
        Number(info.total_count) >= 1 &&
        Number.isSafeInteger(info.per_page) &&
        Number(info.per_page) === pageSize,
      'Queue list pagination is ambiguous.',
    );
    if (totalPages === undefined) {
      totalPages = Number(info.total_pages);
      totalCount = Number(info.total_count);
    } else {
      gate(
        totalPages === info.total_pages && totalCount === info.total_count,
        'Queue roster changed during pagination.',
      );
    }
    for (const value of values) {
      gate(row(value), 'Malformed Queue metadata.');
      queues.push(value);
    }
  }
  gate(queues.length === totalCount, 'Queue roster is incomplete.');
  const matches = queues.filter(
    (queue) => queue.queue_name === target.logout_queue || queue.queue_name === target.logout_dlq,
  );
  gate(matches.length === 2, 'Expected logout Queue resources are absent or ambiguous.');
  const find = (name: string) => matches.find((queue) => queue.queue_name === name);
  const producer = find(target.logout_queue);
  const deadLetter = find(target.logout_dlq);
  gate(producer && deadLetter, 'Expected logout Queue resources are absent.');
  const queueId = (value: unknown) => {
    gate(typeof value === 'string' && /^[a-f0-9]{32}$/.test(value), 'Malformed Queue identifier.');
    return value;
  };
  const producerId = queueId(producer.queue_id);
  const deadLetterId = queueId(deadLetter.queue_id);
  gate(producerId !== deadLetterId, 'Logout Queue and DLQ identifiers collide.');
  gate(
    Array.isArray(producer.producers) &&
      producer.producers.length === 1 &&
      row(producer.producers[0]) &&
      producer.producers[0].type === 'worker' &&
      producer.producers[0].script === target.op,
    'Logout Queue producer is not the qualified OP Worker.',
  );
  gate(
    Array.isArray(producer.consumers) &&
      producer.consumers.length === 1 &&
      producer.consumers_total_count === 1,
    'Logout Queue consumer is absent or ambiguous.',
  );
  const consumer = producer.consumers[0];
  gate(
    row(consumer) &&
      consumer.type === 'worker' &&
      consumer.script_name === target.op &&
      consumer.queue_name === target.logout_queue &&
      consumer.dead_letter_queue === target.logout_dlq &&
      row(consumer.settings),
    'Logout Queue consumer target or DLQ differs.',
  );
  const settings = consumer.settings;
  gate(
    settings.batch_size === 1 &&
      settings.max_wait_time_ms === 1000 &&
      settings.max_retries === 3 &&
      settings.max_concurrency === 2 &&
      settings.retry_delay === 30,
    'Logout Queue consumer bounds differ from source configuration.',
  );
  gate(
    (deadLetter.consumers_total_count ?? 0) === 0 &&
      (deadLetter.consumers === undefined ||
        (Array.isArray(deadLetter.consumers) && deadLetter.consumers.length === 0)),
    'Logout DLQ must not have an unexpected consumer.',
  );
  return {
    producer: { name: target.logout_queue, queue_id: producerId, queue_name: target.logout_queue },
    dead_letter: { name: target.logout_dlq, queue_id: deadLetterId, queue_name: target.logout_dlq },
    consumer: {
      script_name: target.op,
      batch_size: 1,
      max_batch_timeout_ms: 1000,
      max_retries: 3,
      max_concurrency: 2,
      retry_delay: 30,
      dead_letter_queue: target.logout_dlq,
    },
  };
}

export async function inspectWorkerInventory(
  get: MetadataGet,
  target: InventoryTarget,
): Promise<{
  scope: 'ordinary_account_workers_only';
  not_inventoried: readonly ['pages_functions', 'workers_for_platforms'];
  workers: Worker[];
  logout_queues: LogoutQueues;
}> {
  gate(/^[a-f0-9]{32}$/.test(target.account), 'Malformed account identifier.');
  uuid(target.database_id);
  gate(/^[a-f0-9]{40}$/.test(target.qualified_source), 'Missing qualified live source.');
  safeName(target.op);
  safeName(target.claim);
  safeName(target.logout_queue);
  safeName(target.logout_dlq);
  uuid(target.versions.op);
  uuid(target.versions.claim);
  gate(target.op !== target.claim, 'Expected distinct production Workers.');
  const base = `/accounts/${target.account}/workers`;
  const names = await roster(get, base);
  gate(
    names.includes(target.op) && names.includes(target.claim),
    'Expected production Workers are absent from the account roster.',
  );
  const workers: Worker[] = [];
  for (const name of names) {
    const path = `${base}/scripts/${name}`;
    const settings = result(await get(`${path}/settings`));
    gate(row(settings), 'Malformed Worker settings metadata.');
    const projected = projectBindings(settings.bindings, name === target.op);
    checkConsumer(name, projected, target);
    const ids = await activeVersions(get, path);
    if (name === target.op || name === target.claim)
      gate(
        same(ids, [name === target.op ? target.versions.op : target.versions.claim]),
        'Production Worker version is not the independently qualified live version.',
      );
    const versions: Worker['versions'] = [];
    for (const id of ids) {
      const version = result(await get(`${path}/versions/${id}`));
      gate(
        row(version) && version.id === id && row(version.resources),
        'Worker version identity differs.',
      );
      if (name === target.op || name === target.claim) {
        // Pinned Wrangler version views expose upload annotations at the top level.
        // Independently recorded version IDs remain mandatory; annotations alone are insufficient.
        gate(
          row(version.annotations) &&
            version.annotations['workers/tag'] === target.qualified_source.slice(0, 12) &&
            version.annotations['workers/message'] === `main CI ${target.qualified_source}`,
          'Production Worker source annotation differs from the qualified source.',
        );
      }
      const bindings = projectBindings(version.resources.bindings, name === target.op);
      checkConsumer(name, bindings, target);
      versions.push({ id, ...bindings });
    }
    workers.push({ name, settings: projected, versions });
  }
  gate(
    same(await roster(get, base), names),
    'Worker roster changed during compatibility inspection.',
  );
  for (const worker of workers) {
    const path = `${base}/scripts/${worker.name}`;
    gate(
      same(
        await activeVersions(get, path),
        worker.versions.map((version) => version.id),
      ),
      'Active Worker deployment changed during compatibility inspection.',
    );
    const settings = result(await get(`${path}/settings`));
    gate(
      row(settings) &&
        same(projectBindings(settings.bindings, worker.name === target.op), worker.settings),
      'Worker settings changed during compatibility inspection.',
    );
  }
  const logoutQueues = await logoutQueueMetadata(get, target.account, target);
  return {
    scope: 'ordinary_account_workers_only',
    not_inventoried: ['pages_functions', 'workers_for_platforms'],
    workers,
    logout_queues: logoutQueues,
  };
}

/** Existing credential only; no redirect, raw body, binding value or returned error-message logging. */
export function cloudflareMetadataGet(
  account: string,
  token: string,
  fetcher: typeof fetch = fetch,
): MetadataGet {
  gate(
    /^[a-f0-9]{32}$/.test(account) && token.length > 0,
    'Existing metadata credentials unavailable.',
  );
  const base = `/accounts/${account}/workers/`;
  const queues = `/accounts/${account}/queues`;
  return async (path) => {
    gate(
      path.startsWith(base)
        ? /^(?:scripts|scripts\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/(?:settings|deployments\?page=1&per_page=1|versions\/[a-f0-9-]{36}))$/.test(
            path.slice(base.length),
          )
        : new RegExp(`^${queues.replaceAll('/', '\\/')}\\?page=[1-9][0-9]*&per_page=100$`).test(
            path,
          ),
      'Unapproved Cloudflare metadata endpoint.',
    );
    try {
      const response = await fetcher(ORIGIN + path, {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
        redirect: 'error',
        signal: AbortSignal.timeout(15_000),
      });
      gate(response.body, `Cloudflare metadata ${response.status}: empty response.`);
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let length = 0;
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          length += value.length;
          gate(
            length <= MAX_BYTES,
            `Cloudflare metadata ${response.status}: response exceeds limit.`,
          );
          chunks.push(value);
        }
      } finally {
        await reader.cancel();
      }
      let value: unknown;
      try {
        value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        throw new InventoryError(`Cloudflare metadata ${response.status}: malformed JSON.`);
      }
      if (!response.ok || !row(value) || value.success !== true) {
        const codes =
          row(value) && Array.isArray(value.errors)
            ? value.errors
                .filter(row)
                .map((error) => error.code)
                .filter(
                  (code) =>
                    Number.isSafeInteger(code) && Number(code) >= 1000 && Number(code) <= 999999,
                )
                .slice(0, 5)
            : [];
        throw new InventoryError(
          `Cloudflare metadata ${response.status}; codes ${codes.join(',') || 'unavailable'}; endpoint ${path}.`,
        );
      }
      return value;
    } catch (error) {
      if (error instanceof InventoryError) throw error;
      throw new InventoryError(`Cloudflare metadata request failed; endpoint ${path}.`);
    }
  };
}
