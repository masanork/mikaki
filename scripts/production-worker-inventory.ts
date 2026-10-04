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
  versions: { op: string; claim: string };
};
type Bindings = {
  databases: { name: string; database_id: string }[];
  services: { name: string; service: string; environment?: string; entrypoint?: string }[];
  r2_buckets: { name: string; bucket_name: string }[];
};
type Worker = { name: string; settings: Bindings; versions: ({ id: string } & Bindings)[] };
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
  const projected: Bindings = { databases: [], services: [], r2_buckets: [] };
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
    gate(consumers.length === 1 && consumers[0]!.name === 'DB', 'Declared OP D1 binding differs.');
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

export async function inspectWorkerInventory(
  get: MetadataGet,
  target: InventoryTarget,
): Promise<{
  scope: 'ordinary_account_workers_only';
  not_inventoried: readonly ['pages_functions', 'workers_for_platforms'];
  workers: Worker[];
}> {
  gate(/^[a-f0-9]{32}$/.test(target.account), 'Malformed account identifier.');
  uuid(target.database_id);
  gate(/^[a-f0-9]{40}$/.test(target.qualified_source), 'Missing qualified live source.');
  safeName(target.op);
  safeName(target.claim);
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
  return {
    scope: 'ordinary_account_workers_only',
    not_inventoried: ['pages_functions', 'workers_for_platforms'],
    workers,
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
  return async (path) => {
    gate(
      path.startsWith(base) &&
        /^(?:scripts|scripts\/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\/(?:settings|deployments\?page=1&per_page=1|versions\/[a-f0-9-]{36}))$/.test(
          path.slice(base.length),
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
