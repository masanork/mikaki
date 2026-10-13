/** Staged private bindings. Productive copy activation requires a separate reviewed rollout. */
import assert from 'node:assert/strict';
import { COPY_BINDING_EDGES } from './work-copy-binding-plan.ts';
import { COPY_RUNTIME_MODULES } from './work-copy-runtime-packet.ts';
import { PRODUCTION_WORK_TARGET } from './production-work-adoption.ts';

export const PRODUCTION_COPY_PREFIX = 'mikaki-work';
export const CLOSED_OP_COPY_VARS = [
  'WORK_COPY_EXECUTION_ENABLED',
  'WORK_EFFECT_STORE_ENABLED',
  'WORK_MINT_STORE_ENABLED',
  'WORK_GIT_STORE_ENABLED',
  'WORK_GIT_EXECUTION_ENABLED',
  'WORK_PREPARATION_VERIFY_ENABLED',
] as const;
type Service = { binding: string; service: string; entrypoint?: string };
type Config = { vars: Record<string, string>; services?: Service[] };
const checkpoint = {
  binding: 'WORK_AUTHORITY_CHECKPOINT',
  service: PRODUCTION_WORK_TARGET.checkpoint,
  entrypoint: 'WorkCheckpointService',
};
export function productionCopyCompanions() {
  return COPY_RUNTIME_MODULES.filter(([id]) => id !== 'checkpoint').map(
    ([id]) => `${PRODUCTION_COPY_PREFIX}-${id}`,
  );
}

/** Exact named edges only; additional capabilities and enabled gates refuse promotion. */
export function assertClosedProductionCopyGraph(config: Config) {
  const selected = config.vars.WORK_COPY_BINDINGS_STAGED;
  assert.ok(
    selected === undefined || ['true', 'false'].includes(selected),
    'Invalid copy binding stage',
  );
  const staged = selected === 'true';
  assert.equal(
    config.vars.WORK_COPY_ACTIVATION_PROFILE,
    'closed',
    'Ordinary copy activation profile must remain closed',
  );
  assert.equal(
    config.vars.WORK_COPY_ACTIVATION_DISCLOSURE_DIGEST,
    undefined,
    'Ordinary promotion must not retain a productive disclosure selector',
  );
  if (staged) {
    assert.equal(config.vars.WORK_SCHEMA_ENABLED, 'true', 'Copy bindings require enrolled schema');
    for (const name of CLOSED_OP_COPY_VARS)
      assert.equal(config.vars[name], 'false', 'Staged copy gates must remain disabled');
  }
  const expected: Service[] = staged
    ? COPY_BINDING_EDGES.filter(([from]) => from === 'op').map(([, binding, to, entrypoint]) => ({
        binding,
        service:
          to === 'checkpoint'
            ? PRODUCTION_WORK_TARGET.checkpoint
            : `${PRODUCTION_COPY_PREFIX}-${to}`,
        entrypoint,
      }))
    : config.vars.WORK_SCHEMA_ENABLED === 'true'
      ? [checkpoint]
      : [];
  const sort = (services: Service[]) =>
    [...services].sort((a, b) => a.binding.localeCompare(b.binding));
  assert.deepEqual(
    sort(config.services?.filter(({ binding }) => binding.startsWith('WORK_')) ?? []),
    sort(expected),
    'Production Work named capability graph differs from the closed selection',
  );
  return staged;
}

/** New companions are provisioned separately; ordinary OP promotions never create them. */
export function assertCopyCompanionsPresent(value: unknown) {
  assert.ok(Array.isArray(value) && value.length <= 100, 'Bounded copy companion roster required');
  const names = value.map((item: unknown) => {
    assert.ok(item && typeof item === 'object' && 'id' in item && typeof item.id === 'string');
    return item.id;
  });
  assert.equal(new Set(names).size, names.length, 'Duplicate Worker roster identity');
  assert.ok(
    productionCopyCompanions().every((name) => names.includes(name)),
    'Closed copy companion is absent',
  );
}

/** Ordinary CI must not replace an operator's active copy/cleanup configuration. */
export async function closedCopyDeployment(get: (path: string) => Promise<unknown>, path: string) {
  const active = async () => {
    const envelope = (await get(path + '/deployments?page=1&per_page=1')) as {
      result: {
        deployments: { strategy: string; versions: { version_id: string; percentage: number }[] }[];
      };
    };
    const deployments = envelope.result.deployments;
    assert.equal(deployments.length, 1, 'Unambiguous current OP deployment required');
    assert.equal(deployments[0]!.strategy, 'percentage');
    const versions = deployments[0]!.versions;
    assert.equal(versions.length, 1, 'Single current OP version required');
    assert.equal(versions[0]!.percentage, 100);
    assert.match(versions[0]!.version_id, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
    return versions[0]!.version_id;
  };
  const id = await active();
  const envelope = (await get(path + '/versions/' + id)) as {
    result: {
      id: string;
      resources: { bindings: { type: string; name: string; text?: string }[] };
    };
  };
  assert.equal(envelope.result.id, id);
  const bindings = envelope.result.resources.bindings;
  assert.ok(Array.isArray(bindings) && bindings.length <= 128);
  assert.equal(new Set(bindings.map((b) => b.name)).size, bindings.length);
  for (const name of CLOSED_OP_COPY_VARS) {
    const binding = bindings.find((b) => b.name === name);
    assert.ok(
      !binding || (binding.type === 'plain_text' && binding.text === 'false'),
      'Active Work copy requires separate reviewed deactivation',
    );
  }
  const profile = bindings.find((b) => b.name === 'WORK_COPY_ACTIVATION_PROFILE');
  assert.ok(
    !profile || (profile.type === 'plain_text' && profile.text === 'closed'),
    'Active Work copy requires separate reviewed deactivation',
  );
  assert.ok(
    !bindings.some((b) => b.name === 'WORK_COPY_ACTIVATION_DISCLOSURE_DIGEST'),
    'Active Work copy requires separate reviewed deactivation',
  );
  assert.equal(await active(), id, 'Current OP deployment changed during preflight');
  return id;
}
