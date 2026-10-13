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
