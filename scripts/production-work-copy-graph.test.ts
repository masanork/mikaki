import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  assertClosedProductionCopyGraph,
  assertCopyCompanionsPresent,
  CLOSED_OP_COPY_VARS,
  productionCopyCompanions,
} from './production-work-copy-graph.ts';
const config = () => JSON.parse(readFileSync('crates/worker/wrangler.production.jsonc', 'utf8'));

test('staged production graph refuses enabled gates and altered named capabilities', () => {
  assert.equal(assertClosedProductionCopyGraph(config()), true);
  for (const name of CLOSED_OP_COPY_VARS) {
    for (const value of [undefined, 'true', 'False']) {
      const changed = config();
      changed.vars[name] = value;
      assert.throws(() => assertClosedProductionCopyGraph(changed), /disabled/);
    }
  }
  for (const binding of config().services.filter((s: { binding: string }) =>
    s.binding.startsWith('WORK_'),
  )) {
    const missing = config();
    missing.services = missing.services.filter(
      (s: { binding: string }) => s.binding !== binding.binding,
    );
    assert.throws(() => assertClosedProductionCopyGraph(missing), /graph differs/);
    for (const field of ['service', 'entrypoint']) {
      const changed = config();
      changed.services.find((s: { binding: string }) => s.binding === binding.binding)[field] =
        'OpAuthorityAdmin';
      assert.throws(() => assertClosedProductionCopyGraph(changed), /graph differs/);
    }
  }
  const additional = config();
  additional.services.push({
    binding: 'WORK_ADMIN',
    service: 'mikaki-auth',
    entrypoint: 'OpAuthorityAdmin',
  });
  assert.throws(() => assertClosedProductionCopyGraph(additional), /graph differs/);
});

test('unstaged selection permits only the existing enrolled checkpoint edge', () => {
  const baseline = config();
  delete baseline.vars.WORK_COPY_BINDINGS_STAGED;
  baseline.services = baseline.services.filter(
    (s: { binding: string }) =>
      !s.binding.startsWith('WORK_') || s.binding === 'WORK_AUTHORITY_CHECKPOINT',
  );
  assert.equal(assertClosedProductionCopyGraph(baseline), false);
  const disabled = structuredClone(baseline);
  disabled.vars.WORK_SCHEMA_ENABLED = 'false';
  assert.throws(() => assertClosedProductionCopyGraph(disabled), /graph differs/);
  disabled.services = disabled.services.filter(
    (s: { binding: string }) => s.binding !== 'WORK_AUTHORITY_CHECKPOINT',
  );
  assert.equal(assertClosedProductionCopyGraph(disabled), false);
  const bad = config();
  bad.vars.WORK_COPY_BINDINGS_STAGED = 'False';
  assert.throws(() => assertClosedProductionCopyGraph(bad), /Invalid/);
});

test('promotion requires all separately provisioned companions and a bounded unique roster', () => {
  const roster = productionCopyCompanions().map((id) => ({ id }));
  assert.equal(roster.length, 13);
  assertCopyCompanionsPresent(roster);
  for (const row of roster)
    assert.throws(() => assertCopyCompanionsPresent(roster.filter((r) => r !== row)), /absent/);
  for (const value of [
    undefined,
    {},
    [null],
    [...roster, roster[0]],
    Array.from({ length: 101 }, (_, i) => ({ id: String(i) })),
  ])
    assert.throws(() => assertCopyCompanionsPresent(value));
});
