/** Temporary SQL fence for the one-shot, populated production adoption. */
import assert from 'node:assert/strict';
import type { SchemaRow } from './production-baseline.ts';

export function workAdoptionFences(schema: SchemaRow[]) {
  const tables = schema
    .filter(({ type }) => type === 'table')
    .map(({ name }) => name)
    .filter((name) => !['atomic_guard', 'work_authority_checkpoint'].includes(name));
  assert.ok(tables.length > 0 && tables.length < 200);
  assert.equal(new Set(tables).size, tables.length);
  return tables.flatMap((table) => {
    assert.match(table, /^[a-zA-Z_][a-zA-Z_0-9]{0,100}$/);
    return ['INSERT', 'UPDATE', 'DELETE'].map((action) => {
      const name = `work_adoption_fence_${table}_${action.toLowerCase()}`;
      return {
        name,
        create: `CREATE TRIGGER ${name} BEFORE ${action} ON "${table}" BEGIN SELECT RAISE(ABORT,'work_production_adoption_closed'); END`,
        drop: `DROP TRIGGER ${name}`,
      };
    });
  });
}
