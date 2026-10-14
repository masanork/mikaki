import { archiveAppOrigin } from './vault-thread-archive.ts';
import { OWNER_WORKSPACE_MAX_BYTES } from './vault-owner-crypto.ts';

export const WORKSPACE_SNAPSHOT_MAX_BYTES = OWNER_WORKSPACE_MAX_BYTES - 29;
export const WORKSPACE_COLLECTION = 'workspace-snapshots';
export const WORKSPACE_KIND = 'workspace-snapshot';
type ObjectValue = Record<string, unknown>;
export type WorkspaceSnapshot = {
  format: 'cloudflare-os-workspace';
  version: 1;
  source: { origin: string; workspaceId: string; capturedAt: string };
  title: string;
  records: [string, unknown][];
  gadgets: {
    id: number;
    state: { schema: ObjectValue[]; tables: ObjectValue[]; kv: [string, unknown][] };
  }[];
};
function object(value: unknown): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid snapshot');
  return value as ObjectValue;
}
function exact(value: ObjectValue, fields: string): void {
  if (Object.keys(value).sort().join(',') !== fields) throw new Error('invalid snapshot fields');
}
function list(value: unknown, max: number): unknown[] {
  if (!Array.isArray(value) || value.length > max) throw new Error('invalid snapshot list');
  return value;
}
function portable(value: unknown, depth = 0): void {
  if (depth > 32) throw new Error('snapshot nesting limit');
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  )
    return;
  const v = object(value);
  exact(v, 'type,value');
  if (v['type'] === 'undefined' && v['value'] === null) return;
  if (
    v['type'] === 'bytes' &&
    typeof v['value'] === 'string' &&
    /^(?:[0-9a-f]{2})*$/.test(v['value'])
  )
    return;
  if (
    v['type'] === 'date' &&
    typeof v['value'] === 'string' &&
    new Date(v['value']).toISOString() === v['value']
  )
    return;
  if (v['type'] === 'array' || v['type'] === 'set') {
    for (const item of list(v['value'], 10000)) portable(item, depth + 1);
    return;
  }
  if (v['type'] === 'object' || v['type'] === 'map') {
    const seen = new Set<string>();
    for (const item of list(v['value'], 10000)) {
      const pair = list(item, 2);
      if (pair.length !== 2) throw new Error('invalid snapshot pair');
      if (v['type'] === 'object') {
        if (
          typeof pair[0] !== 'string' ||
          ['__proto__', 'constructor', 'prototype'].includes(pair[0]) ||
          seen.has(pair[0])
        )
          throw new Error('invalid snapshot key');
        seen.add(pair[0]);
      }
      portable(pair[0], depth + 1);
      portable(pair[1], depth + 1);
    }
    return;
  }
  throw new Error('invalid portable value');
}
function pairs(value: unknown): [string, unknown][] {
  const seen = new Set<string>();
  for (const item of list(value, 10000)) {
    const pair = list(item, 2);
    if (pair.length !== 2 || typeof pair[0] !== 'string' || seen.has(pair[0]))
      throw new Error('invalid snapshot pair');
    seen.add(pair[0]);
    portable(pair[1]);
  }
  return value as [string, unknown][];
}
// Mikaki validates the portable envelope; it never runs archived SQL or app code.
export function parseWorkspaceSnapshot(text: string): WorkspaceSnapshot {
  if (
    text.length > WORKSPACE_SNAPSHOT_MAX_BYTES ||
    new TextEncoder().encode(text).length > WORKSPACE_SNAPSHOT_MAX_BYTES
  )
    throw new Error('snapshot exceeds 2 MiB');
  const v = object(JSON.parse(text));
  exact(v, 'format,gadgets,records,source,title,version');
  const source = object(v['source']);
  exact(source, 'capturedAt,origin,workspaceId');
  if (
    v['format'] !== 'cloudflare-os-workspace' ||
    v['version'] !== 1 ||
    typeof v['title'] !== 'string' ||
    !v['title'].trim() ||
    v['title'].length > 256 ||
    typeof source['origin'] !== 'string' ||
    !archiveAppOrigin(source['origin']) ||
    typeof source['workspaceId'] !== 'string' ||
    !/^[0-9a-f]{64}$/.test(source['workspaceId']) ||
    typeof source['capturedAt'] !== 'string' ||
    new Date(source['capturedAt']).toISOString() !== source['capturedAt']
  )
    throw new Error('invalid snapshot identity');
  pairs(v['records']);
  const ids = new Set<number>();
  for (const item of list(v['gadgets'], 16)) {
    const g = object(item);
    exact(g, 'id,state');
    if (
      typeof g['id'] !== 'number' ||
      !Number.isSafeInteger(g['id']) ||
      g['id'] < 0 ||
      ids.has(g['id'])
    )
      throw new Error('invalid gadget');
    ids.add(g['id']);
    const state = object(g['state']);
    exact(state, 'kv,schema,tables');
    pairs(state['kv']);
    for (const item of list(state['schema'], 256)) {
      const schema = object(item);
      exact(schema, 'name,sql,type');
      if (
        !['table', 'index', 'view', 'trigger'].includes(String(schema['type'])) ||
        typeof schema['name'] !== 'string' ||
        typeof schema['sql'] !== 'string'
      )
        throw new Error('invalid schema');
    }
    for (const item of list(state['tables'], 128)) {
      const t = object(item);
      if (
        !['columns,name,rows', 'columns,name,rows,sequence'].includes(
          Object.keys(t).sort().join(','),
        ) ||
        typeof t['name'] !== 'string' ||
        list(t['columns'], 128).some((c) => typeof c !== 'string') ||
        (t['sequence'] !== undefined &&
          (typeof t['sequence'] !== 'number' ||
            !Number.isSafeInteger(t['sequence']) ||
            t['sequence'] < 0))
      )
        throw new Error('invalid table');
      for (const row of list(t['rows'], 10000)) {
        if (list(row, 128).length !== (t['columns'] as unknown[]).length)
          throw new Error('invalid row');
        for (const cell of row as unknown[]) portable(cell);
      }
    }
  }
  return v as WorkspaceSnapshot;
}
