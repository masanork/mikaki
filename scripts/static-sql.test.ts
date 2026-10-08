import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { staticSql } from './static-sql.ts';

const extract = (files: Record<string, string>, entry = 'main.ts') =>
  staticSql([resolve(entry)], (file) => {
    const source = files[file.slice(resolve('.').length + 1)];
    if (source === undefined) throw new Error('Unexpected source file');
    return source;
  });

test('runtime operation parameters cannot create SQL capabilities', () => {
  assert.throws(
    () =>
      extract({
        'main.ts':
          "function operation(column: string) { db.prepare(`SELECT ${column} FROM agent_grant`); } operation('unused');",
      }),
    /Nonstatic/,
  );
});

test('SQL extraction preserves imported aliases and independent callback bindings', () => {
  assert.deepEqual(
    extract({
      'main.ts':
        "import { fields as columns, column as render } from './helper.js'; const column='outside'; db.prepare(`SELECT ${[...columns,'third'].map((column) => render(column)).join(',')} FROM agent_grant WHERE ${column}`);",
      'helper.ts':
        "export const fields=['first','second'] as const; export function column(value: string) { return `g.${value}`; }",
    }),
    ['SELECT g.first,g.second,g.third FROM agent_grant WHERE outside'],
  );
});

test('SQL extraction retains both static conditional alternatives', () => {
  assert.deepEqual(
    extract({
      'main.ts':
        "db.prepare(enabled ? 'SELECT first FROM agent_grant' : 'SELECT second FROM agent_grant');",
    }),
    ['SELECT first FROM agent_grant', 'SELECT second FROM agent_grant'],
  );
});

test('SQL extraction never executes dynamic code or accepts reassigned/circular bindings', () => {
  for (const source of [
    "db.prepare(fetch('https://invalid.example'))",
    "let sql='SELECT first'; sql='SELECT second'; db.prepare(sql);",
    'const first=second; const second=first; db.prepare(first);',
    'db.prepare(`SELECT ${request.value}`);',
    "let query=()=>'SELECT first'; query=()=>'SELECT second'; db.prepare(query());",
    'function query() { return query(); } db.prepare(query());',
    "function query() { if (enabled) return 'SELECT first'; return 'SELECT second'; } db.prepare(query());",
  ])
    assert.throws(() => extract({ 'main.ts': source }), /Nonstatic|Unbound/);
});

test('SQL extraction applies only the supported static replacement patterns', () => {
  assert.deepEqual(
    extract({
      'main.ts':
        "db.prepare('SELECT authorization_details'.replace(/authorization_details$/, 'scopes'));",
    }),
    ['SELECT scopes'],
  );
  assert.throws(
    () => extract({ 'main.ts': "db.prepare('SELECT first'.replace(/first/g, 'second'));" }),
    /Unsupported/,
  );
});
