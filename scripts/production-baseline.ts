import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
const gate: (ok: unknown, message: string) => asserts ok = (ok, message) => assert.ok(ok, message);

/** Conservative SQLite tokenization: ignore layout/comments, never bytes inside quotes.
 * Token boundaries remain explicit, so `IS NOT` cannot equal `ISNOT`, nor `- -` a comment.
 * This is not a semantic SQL rewriter: case, operators, numbers and quoted bytes stay exact.
 */
export function canonicalSql(sql: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < sql.length) {
    const rest = sql.slice(i);
    const whitespace = /^[ \t\r\n\f]+/.exec(rest);
    if (whitespace) {
      i += whitespace[0].length;
      continue;
    }
    if (rest.startsWith('--')) {
      const end = sql.indexOf('\n', i + 2);
      i = end < 0 ? sql.length : end + 1;
      continue;
    }
    if (rest.startsWith('/*')) {
      const end = sql.indexOf('*/', i + 2);
      gate(end >= 0, 'Unterminated schema SQL comment.');
      i = end + 2;
      continue;
    }
    // SQLite blob literals are one token: X'AB' must differ from X 'AB'.
    const blob = /^[xX]'[0-9a-fA-F]*'/.exec(rest);
    if (blob) {
      tokens.push(blob[0]);
      i += blob[0].length;
      continue;
    }
    const quote = sql[i]!;
    if (["'", '"', '`', '['].includes(quote)) {
      const start = i++;
      const close = quote === '[' ? ']' : quote;
      let closed = false;
      while (i < sql.length) {
        if (sql[i++] !== close) continue;
        if (quote !== '[' && sql[i] === close) {
          i++;
          continue;
        }
        closed = true;
        break;
      }
      gate(closed, 'Unterminated schema SQL quote.');
      tokens.push(sql.slice(start, i));
      continue;
    }
    const token =
      /^(?:[A-Za-z_\u0080-\uffff][A-Za-z_0-9$\u0080-\uffff]*|0[xX][0-9a-fA-F](?:_?[0-9a-fA-F])*|(?:\d(?:_?\d)*(?:\.(?:\d(?:_?\d)*)?)?|\.\d(?:_?\d)*)(?:[eE][+-]?\d(?:_?\d)*)?|->>|->|<=|>=|!=|==|<>|\|\||<<|>>|[(),.;+*\/%<>=~&|!-])/.exec(
        rest,
      );
    gate(token, 'Unsupported schema SQL token.');
    tokens.push(token[0]);
    i += token[0].length;
  }
  if (tokens.at(-1) === ';') tokens.pop();
  return tokens;
}

export const BASELINE_NAME = '0001_owner_vault_initial.sql';
export const BASELINE_SCHEMA_QUERY = `SELECT type,name,tbl_name,sql FROM sqlite_master
WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*' AND name != '_cf_KV' AND tbl_name != '_cf_KV'
AND name != 'd1_migrations' AND tbl_name != 'd1_migrations' ORDER BY type,name`;
type SchemaRow = { type: string; name: string; tbl_name: string; sql: string };
function canonicalSchema(rows: SchemaRow[]) {
  return rows.map((row) => ({ ...row, sql: canonicalSql(row.sql) }));
}
/** Verify the actual baseline, including checks/indexes/triggers, before any upload.
 * A filename-only ledger cannot establish the removal of historical token authority.
 */
export function assertProductionBaseline(
  baseline: string,
  ledger: { name: string }[],
  remoteSchema: SchemaRow[],
) {
  assert.deepEqual(
    ledger.map((row) => row.name),
    [BASELINE_NAME],
    'Production must have the single reset baseline ledger',
  );
  const db = new DatabaseSync(':memory:');
  try {
    db.exec('PRAGMA foreign_keys=ON');
    db.exec(baseline);
    assert.deepEqual(
      db.prepare('PRAGMA foreign_key_check').all(),
      [],
      'Baseline foreign keys failed',
    );
    const expected = db.prepare(BASELINE_SCHEMA_QUERY).all() as SchemaRow[];
    assert.deepEqual(
      canonicalSchema(remoteSchema),
      canonicalSchema(expected),
      'Production schema differs from the reset baseline',
    );
  } finally {
    db.close();
  }
}
