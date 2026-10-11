/** Explicit local opt-in; production migration directories never include this schema. */
import { readFile, readdir } from 'node:fs/promises';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import type { D1Database } from '@cloudflare/workers-types';

export const workSchemaDirectory = new URL(
  '../../../crates/worker/work-migrations/',
  import.meta.url,
);
export const baselineSchemaDirectory = new URL(
  '../../../crates/worker/migrations/',
  import.meta.url,
);

export async function schemaSql(through?: string) {
  const statements: string[] = [];
  for (const directory of [baselineSchemaDirectory, workSchemaDirectory]) {
    for (const name of (await readdir(directory)).filter((x) => x.endsWith('.sql')).sort()) {
      if (through && name.slice(0, 4) > through) continue;
      statements.push(await readFile(new URL(name, directory), 'utf8'));
    }
  }
  return statements.join('\n');
}

export async function applyWorkSchema(db: D1Database, through?: string) {
  const names = (await readdir(workSchemaDirectory)).filter((name) => name.endsWith('.sql')).sort();
  for (const name of names) {
    if (through && name.slice(0, 4) > through) continue;
    const sql = await readFile(new URL(name, workSchemaDirectory), 'utf8');
    await db.batch(splitSqlQuery(sql).map((statement) => db.prepare(statement)));
  }
}
