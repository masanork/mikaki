/** Explicit local qualification migrations; production uses its separate ledger. */
import { readFile, readdir } from 'node:fs/promises';
import { unstable_splitSqlQuery as splitSqlQuery } from 'wrangler';
import type { D1Database } from '@cloudflare/workers-types';
export async function applyWorkMigrations(db: D1Database, through = 8) {
  const directory = new URL('../../../crates/worker/work-migrations/', import.meta.url);
  for (const name of (await readdir(directory)).filter((n) => n.endsWith('.sql')).sort()) {
    if (Number(name.slice(0, 4)) > through) continue;
    const sql = splitSqlQuery(await readFile(new URL(name, directory), 'utf8'));
    await db.batch(sql.map((statement) => db.prepare(statement)));
  }
}

export async function applySqliteBaseline(db: import('node:sqlite').DatabaseSync) {
  const directory = new URL('../../../crates/worker/migrations/', import.meta.url);
  for (const name of (await readdir(directory)).filter((n) => n.endsWith('.sql')).sort())
    db.exec(await readFile(new URL(name, directory), 'utf8'));
}
