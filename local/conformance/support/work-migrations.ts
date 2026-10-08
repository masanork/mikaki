/** Explicit local qualification migrations; production uses its separate ledger. */
import { readFile, readdir } from 'node:fs/promises';
import { applyWorkSchema } from './work-schema.ts';
import type { D1Database } from '@cloudflare/workers-types';
export async function applyWorkMigrations(db: D1Database, through = 12) {
  await applyWorkSchema(db, String(through).padStart(4, '0'));
}

export async function applySqliteBaseline(db: import('node:sqlite').DatabaseSync) {
  const directory = new URL('../../../crates/worker/migrations/', import.meta.url);
  for (const name of (await readdir(directory)).filter((n) => n.endsWith('.sql')).sort())
    db.exec(await readFile(new URL(name, directory), 'utf8'));
}
