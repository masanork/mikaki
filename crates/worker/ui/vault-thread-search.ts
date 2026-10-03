import {
  normalizeThreadSearchText as normalize,
  threadSearchTerms,
} from './vault-thread-search-query.ts';
import { parseThreadArchive, type ThreadArchive } from './vault-thread-archive.ts';
import { threadSearchExcerpt } from './vault-thread-search-excerpt.ts';

export type SearchArchive = { id: string; revision: number; archive: ThreadArchive };
export type SearchHit = {
  thread: string;
  revision: number;
  // -1 identifies the title; other values are zero-based message positions.
  message: number;
  text: string;
};
export type SearchResult = { hits: SearchHit[]; truncated: boolean };
export type SearchCoverage = { threads: number; messages: number };

// Small adapter for the official SQLite oo1 API. The bootstrap must supply a
// ':memory:' database; this interface cannot verify a factory's storage choice.
export interface SearchDatabase {
  exec(input: string | { sql: string; bind: (string | number)[] }): unknown;
  selectObjects(sql: string, bind: (string | number)[]): Record<string, unknown>[];
  close(): void;
}
export type SearchDatabaseFactory = () => SearchDatabase;
const schema = `
PRAGMA temp_store=MEMORY;
CREATE TABLE items(id INTEGER PRIMARY KEY, thread TEXT NOT NULL, revision INTEGER NOT NULL,
 message INTEGER NOT NULL, body TEXT NOT NULL, normalized TEXT NOT NULL);
CREATE INDEX items_thread ON items(thread);
CREATE VIRTUAL TABLE ft USING fts5(normalized, content=items, content_rowid=id,
 tokenize='trigram case_sensitive 1');
`;

export class ThreadSearchProjection {
  private db: SearchDatabase | null = null;
  private allowed: string[] = [];
  private readonly createDatabase: SearchDatabaseFactory;
  constructor(createDatabase: SearchDatabaseFactory) {
    this.createDatabase = createDatabase;
  }

  replace(input: unknown): SearchCoverage {
    // A failed replacement must not leave a seemingly current, stale projection.
    this.dispose();
    if (!Array.isArray(input) || input.length > 256) throw new Error('invalid snapshot');
    const ids = new Set<string>();
    const records = input.map((value: unknown): SearchArchive => {
      if (!value || typeof value !== 'object' || Array.isArray(value))
        throw new Error('invalid record');
      const v = value as Record<string, unknown>;
      if (
        Object.keys(v).some((key) => !['id', 'revision', 'archive'].includes(key)) ||
        typeof v['id'] !== 'string' ||
        !/^[A-Za-z0-9_-]{1,128}$/.test(v['id']) ||
        ids.has(v['id']) ||
        !Number.isSafeInteger(v['revision']) ||
        (v['revision'] as number) < 1
      )
        throw new Error('invalid record');
      ids.add(v['id']);
      const archive = parseThreadArchive(v['archive']);
      if (
        [
          archive.title,
          ...archive.messages.flatMap((message) => [message.speaker, message.text]),
        ].some((text) => /[\uD800-\uDFFF]/u.test(text))
      )
        throw new Error('invalid archive unicode');
      if (new TextEncoder().encode(JSON.stringify(archive)).length > 24000)
        throw new Error('archive too large');
      return { id: v['id'], revision: v['revision'] as number, archive };
    });
    const db = this.createDatabase();
    let messages = 0;
    try {
      db.exec(schema);
      db.exec('BEGIN');
      let id = 0;
      for (const record of records) {
        const add = (message: number, body: string, searchable: string) =>
          db.exec({
            sql: 'INSERT INTO items VALUES(?,?,?,?,?,?)',
            bind: [++id, record.id, record.revision, message, body, normalize(searchable)],
          });
        add(-1, record.archive.title, record.archive.title);
        record.archive.messages.forEach((message, index) => {
          add(index, message.text, `${message.speaker}\n${message.text}`);
          messages++;
        });
      }
      db.exec("INSERT INTO ft(ft) VALUES('rebuild')");
      db.exec('COMMIT');
      this.db = db;
      this.allowed = [...ids];
      return { threads: records.length, messages };
    } catch (error) {
      db.close();
      throw error;
    }
  }

  search(query: unknown, scope: unknown): SearchResult {
    if (!this.db) throw new Error('locked');
    if (
      !Array.isArray(scope) ||
      scope.length > 256 ||
      scope.some((id: unknown) => typeof id !== 'string' || !this.allowed.includes(id))
    )
      throw new Error('invalid query');
    const terms = threadSearchTerms(query);
    if (!terms.length || !scope.length) return { hits: [], truncated: false };
    // MATCH expressions cannot represent embedded NUL; bounded instr remains literal.
    const long = terms.filter((term) => [...term].length >= 3 && !term.includes('\0'));
    const bind: (string | number)[] = [...new Set(scope as string[])];
    const conditions = [`i.thread IN (${bind.map(() => '?').join(',')})`];
    if (long.length) {
      conditions.push('ft MATCH ?');
      bind.push(long.map((term) => `"${term.replaceAll('"', '""')}"`).join(' AND '));
    }
    for (const term of terms) {
      conditions.push('instr(i.normalized, ?) > 0');
      bind.push(term);
    }
    // Stable order avoids corpus-wide bm25 statistics from affecting restricted scopes.
    const rows = this.db.selectObjects(
      `SELECT i.thread,i.revision,i.message,i.body FROM items i
       ${long.length ? 'JOIN ft ON ft.rowid=i.id' : ''}
       WHERE ${conditions.join(' AND ')} ORDER BY i.thread,i.message LIMIT 51`,
      bind,
    );
    return {
      truncated: rows.length > 50,
      hits: rows.slice(0, 50).map((row) => ({
        thread: row['thread'] as string,
        revision: row['revision'] as number,
        message: row['message'] as number,
        text: threadSearchExcerpt(row['body'] as string, terms),
      })),
    };
  }

  dispose(): void {
    const db = this.db;
    this.db = null;
    this.allowed = [];
    db?.close();
  }
}
