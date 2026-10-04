/** D1-shaped client for fixed OP-owned statement capabilities; no SQL crosses the binding. */
export class ServiceDatabase implements D1Database {
  private service: Fetcher;
  constructor(service: Fetcher) {
    this.service = service;
  }
  prepare(query: string): D1PreparedStatement {
    return new Statement(this, query);
  }
  async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    if (
      statements.some(
        (statement) => !(statement instanceof Statement) || statement.database !== this,
      )
    )
      throw new Error('Foreign statement');
    const entries = await Promise.all(
      statements.map(async (statement) => {
        if (!(statement instanceof Statement)) throw new Error('Foreign statement');
        const digest = await crypto.subtle.digest(
          'SHA-256',
          new TextEncoder().encode(statement.query),
        );
        return {
          id: Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join(''),
          values: statement.values,
        };
      }),
    );
    const response = await this.service.fetch('https://store.internal/statements', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ statements: entries }),
    });
    if (!response.ok) throw new Error('Store unavailable or operation denied');
    return (await response.json()) as D1Result<T>[];
  }
  withSession(): D1DatabaseSession {
    return this;
  }
  getBookmark(): string | null {
    return null;
  } // every invocation uses first-primary
  async exec(): Promise<D1ExecResult> {
    throw new Error('Arbitrary SQL denied');
  }
  async dump(): Promise<ArrayBuffer> {
    throw new Error('Database export denied');
  }
}
class Statement implements D1PreparedStatement {
  readonly database: ServiceDatabase;
  readonly query: string;
  readonly values: unknown[];
  constructor(database: ServiceDatabase, query: string, values: unknown[] = []) {
    this.database = database;
    this.query = query;
    this.values = values;
  }
  bind(...values: unknown[]): D1PreparedStatement {
    return new Statement(this.database, this.query, values);
  }
  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    return (await this.database.batch<T>([this]))[0];
  }
  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    return this.all<T>();
  }
  async first<T = Record<string, unknown>>(column?: string): Promise<T | null> {
    const row = (await this.all<Record<string, unknown>>()).results[0];
    return (row === undefined ? null : column === undefined ? row : row[column]) as T | null;
  }
  raw<T = unknown[]>(options: { columnNames: true }): Promise<[string[], ...T[]]>;
  raw<T = unknown[]>(options?: { columnNames?: false }): Promise<T[]>;
  async raw(): Promise<never> {
    throw new Error('Raw query denied');
  }
}

export type AgentRuntime = Env & { DB: D1Database };
export const runtime = (env: Env): AgentRuntime => ({
  ...env,
  DB: new ServiceDatabase(env.AUTH_STORE),
});
