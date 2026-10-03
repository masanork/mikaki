import { ThreadSearchProjection, type SearchDatabaseFactory } from './vault-thread-search.ts';

export interface SearchWorkerPort {
  onmessage: ((event: MessageEvent) => void) | null;
  postMessage(value: unknown): void;
}

// Called by a separately served module Worker after loading the pinned WASM runtime.
// No keys, Vault requests, SQL from the caller, or persistent storage are involved.
export function installThreadSearchWorker(
  port: SearchWorkerPort,
  ready: Promise<SearchDatabaseFactory>,
): void {
  let projection: ThreadSearchProjection | null = null;
  let busy = false;
  // Initialization may fail before the first request. Handle that rejection now.
  const initialized = ready.then(
    (create) => create,
    () => null,
  );
  port.onmessage = (event) => {
    const value: unknown = event.data;
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    const request = value as Record<string, unknown>;
    const id = request['id'];
    if (!Number.isSafeInteger(id) || (id as number) < 1) return;
    if (busy) {
      port.postMessage({ id, error: 'busy' });
      return;
    }
    busy = true;
    void (async () => {
      try {
        const create = await initialized;
        if (!create) throw new Error('runtime unavailable');
        projection ??= new ThreadSearchProjection(create);
        let result: unknown;
        if (request['operation'] === 'replace') result = projection.replace(request['records']);
        else if (request['operation'] === 'search')
          result = projection.search(request['query'], request['scope']);
        else throw new Error('invalid operation');
        port.postMessage({ id, result });
      } catch {
        // Exceptions can contain plaintext SQL/bind values. Never forward/log them.
        port.postMessage({ id, error: 'unavailable' });
      } finally {
        busy = false;
      }
    })();
  };
}
