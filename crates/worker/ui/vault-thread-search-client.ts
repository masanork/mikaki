import type { SearchArchive, SearchCoverage, SearchResult } from './vault-thread-search.ts';

export class ThreadSearchClient {
  private worker: Worker | null;
  private sequence = 0;
  private pending: {
    id: number;
    resolve: (value: unknown) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  } | null = null;
  private readonly stop = () => this.dispose();
  private readonly visibility = () => {
    if (document.visibilityState === 'hidden') this.dispose();
  };

  constructor(
    worker: Worker,
    private readonly signal: AbortSignal,
  ) {
    this.worker = worker;
    worker.onmessage = (event: MessageEvent<{ id: number; error?: string; result?: unknown }>) => {
      const pending = this.pending;
      if (!pending || pending.id !== event.data.id || !this.worker) return;
      this.pending = null;
      clearTimeout(pending.timer);
      if (event.data.error) pending.reject(new Error('search unavailable'));
      else pending.resolve(event.data.result);
    };
    worker.onerror = () => this.dispose();
    worker.onmessageerror = () => this.dispose();
    signal.addEventListener('abort', this.stop, { once: true });
    window.addEventListener('pagehide', this.stop);
    document.addEventListener('visibilitychange', this.visibility);
    if (signal.aborted || document.visibilityState === 'hidden') this.dispose();
  }

  private request(value: Record<string, unknown>): Promise<unknown> {
    if (!this.worker) return Promise.reject(new Error('search locked'));
    // One request at a time bounds plaintext cloning and the Worker queue.
    if (this.pending) return Promise.reject(new Error('search busy'));
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(this.stop, 15000);
      this.pending = { id, resolve, reject, timer };
      try {
        this.worker!.postMessage({ id, ...value });
      } catch {
        this.dispose();
      }
    });
  }

  async replace(records: SearchArchive[]): Promise<SearchCoverage> {
    return (await this.request({ operation: 'replace', records })) as SearchCoverage;
  }
  async search(query: string, scope: string[]): Promise<SearchResult> {
    return (await this.request({ operation: 'search', query, scope })) as SearchResult;
  }
  dispose(): void {
    this.worker?.terminate();
    this.worker = null;
    const pending = this.pending;
    this.pending = null;
    if (pending) {
      clearTimeout(pending.timer);
      pending.reject(new Error('search locked'));
    }
    this.signal.removeEventListener('abort', this.stop);
    window.removeEventListener('pagehide', this.stop);
    document.removeEventListener('visibilitychange', this.visibility);
  }
}
