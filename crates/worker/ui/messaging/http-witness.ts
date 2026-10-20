/** Same-origin owner-session transport for the independent device journal head. */
import type { Head, HeadWitness } from './device-store.js';

function parse(value: unknown): Head {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('invalid_witness_response');
  const head = value as Head;
  if (
    Object.keys(head).sort().join(',') !== 'hash,revision' ||
    !Number.isSafeInteger(head.revision) ||
    head.revision < 0 ||
    (head.revision === 0
      ? head.hash !== null
      : typeof head.hash !== 'string' || !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(head.hash))
  )
    throw new Error('invalid_witness_response');
  return { revision: head.revision, hash: head.hash };
}
async function boundedJson(response: Response): Promise<unknown> {
  if (
    !response.headers.get('Content-Type')?.startsWith('application/json') ||
    !response.headers
      .get('Cache-Control')
      ?.split(',')
      .map((v) => v.trim())
      .includes('no-store') ||
    !response.body
  )
    throw new Error('invalid_witness_response');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > 1024) {
        await reader.cancel();
        throw new Error('invalid_witness_response');
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally {
    reader.releaseLock();
  }
}
export class AuthenticatedHeadWitness implements HeadWitness {
  readonly #origin: string;
  readonly #signal: AbortSignal | undefined;
  readonly #transport: typeof fetch;
  constructor(
    origin = location.origin,
    signal?: AbortSignal,
    transport: typeof fetch = (...args) => fetch(...args),
  ) {
    const parsed = new URL(origin);
    if (parsed.protocol !== 'https:' || parsed.origin !== origin || origin !== location.origin)
      throw new Error('witness_origin_mismatch');
    this.#origin = origin;
    this.#signal = signal;
    this.#transport = transport;
  }
  async #request(scope: string, value?: { expected: Head; next: Head }): Promise<Head> {
    if (!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(scope))
      throw new Error('invalid_witness_scope');
    const response = await this.#transport(`${this.#origin}/messaging/heads/${scope}`, {
      method: value ? 'PUT' : 'GET',
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      headers: value
        ? { 'Content-Type': 'application/json', Accept: 'application/json' }
        : { Accept: 'application/json' },
      ...(value ? { body: JSON.stringify(value) } : {}),
      signal: this.#signal,
    });
    if (response.status === 401 || response.status === 403)
      throw new Error('witness_authentication_required');
    if (response.status === 404) throw new Error('witness_scope_missing');
    if (response.status !== 200) throw new Error('witness_unavailable');
    return parse(await boundedJson(response));
  }
  read(scope: string): Promise<Head> {
    return this.#request(scope);
  }
  compareAndSet(scope: string, expected: Head, next: Head): Promise<Head> {
    const selected = { expected: parse(expected), next: parse(next) };
    if (selected.next.revision !== selected.expected.revision + 1)
      throw new Error('invalid_witness_transition');
    return this.#request(scope, selected);
  }
}
