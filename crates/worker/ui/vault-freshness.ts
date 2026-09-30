// Observations describe a server read at one time, never a guarantee of live synchronization.
export type SourceAttribute = 'name' | 'owner_note';
export type SavedHead = {
  state: 'saved' | 'deleted' | 'missing';
  revision: number;
  checkedAt: number;
};
export type SourceObservation = { head: SavedHead | null; failed: boolean };

export async function readSavedHead(
  attribute: SourceAttribute,
  request: typeof fetch = fetch,
): Promise<SavedHead> {
  const response = await request(`/vault/attributes/${attribute}`, { cache: 'no-store' });
  const etag = response.headers.get('ETag');
  const digits = etag === null ? null : /^"([1-9][0-9]*)"$/.exec(etag);
  if (etag !== null && (!digits || !Number.isSafeInteger(Number(digits[1]))))
    throw new Error('Invalid saved revision');
  const revision = digits ? Number(digits[1]) : 0;
  const body: unknown = await response.json();
  if (typeof body !== 'object' || body === null) throw new Error('Invalid saved head');
  if (response.status === 404 && 'error' in body && body.error === 'not_found') {
    return { state: revision ? 'deleted' : 'missing', revision, checkedAt: Date.now() };
  }
  if (
    !response.ok ||
    revision < 1 ||
    !('revision' in body) ||
    body.revision !== revision ||
    !('format_version' in body) ||
    !Number.isSafeInteger(body.format_version) ||
    Number(body.format_version) < 1 ||
    !('ciphertext' in body) ||
    typeof body.ciphertext !== 'string' ||
    !('owner_envelope' in body) ||
    typeof body.owner_envelope !== 'string'
  )
    throw new Error('Could not confirm saved head');
  return { state: 'saved', revision, checkedAt: Date.now() };
}

export function compareSource(observation: SourceObservation, copiedRevision: number) {
  if (observation.failed || !observation.head) return 'unknown';
  const head = observation.head;
  if (head.state === 'deleted') return 'deleted';
  if (head.state === 'missing') return 'missing';
  if (head.revision === copiedRevision) return 'same';
  if (head.revision > copiedRevision) return 'newer';
  return 'different';
}
