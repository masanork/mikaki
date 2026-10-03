export const normalizeThreadSearchText = (text: string) => text.normalize('NFKC').toLowerCase();

// Shared with the UI so unsupported input never starts/retries a Worker request.
export function threadSearchTerms(query: unknown): string[] {
  if (typeof query !== 'string' || query.length > 256 || /[\uD800-\uDFFF]/u.test(query))
    throw new Error('invalid query');
  const terms = normalizeThreadSearchText(query).trim().split(/\s+/u).filter(Boolean);
  if (terms.length > 8) throw new Error('invalid query');
  return terms;
}
