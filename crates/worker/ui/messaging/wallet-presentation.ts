/** A Chat message is only a navigation request. Native Wallet verifies the
 * configured recipient, signed request, nonce and selection before consent. */
export function walletPresentationLink(text: string): string | null {
  if (text.length > 4096 || text.trim() !== text) return null;
  try {
    const url = new URL(text);
    if (
      !['openid4vp:', 'mdoc-openid4vp:'].includes(url.protocol) ||
      url.host ||
      url.pathname ||
      url.hash ||
      url.username ||
      url.password
    )
      return null;
    const keys = [...url.searchParams.keys()];
    if (
      keys.length !== new Set(keys).size ||
      keys.some((key) => !['client_id', 'request_uri', 'request_uri_method'].includes(key))
    )
      return null;
    if (!url.searchParams.get('client_id')) return null;
    const uri = new URL(url.searchParams.get('request_uri') ?? '');
    if (uri.protocol !== 'https:' || !uri.host || uri.username || uri.password || uri.hash)
      return null;
    const method = url.searchParams.get('request_uri_method');
    if (method && method !== 'get' && method !== 'post') return null;
    return url.href;
  } catch {
    return null;
  }
}
