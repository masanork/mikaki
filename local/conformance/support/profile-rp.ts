/** Minimal independent RP-side UserInfo consumer for local interoperability tests. */
type HttpRequest = (
  url: string,
  init?: RequestInit,
) => Promise<{
  ok: boolean;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}>;

export async function readProfileFromUserInfo(
  issuer: string,
  accessToken: string,
  idTokenSubject: string,
  request: HttpRequest = fetch,
): Promise<{ sub: string; name?: string }> {
  if (!issuer.startsWith('https://') || !accessToken || !idTokenSubject)
    throw new Error('invalid_rp_input');
  const metadataResponse = await request(`${issuer}/.well-known/openid-configuration`, {
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
  });
  if (!metadataResponse.ok) throw new Error('discovery_failed');
  const metadata = await metadataResponse.json();
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata))
    throw new Error('invalid_discovery');
  const configuration = metadata as Record<string, unknown>;
  if (configuration.issuer !== issuer || typeof configuration.userinfo_endpoint !== 'string')
    throw new Error('invalid_discovery');
  const endpoint = new URL(configuration.userinfo_endpoint);
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.hash)
    throw new Error('invalid_userinfo_endpoint');
  const response = await request(endpoint.href, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error('userinfo_failed');
  if (response.headers.get('content-type')?.split(';')[0] !== 'application/json')
    throw new Error('invalid_userinfo_type');
  const claims = await response.json();
  if (!claims || typeof claims !== 'object' || Array.isArray(claims))
    throw new Error('invalid_userinfo');
  const profile = claims as Record<string, unknown>;
  // OIDC Core requires this comparison before using any other UserInfo claim.
  if (profile.sub !== idTokenSubject) throw new Error('userinfo_subject_mismatch');
  if (profile.name !== undefined && (typeof profile.name !== 'string' || !profile.name))
    throw new Error('invalid_userinfo_name');
  return profile.name === undefined
    ? { sub: idTokenSubject }
    : { sub: idTokenSubject, name: profile.name as string };
}
