import { z } from 'zod';
export const clientId = z.string().regex(/^[A-Za-z0-9_-]{1,80}$/);
export function redirectUri(raw: string): string {
  const url = new URL(raw);
  if (
    url.href !== raw ||
    url.username ||
    url.password ||
    url.hash ||
    url.searchParams.has('code') ||
    url.searchParams.has('state') ||
    url.searchParams.has('error') ||
    url.searchParams.has('iss') ||
    !(
      url.protocol === 'https:' ||
      (url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname))
    )
  )
    throw new Error('Invalid callback');
  return raw;
}
export function registration(raw: unknown) {
  return z
    .strictObject({
      client_id: clientId,
      client_name: z.string().trim().min(1).max(160),
      redirect_uris: z
        .array(z.string().max(1024).transform(redirectUri))
        .min(1)
        .max(10)
        .refine((v) => new Set(v).size === v.length),
    })
    .parse(raw);
}
