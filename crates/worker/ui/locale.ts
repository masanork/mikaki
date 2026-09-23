import { overwriteGetLocale, type Locale } from './paraglide/runtime.js';

export function initializeLocale(): Locale {
  const locale = document.documentElement.lang;
  if (locale !== 'ja' && locale !== 'en') throw new Error('Unsupported page locale');
  overwriteGetLocale(() => locale);
  return locale;
}

export function switchLocale(value: string): void {
  if (value !== 'ja' && value !== 'en') return;
  document.cookie = `__Host-op-locale=${value}; Max-Age=31536000; Path=/; Secure; SameSite=Lax`;
  const next = new URL(location.href);
  next.searchParams.set('lang', value);
  location.assign(next);
}
