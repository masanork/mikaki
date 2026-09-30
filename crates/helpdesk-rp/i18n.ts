// Request-scoped adapter for the catalogs also used by Paraglide and the OP.
import ja from '../../messages/ja.json' with { type: 'json' };
import en from '../../messages/en.json' with { type: 'json' };

export type Locale = 'ja' | 'en';
export type MessageKey = keyof typeof ja;
export const LOCALE_COOKIE = '__Host-help-locale';

function supported(tag: string | null): Locale | undefined {
  if (!tag || !/^[A-Za-z]+(?:-[A-Za-z0-9]+)*$/.test(tag)) return;
  const primary = tag.split('-')[0].toLowerCase();
  if (primary === 'ja' || primary === 'en') return primary;
}

export function selectLocale(request: Request): Locale {
  const explicit = supported(new URL(request.url).searchParams.get('lang'));
  if (explicit) return explicit;
  const cookies = (request.headers.get('cookie') ?? '')
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.startsWith(`${LOCALE_COOKIE}=`));
  const saved =
    cookies.length === 1 ? supported(cookies[0].slice(LOCALE_COOKIE.length + 1)) : undefined;
  if (saved) return saved;
  let best: { locale: Locale; quality: number } | undefined;
  for (const item of (request.headers.get('accept-language') ?? '').split(',').slice(0, 20)) {
    const [tag, weight] = item.trim().split(';');
    const locale = supported(tag);
    const quality = weight?.trim().startsWith('q=') ? Number(weight.trim().slice(2)) : 1;
    if (locale && quality > 0 && quality <= 1 && (!best || quality > best.quality)) {
      best = { locale, quality };
    }
  }
  return best?.locale ?? 'ja';
}

export function catalog(locale: Locale) {
  const messages = locale === 'en' ? en : ja;
  return { locale, message: (key: MessageKey): string => messages[key] };
}
export type Catalog = ReturnType<typeof catalog>;

const errorKeys: Record<string, MessageKey> = {
  not_found: 'helpNotFoundBody',
  login_required: 'helpLoginRequired',
  session_inactive: 'helpSessionExpired',
  session_expired: 'helpSessionExpired',
  session_changed: 'helpSessionExpired',
  session_revoked: 'helpSessionExpired',
  invalid_title: 'helpInvalidTitle',
  invalid_message: 'helpInvalidMessage',
  ticket_changed: 'helpTicketChanged',
  invalid_origin: 'helpInvalidRequest',
  invalid_csrf: 'helpInvalidRequest',
  duplicate_cookie: 'helpInvalidRequest',
  unsupported_media_type: 'helpInvalidRequest',
  missing_body: 'helpInvalidRequest',
  request_too_large: 'helpRequestTooLarge',
  invalid_form: 'helpInvalidRequest',
  invalid_callback: 'helpLoginFailed',
  invalid_transaction: 'helpLoginFailed',
  invalid_id_token: 'helpLoginFailed',
  invalid_logout_token: 'helpInvalidRequest',
};

export function errorMessage(strings: Catalog, code: string): string {
  return strings.message(
    Object.hasOwn(errorKeys, code) ? errorKeys[code] : 'helpServiceUnavailable',
  );
}
