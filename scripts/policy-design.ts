import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'smol-toml';

export const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DURATION_GROUPS: Record<string, string> = {
  registration: 'invitation_ttl bootstrap_invitation_ttl',
  authentication: 'ceremony_ttl',
  session: 'sso_absolute_ttl app_idle_timeout',
  'session.validation': 'lease_ttl',
  'session.management': 'operation_authorization_ttl',
  oidc: 'authorization_code_ttl id_token_ttl',
  'oidc.login': 'transaction_ttl',
  'oidc.client_authentication': 'assertion_ttl',
  'oidc.access_token': 'ttl',
  'oidc.validation': 'clock_skew',
  'oidc.backchannel': 'request_timeout',
  oidc_logout: 'token_ttl',
  signing:
    'rotation_interval prepublish_duration jwks_cache_max_age verification_key_min_retention deployment_margin',
  jwks_fetch: 'timeout unknown_kid_cooldown negative_cache_ttl',
  rate_limit: 'window',
  logout_delivery:
    'base_delay max_delay retry_deadline lease_ttl scheduler_interval oldest_pending_alert_age',
  retention: 'gc_interval gc_grace audit_ttl delivery_result_ttl rate_key_ttl',
  vault: 'unlock_idle_timeout unlock_absolute_ttl',
};
const COUNT_GROUPS: Record<string, string> = {
  authentication: 'ceremony_max_failures',
  jwks_fetch: 'max_inflight_per_issuer negative_cache_entries_per_issuer',
  limits:
    'request_target_bytes header_bytes form_body_bytes json_body_bytes webauthn_body_bytes webauthn_depth jwt_bytes jwks_bytes jwks_keys json_depth parameter_count state_bytes nonce_bytes jti_bytes kid_bytes client_id_bytes redirect_uri_bytes scope_bytes pending_login_per_browser active_sso_per_account active_client_sessions_per_sso_client registered_clients credentials_per_account response_bytes',
  rate_limit:
    'discovery_per_ip authorize_per_browser authorize_per_ip ceremony_start_per_browser ceremony_finish_per_browser token_per_ip token_per_authenticated_client userinfo_per_ip session_check_per_authenticated_client management_per_account logout_receive_per_authenticated_issuer',
  logout_delivery: 'max_attempts fanout_batch_size claim_batch_size max_inflight_per_client',
  retention: 'gc_batch_size',
};
// max_response_bytes is part of the logout delivery count group, kept separate for readability.
COUNT_GROUPS.logout_delivery += ' max_response_bytes backlog_alert_count';

function keysIn(groups: Record<string, string>): Set<string> {
  return new Set(
    Object.entries(groups).flatMap(([group, keys]) =>
      keys.split(' ').map((key) => `${group}.${key}`),
    ),
  );
}
const DURATIONS = keysIn(DURATION_GROUPS);
const COUNTS = keysIn(COUNT_GROUPS);
const EXPECTED = new Set([...DURATIONS, ...COUNTS, 'schema_version']);
const TABLES = new Set(
  [...EXPECTED].flatMap((path) => {
    const parts = path.split('.');
    return parts.slice(1).map((_, index) => parts.slice(0, index + 1).join('.'));
  }),
);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function flatten(data: Record<string, unknown>, prefix = ''): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    const path = prefix + key;
    if (isRecord(value)) Object.assign(result, flatten(value, `${path}.`));
    else result[path] = value;
  }
  return result;
}

function requireValue(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export function validate(data: Record<string, unknown>): Record<string, number> {
  const values = flatten(data);
  function checkTables(node: Record<string, unknown>, prefix = '') {
    for (const [key, value] of Object.entries(node)) {
      const path = prefix + key;
      if (isRecord(value)) {
        requireValue(TABLES.has(path), `unknown table: ${path}`);
        checkTables(value, `${path}.`);
      }
    }
  }
  checkTables(data);
  requireValue(
    Object.keys(values).length === EXPECTED.size &&
      Object.keys(values).every((key) => EXPECTED.has(key)),
    'unknown/missing keys',
  );
  requireValue(
    values.schema_version === 1 && typeof values.schema_version === 'number',
    'schema_version',
  );
  const out: Record<string, number> = { schema_version: 1 };
  const units: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
  for (const key of [...DURATIONS, ...COUNTS].sort()) {
    let value = values[key];
    if (DURATIONS.has(key)) {
      const match = typeof value === 'string' ? /^([1-9][0-9]*)([smhd])$/.exec(value) : null;
      requireValue(match, `${key}: positive duration required`);
      value = Number(match[1]) * units[match[2]];
    }
    requireValue(
      typeof value === 'number' && Number.isInteger(value) && value > 0 && value <= 2 ** 31 - 1,
      `${key}: positive bounded integer required`,
    );
    out[key] = value;
  }
  const le = (a: string, b: string) => requireValue(out[a] <= out[b], `${a} must be <= ${b}`);
  for (const [a, b] of [
    ['session.app_idle_timeout', 'session.sso_absolute_ttl'],
    ['session.validation.lease_ttl', 'session.app_idle_timeout'],
    ['session.management.operation_authorization_ttl', 'session.sso_absolute_ttl'],
    ['oidc.authorization_code_ttl', 'session.sso_absolute_ttl'],
    ['oidc.authorization_code_ttl', 'oidc.login.transaction_ttl'],
    ['oidc.access_token.ttl', 'session.sso_absolute_ttl'],
    ['oidc.id_token_ttl', 'session.sso_absolute_ttl'],
    ['vault.unlock_idle_timeout', 'vault.unlock_absolute_ttl'],
    ['logout_delivery.base_delay', 'logout_delivery.max_delay'],
    ['logout_delivery.max_delay', 'logout_delivery.retry_deadline'],
    ['logout_delivery.lease_ttl', 'logout_delivery.retry_deadline'],
    ['logout_delivery.oldest_pending_alert_age', 'logout_delivery.retry_deadline'],
    ['jwks_fetch.negative_cache_ttl', 'signing.prepublish_duration'],
    ['jwks_fetch.unknown_kid_cooldown', 'signing.prepublish_duration'],
    ['limits.jwt_bytes', 'limits.form_body_bytes'],
    ['limits.jwt_bytes', 'limits.json_body_bytes'],
    ['limits.jwks_bytes', 'limits.response_bytes'],
  ])
    le(a, b);
  requireValue(
    out['oidc.backchannel.request_timeout'] < out['logout_delivery.lease_ttl'],
    'delivery lease must exceed HTTP timeout',
  );
  requireValue(
    out['jwks_fetch.timeout'] < out['oidc.backchannel.request_timeout'],
    'JWKS timeout must leave processing time',
  );
  requireValue(
    out['signing.prepublish_duration'] >=
      out['signing.jwks_cache_max_age'] +
        out['oidc.validation.clock_skew'] +
        out['signing.deployment_margin'],
    'prepublish too short',
  );
  requireValue(
    out['signing.rotation_interval'] > out['signing.prepublish_duration'],
    'rotation <= prepublish',
  );
  requireValue(
    out['limits.jwt_bytes'] + 4096 <= out['limits.header_bytes'],
    'header budget too small',
  );
  requireValue(
    out['limits.jwt_bytes'] + 4096 <= out['limits.form_body_bytes'],
    'form budget too small',
  );
  requireValue(
    [10, 60].includes(out['rate_limit.window']),
    'Cloudflare rate window must be 10s or 60s',
  );
  requireValue(out['limits.json_depth'] <= 64, 'json_depth exceeds tested profile');
  requireValue(out['limits.webauthn_depth'] <= 64, 'webauthn_depth exceeds tested profile');
  requireValue(out['limits.jwks_keys'] <= 128, 'jwks_keys exceeds tested profile');
  requireValue(
    [...COUNTS].filter((key) => key.endsWith('_bytes')).every((key) => out[key] <= 1_048_576),
    'byte bound exceeds initial profile',
  );
  return out;
}

export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value))
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  return JSON.stringify(value);
}

export function revision(data: Record<string, unknown>): string {
  return createHash('sha256')
    .update(canonicalJson(validate(data)), 'ascii')
    .digest('hex');
}

export async function readToml(path: string): Promise<Record<string, unknown>> {
  return parse(await readFile(path, 'utf8')) as Record<string, unknown>;
}

export function policyPath(): string {
  return resolve(ROOT, 'config/runtime-policy.example.toml');
}
