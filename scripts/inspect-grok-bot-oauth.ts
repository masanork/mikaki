/** Inspect a captured authorize URL offline; output never includes request values. */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { configuration } from './prepare-grok-bot.ts';

const parameters = [
  'response_type',
  'client_id',
  'redirect_uri',
  'resource',
  'scope',
  'state',
  'code_challenge',
  'code_challenge_method',
];
const readScopes = ['list', 'search', 'read'];

export function inspect(raw: string, config: unknown) {
  if (Buffer.byteLength(raw, 'utf8') > 4096) throw new Error('Invalid input');
  const expected = configuration(config);
  const request = new URL(raw.trim());
  const query = request.searchParams;
  const requestedScopes = (query.get('scope') ?? '').split(' ');
  const keys = [...query.keys()];
  const stateLength = (query.get('state') ?? '').length;
  const checks = {
    authorization_endpoint:
      request.protocol === 'https:' &&
      !request.username &&
      !request.password &&
      !request.hash &&
      `${request.origin}${request.pathname}` ===
        `${new URL(expected.resource).origin}/oauth/authorize`,
    bounded_request: request.href.length <= 4096,
    required_parameters: parameters.every((key) => query.has(key)),
    unique_parameters: keys.every((key) => query.getAll(key).length === 1),
    allowed_parameters: keys.every((key) => parameters.includes(key)),
    response_type_code: query.get('response_type') === 'code',
    client_id: query.get('client_id') === expected.client.client_id,
    exact_callback: query.get('redirect_uri') === expected.client.redirect_uris[0],
    exact_resource: query.get('resource') === expected.resource,
    read_only_scopes:
      requestedScopes.length > 0 &&
      requestedScopes.length <= 3 &&
      new Set(requestedScopes).size === requestedScopes.length &&
      requestedScopes.every((scope) => readScopes.includes(scope)),
    state_length: stateLength >= 16 && stateLength <= 512,
    pkce_s256: query.get('code_challenge_method') === 'S256',
    pkce_challenge_format: /^[A-Za-z0-9_-]{43}$/.test(query.get('code_challenge') ?? ''),
  };
  return {
    compatible_request: Object.values(checks).every(Boolean),
    evidence: 'authorize_request_only',
    checks,
    observations: {
      state_length: stateLength,
      requested_read_scopes: Object.fromEntries(
        readScopes.map((scope) => [scope, requestedScopes.includes(scope)]),
      ),
      unknown_scope_count: requestedScopes.filter((scope) => !readScopes.includes(scope)).length,
      unknown_parameter_count: keys.filter((key) => !parameters.includes(key)).length,
      duplicate_parameter_count: new Set(keys.filter((key) => query.getAll(key).length > 1)).size,
    },
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [input, ...extra] = process.argv.slice(2);
    if (!input || extra.length) throw new Error();
    const configBytes = await readFile(input);
    if (configBytes.length > 16384) throw new Error();
    const chunks: Buffer[] = [];
    let length = 0;
    for await (const chunk of process.stdin) {
      const bytes = Buffer.from(chunk);
      length += bytes.length;
      if (length > 4096) throw new Error();
      chunks.push(bytes);
    }
    const report = inspect(
      Buffer.concat(chunks).toString('utf8'),
      JSON.parse(configBytes.toString('utf8')),
    );
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.compatible_request ? 0 : 1;
  } catch {
    // URL/parser/configuration errors may embed input values. Never print the original error.
    console.error(
      'Invalid input. Usage: node scripts/inspect-grok-bot-oauth.ts CONFIG_JSON < PRIVATE_URL_FILE',
    );
    process.exitCode = 2;
  }
}
