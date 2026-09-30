import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { inspect } from './inspect-grok-bot-oauth.ts';

const config = {
  resource: 'https://agent-test.example/mcp',
  client: {
    client_id: 'mikaki-cursor-hosted-test',
    client_name: 'Synthetic test',
    redirect_uris: ['https://www.cursor.com/agents/mcp/oauth/callback'],
  },
};
function request() {
  const url = new URL('https://agent-test.example/oauth/authorize');
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: config.client.client_id,
    redirect_uri: config.client.redirect_uris[0],
    resource: config.resource,
    scope: 'list search read',
    state: 'secret_state_never_log_this',
    code_challenge: 'C'.repeat(43),
    code_challenge_method: 'S256',
  }).toString();
  return url;
}

test('request report checks the bounded read-only profile without emitting values', () => {
  const url = request();
  const report = inspect(url.href, config);
  assert.equal(report.compatible_request, true);
  assert.equal(report.evidence, 'authorize_request_only');
  assert.equal(report.observations.state_length, 27);
  const output = JSON.stringify(report);
  for (const value of [
    config.resource,
    config.client.client_id,
    config.client.redirect_uris[0],
    url.searchParams.get('state')!,
    url.searchParams.get('code_challenge')!,
  ])
    assert.ok(!output.includes(value));
});

test('binding, PKCE, scope and duplicate failures are rejected without reflecting malicious input', () => {
  for (const [key, value] of [
    ['client_id', 'secret_wrong_client'],
    ['redirect_uri', 'https://evil.example/secret'],
    ['resource', 'https://evil.example/secret'],
    ['scope', 'read propose'],
    ['scope', 'read read'],
    ['scope', 'read  search'],
    ['state', 'short'],
    ['code_challenge_method', 'plain'],
    ['code_challenge', 'invalid-secret'],
    ['response_type', 'token'],
    ['secret_unknown_parameter', 'secret_value'],
  ]) {
    const url = request();
    url.searchParams.set(key, value);
    const report = inspect(url.href, config);
    assert.equal(report.compatible_request, false, key);
    assert.ok(!JSON.stringify(report).includes(value), key);
  }
  const duplicate = request();
  duplicate.searchParams.append('resource', config.resource);
  assert.equal(inspect(duplicate.href, config).checks.unique_parameters, false);
  const wrongEndpoint = request();
  wrongEndpoint.hostname = 'evil.example';
  assert.equal(inspect(wrongEndpoint.href, config).checks.authorization_endpoint, false);
});

test('CLI never echoes malformed or oversized input; compatible metadata is not connection proof', () => {
  const run = (input: string) =>
    spawnSync(
      process.execPath,
      ['scripts/inspect-grok-bot-oauth.ts', 'integrations/grok-bot/configuration.example.json'],
      { input, encoding: 'utf8' },
    );
  for (const input of ['malformed-secret-value', 'secret'.repeat(1000)]) {
    const result = run(input);
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
    assert.ok(!result.stderr.includes('secret'));
  }
  const result = run(request().href);
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
  assert.equal(JSON.parse(result.stdout).evidence, 'authorize_request_only');
});
