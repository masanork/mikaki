import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { configuration, prepare } from './prepare-grok-bot.ts';

const input = {
  resource: 'https://agent-test.example/mcp',
  client: {
    client_id: 'mikaki-cursor-hosted-test',
    client_name: "Owner's synthetic test",
    redirect_uris: ['https://www.cursor.com/agents/mcp/oauth/callback'],
  },
};

test('hosted preparation rejects credentials, alternate callbacks and ambiguous resources', () => {
  for (const resource of [
    'http://agent-test.example/mcp',
    'https://user:password@agent-test.example/mcp',
    'https://agent-test.example/mcp?token=secret',
    'https://agent-test.example/mcp#secret',
    'https://agent-test.example/mcp?',
    'https://agent-test.example/mcp#',
    'https://AGENT-test.example/mcp',
    'https://agent-test.example:443/mcp',
    'https://agent-test.example/mcp/',
  ])
    assert.throws(() => configuration({ ...input, resource }));
  assert.throws(() => configuration({ ...input, token: 'secret' }));
  assert.throws(() =>
    configuration({ ...input, client: { ...input.client, client_secret: 'secret' } }),
  );
  for (const callback of [
    'http://localhost:8787/callback',
    'https://www.cursor.com/agents/mcp/oauth/callback?next=x',
    'https://unobserved.example/callback',
  ])
    assert.throws(() =>
      configuration({ ...input, client: { ...input.client, redirect_uris: [callback] } }),
    );
});

test('candidate is standalone, read scoped, unqualified and never replaces operator files', async () => {
  const temporary = await mkdtemp(join(tmpdir(), 'mikaki-hosted-package-'));
  try {
    const directory = join(temporary, 'candidate');
    const result = await prepare(input, directory);
    const read = async (path: string) => JSON.parse(await readFile(join(directory, path), 'utf8'));
    const marketplace = await read('.cursor-plugin/marketplace.json');
    const manifest = await read(`${marketplace.plugins[0].source}/.cursor-plugin/plugin.json`);
    assert.equal(marketplace.plugins[0].name, manifest.name);
    assert.equal(manifest.variables, undefined);
    const server = (await read(`plugin/${manifest.mcpServers}`)).mcpServers.mikaki;
    assert.deepEqual(server, {
      url: input.resource,
      auth: { CLIENT_ID: input.client.client_id, scopes: ['list', 'search', 'read'] },
    });
    assert.equal((await read('qualification.json')).status, 'unqualified');
    assert.ok(
      Object.values((await read('qualification.json')).checks).every(
        (check: any) => check.status === 'pending' && check.evidence === null,
      ),
    );
    assert.deepEqual(await read('registration.json'), input.client);
    assert.match(
      await readFile(join(directory, 'registration.sql'), 'utf8'),
      /Owner''s synthetic test/,
    );
    assert.equal(result.files.length, 8);
    const marker = join(directory, 'README.md');
    await writeFile(marker, 'operator content');
    await assert.rejects(prepare(input, directory), { code: 'EEXIST' });
    assert.equal(await readFile(marker, 'utf8'), 'operator content');
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
