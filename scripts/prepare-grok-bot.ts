/** Prepare a standalone hosted-plugin candidate; never publish or apply registration. */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { registration } from '../crates/agent-worker/oauth-client.ts';

const hostedCallback = 'https://www.cursor.com/agents/mcp/oauth/callback';

export function configuration(raw: unknown) {
  const input = z.strictObject({ resource: z.string().max(256), client: z.unknown() }).parse(raw);
  const url = new URL(input.resource);
  if (
    url.href !== input.resource ||
    input.resource !== `${url.origin}/mcp` ||
    url.protocol !== 'https:' ||
    url.pathname !== '/mcp' ||
    url.search ||
    url.hash ||
    url.username ||
    url.password
  )
    throw new Error('Expected a canonical HTTPS /mcp resource without credentials or query');
  const client = registration(input.client);
  if (client.redirect_uris.length !== 1 || client.redirect_uris[0] !== hostedCallback)
    throw new Error(
      'Candidate requires the documented exact hosted callback; qualify changes first',
    );
  return { resource: input.resource, client };
}

export async function prepare(raw: unknown, destination: string) {
  const { resource, client } = configuration(raw);
  const source = new URL('../integrations/grok-bot/.cursor-plugin/plugin.json', import.meta.url);
  const { variables: _variables, ...manifest } = JSON.parse(await readFile(source, 'utf8'));
  const root = resolve(destination);
  // Refuse an existing directory, including a symlink. Never replace an operator's package.
  await mkdir(root, { mode: 0o700 });
  await mkdir(join(root, '.cursor-plugin'));
  await mkdir(join(root, 'plugin', '.cursor-plugin'), { recursive: true });
  const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;
  const quote = (value: string) => `'${value.replaceAll("'", "''")}'`;
  const sql = `INSERT INTO agent_oauth_client(client_id,client_name,redirect_uris,active) VALUES(${quote(client.client_id)},${quote(client.client_name)},${quote(JSON.stringify(client.redirect_uris))},1);\n`;
  const instructions = `# Mikaki hosted test candidate

This standalone package is prepared for private provider qualification. It has not been published, installed, preregistered or qualified with Grok Bot.

Endpoint: ${resource}
Public client ID: ${client.client_id}
Candidate callback: ${hostedCallback}
Requested operations: list, search, read.

The plugin has concrete non-secret values and needs no variable substitution. This avoids one configuration dependency; it does not prove hosted public-client OAuth support. No client secret, bearer token, owner cookie or Vault key is included.

Confirm the actual Bot callback before applying registration.sql to the dedicated test service. Use only disposable synthetic snapshots and owner-selected read grants. Review this folder before uploading it to a separate private plugin repository. Cursor documents Dashboard > Plugins & MCPs > Team Marketplaces > Import from Repo for Teams/Enterprise. Choose opt-in installation (Default Off) and the intended test audience. Grok Bot availability through that route remains unverified. Local Cursor IDE loading and public marketplace review are different routes.

After installation, capture OAuth request metadata without state/code/verifier/token values. Verify exact client/resource/callback, S256 PKCE, narrowed reads, restart/reuse and revocation. Mark each result in qualification.json only after observing it. The JSON is a review record, not a permission input to Mikaki.

All Bots in the account share connector availability. Owner login/Passkey/PRF must stay on the owner's device. Revocation stops future access, but cannot recall previously delivered copies.
`;
  const files: Record<string, string> = {
    '.cursor-plugin/marketplace.json': json({
      name: 'mikaki-hosted-test',
      owner: { name: 'Mikaki operator' },
      metadata: { description: 'Private synthetic hosted-client qualification candidate' },
      plugins: [{ name: manifest.name, source: 'plugin', description: manifest.description }],
    }),
    'plugin/.cursor-plugin/plugin.json': json(manifest),
    'plugin/mcp.json': json({
      mcpServers: {
        mikaki: {
          url: resource,
          auth: { CLIENT_ID: client.client_id, scopes: ['list', 'search', 'read'] },
        },
      },
    }),
    'plugin/README.md': instructions,
    'README.md': instructions,
    'registration.json': json(client),
    'registration.sql': sql,
    'qualification.json': json({
      status: 'unqualified',
      resource,
      client_id: client.client_id,
      candidate_callback: hostedCallback,
      checks: Object.fromEntries(
        [
          'private_distribution',
          'bot_installation',
          'public_client_oauth',
          'exact_bindings',
          'pkce_s256',
          'owner_consent',
          'selected_snapshot_read',
          'write_denied',
          'restart_reuse',
          'revocation',
          'cancel_recovery',
          'service_unavailable',
        ].map((key) => [key, { status: 'pending', evidence: null }]),
      ),
    }),
  };
  for (const [path, content] of Object.entries(files))
    await writeFile(join(root, path), content, { flag: 'wx', mode: 0o600 });
  return { directory: root, files: Object.keys(files), status: 'unqualified' };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [input, output, ...extra] = process.argv.slice(2);
  if (!input || !output || extra.length)
    throw new Error('Usage: node scripts/prepare-grok-bot.ts CONFIG_JSON NEW_DIRECTORY');
  const bytes = await readFile(input);
  if (bytes.length > 16384) throw new Error('Configuration file too large');
  // Parent must already exist; an accidental destination never creates a directory tree.
  console.log(JSON.stringify(await prepare(JSON.parse(bytes.toString('utf8')), output)));
}
