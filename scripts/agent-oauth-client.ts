/** Generate reviewed pre-registration SQL; this command does not modify a database. */
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { registration } from '../crates/agent-worker/oauth-client.ts';

const [input, output, ...extra] = process.argv.slice(2);
if (!input || !output || extra.length)
  throw new Error('Usage: node scripts/agent-oauth-client.ts REGISTRATION_JSON NEW_SQL_FILE');
const bytes = await readFile(input);
if (bytes.length > 16384) throw new Error('Registration file too large');
const client = registration(JSON.parse(bytes.toString('utf8')));
const quote = (value: string) => `'${value.replaceAll("'", "''")}'`;
const statement = `INSERT INTO agent_oauth_client(client_id,client_name,redirect_uris,active) VALUES(${quote(client.client_id)},${quote(client.client_name)},${quote(JSON.stringify(client.redirect_uris))},1);\n`;
await writeFile(resolve(output), statement, { flag: 'wx', mode: 0o600 });
console.log(
  JSON.stringify({
    file: resolve(output),
    client_id: client.client_id,
    redirect_uris: client.redirect_uris,
  }),
);
