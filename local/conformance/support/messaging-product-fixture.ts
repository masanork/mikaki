/** Local product packages, real owner policy and optional shared-D1 replica. */
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { parse } from 'jsonc-parser';
import { createTestHarness } from 'wrangler';
import { activateWorkerPolicy } from '../../../scripts/worker-policy-store.ts';
import type { D1Database } from '@cloudflare/workers-types';
const root = new URL('../../../', import.meta.url).pathname;
const origin = 'https://mikaki.test';
export async function messagingFixture(
  enabled: boolean,
  { defaultBuild = false, replica = false }: { defaultBuild?: boolean; replica?: boolean } = {},
) {
  const config = parse(await readFile(`${root}crates/worker/wrangler.jsonc`, 'utf8'));
  config.main = `${root}crates/worker/${defaultBuild ? 'build' : 'build-messaging-beta'}/worker/service.mjs`;
  config.assets.directory = `${root}assets`;
  config.d1_databases[0].migrations_dir = `${root}crates/worker/migrations`;
  config.vars = { MIKAKI_ISSUER: origin, MESSAGING_BETA_ENABLED: String(enabled || defaultBuild) };
  if (enabled) {
    const jwk = generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' });
    config.vars.MESSAGING_ISSUER_KEY = JSON.stringify({
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      d: jwk.d,
    });
  }
  const harness = createTestHarness({
    root,
    workers: [
      { config },
      ...(replica
        ? [
            {
              config: {
                ...config,
                name: 'messaging-product-replica',
                queues: { ...config.queues, consumers: [] },
              },
            },
          ]
        : []),
    ],
  });
  try {
    await harness.listen();
    const worker = harness.getWorker('mikaki-op-worker');
    await worker.applyD1Migrations('DB');
    const DB: D1Database = (await worker.getEnv()).DB;
    const policy = JSON.parse(await readFile(`${root}local/generated/worker-policy.json`, 'utf8'));
    await activateWorkerPolicy(DB, policy, { actor: 'test', reason: 'Messaging product host' });
    if (enabled) {
      for (const name of [
        '0001_messaging.sql',
        '0002_beta_profile.sql',
        '0003_ingress_budget.sql',
      ]) {
        const sql = (
          await readFile(`${root}crates/worker/messaging-migrations/${name}`, 'utf8')
        ).replace(/^--.*$/gm, '');
        await DB.batch(
          sql
            .split(';')
            .map((s: string) => s.trim())
            .filter(Boolean)
            .map((s: string) => DB.prepare(s)),
        );
      }
    }
    const seed = async () => {
      const account = randomUUID(),
        credential = randomBytes(32),
        id = credential.toString('base64url'),
        secret = randomBytes(32).toString('base64url'),
        session = randomUUID();
      await DB.batch([
        DB.prepare('INSERT INTO account_security VALUES(?,1,1)').bind(account),
        DB.prepare('INSERT INTO credential VALUES(?,?,1)').bind(id, account),
        DB.prepare(
          "INSERT INTO passkey_credential VALUES(?,'fixture-public-key','fixture-user',0,0,0,1)",
        ).bind(id),
        DB.prepare('INSERT INTO sso_session VALUES(?,?,?,1,unixepoch()+3600,0)').bind(
          session,
          account,
          id,
        ),
        DB.prepare('INSERT INTO sso_context VALUES(?,?,unixepoch())').bind(
          session,
          createHash('sha256').update(secret).digest('base64url'),
        ),
      ]);
      return { account, credential: [...credential], secret, session };
    };
    return {
      harness,
      worker,
      DB,
      seed,
      replica: replica ? harness.getWorker('messaging-product-replica') : worker,
    };
  } catch (error) {
    await harness.close();
    throw error;
  }
}
