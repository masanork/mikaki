/** Explicit opt-in runner: missing SDK evidence must fail, never silently skip. */
import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { mkdir, readFile, realpath, stat, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { parseArgs, promisify } from 'node:util';
import { multipazCommit } from '../local/conformance/support/multipaz-wallet.ts';

const { values } = parseArgs({
  options: { checkout: { type: 'string' }, 'native-only': { type: 'boolean' } },
});
const root = fileURLToPath(new URL('../', import.meta.url));
const output = new URL('../local/generated/wallet-multipaz-summary.json', import.meta.url);
const run = promisify(execFile);
const started = Date.now();
const summary: {
  status: string;
  startedAt: string;
  finishedAt?: string;
  sdkCommit: string;
  mode: 'native' | 'bidirectional';
  native?: { sdkTests: number };
  issuer?: { sdkTests: number };
  scope: string;
} = {
  status: 'running',
  startedAt: new Date(started).toISOString(),
  sdkCommit: multipazCommit,
  mode: values['native-only'] ? 'native' : 'bidirectional',
  scope:
    'Synthetic host SDK format/signature and issuance checks; no physical device, production trust, full Wallet app or HAIP qualification.',
};
async function record() {
  await mkdir(new URL('../local/generated/', import.meta.url), { recursive: true });
  await writeFile(output, JSON.stringify(summary, null, 2) + '\n');
}
async function checkCheckout(checkout: string) {
  const shallow = await run('git', ['rev-parse', '--is-shallow-repository'], { cwd: checkout });
  assert.equal(
    shallow.stdout.trim(),
    'false',
    'Fetch complete SDK history and tags for upstream version calculation',
  );
  const head = await run('git', ['rev-parse', 'HEAD'], { cwd: checkout });
  assert.equal(head.stdout.trim(), multipazCommit, 'SDK checkout must match the pinned commit');
  const dirty = await run('git', ['status', '--porcelain', '--untracked-files=no'], {
    cwd: checkout,
  });
  assert.equal(dirty.stdout.trim(), '', 'SDK tracked sources must be unchanged');
}
async function execute(command: string, args: string[], env: NodeJS.ProcessEnv) {
  await new Promise<void>((done, reject) => {
    const child = spawn(command, args, { cwd: root, env, stdio: 'inherit' });
    const timeout = setTimeout(() => child.kill('SIGTERM'), 20 * 60_000);
    child.once('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once('exit', (code) => {
      clearTimeout(timeout);
      if (code === 0) done();
      else reject(new Error(`${command} failed (${code})`));
    });
  });
}
async function sdkResult(checkout: string, name: string, since: number) {
  const path = resolve(checkout, 'multipaz/build/test-results/jvmTest', `TEST-${name}.xml`);
  const file = await stat(path);
  assert.ok(file.mtimeMs >= since, 'SDK report must come from this run');
  const xml = await readFile(path, 'utf8');
  const suite = /<testsuite\b[^>]*>/.exec(xml)?.[0] ?? '';
  const count = (field: string) =>
    Number(new RegExp(`\\b${field}="(\\d+)"`).exec(suite)?.[1] ?? NaN);
  assert.ok(count('tests') > 0, 'SDK must execute at least one test');
  for (const field of ['failures', 'errors', 'skipped'])
    assert.equal(count(field), 0, `SDK ${field}`);
  return { sdkTests: count('tests') };
}
await record();
try {
  const requested = values.checkout ?? process.env.MIKAKI_MULTIPAZ_CHECKOUT;
  assert.ok(requested, 'Supply --checkout /private/tmp/<pinned-multipaz-checkout>');
  const checkout = await realpath(resolve(requested));
  assert.ok(
    checkout.startsWith('/private/tmp/'),
    'Use a disposable SDK checkout under /private/tmp',
  );
  await checkCheckout(checkout);
  const env = {
    ...process.env,
    MIKAKI_MULTIPAZ_PRESENTATION_CHECKOUT: checkout,
    MIKAKI_NATIVE_INVENTORY_PEER: '1',
  };
  const nativeStarted = Date.now();
  await execute(
    'cargo',
    [
      'test',
      '--manifest-path',
      'apps/mikaki-client/src-tauri/Cargo.toml',
      '--lib',
      'identity_inventory',
      '--locked',
      '--offline',
    ],
    env,
  );
  summary.native = await sdkResult(
    checkout,
    'org.multipaz.mdoc.response.MikakiPresentationTest',
    nativeStarted,
  );
  await record();
  if (!values['native-only']) {
    await execute('npm', ['run', 'build:policy'], env);
    await execute('worker-build', ['--release', 'crates/worker', '--locked'], env);
    const issuerStarted = Date.now();
    await execute('node', ['--test', 'local/conformance/identity-issuance.test.ts'], {
      ...env,
      MIKAKI_MULTIPAZ_CHECKOUT: checkout,
    });
    summary.issuer = await sdkResult(
      checkout,
      'org.multipaz.provisioning.openid4vci.MikakiIssuanceTest',
      issuerStarted,
    );
  }
  await checkCheckout(checkout);
  summary.status = 'passed';
} catch (error) {
  summary.status = 'failed';
  throw error;
} finally {
  summary.finishedAt = new Date().toISOString();
  await record();
  process.stdout.write(`Wallet Multipaz evidence: ${fileURLToPath(output)} (${summary.status})\n`);
}
