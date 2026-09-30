// Manage only this workspace's disposable loopback conformance server.
import { spawn, execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, openSync, closeSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
const cwd = fileURLToPath(new URL('../../', import.meta.url));
const directory = resolve(cwd, 'target/conformance-runs');
mkdirSync(directory, { recursive: true });
const port = Number(process.env.FIDO_PORT ?? 8082);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw Error('Invalid FIDO_PORT');
const record = resolve(directory, `${port}.json`);
type Run = { pid: number; identity: string; target: 'native' | 'wasm'; log: string; port: number };
function identity(pid: number): string {
  try {
    return execFileSync('ps', ['-p', String(pid), '-o', 'lstart=,command='], {
      encoding: 'utf8',
    }).trim();
  } catch (error) {
    if ((error as { status?: number }).status === 1) return '';
    throw Error(
      'Cannot inspect process identity; run the manager with process inspection permission',
      {
        cause: error,
      },
    );
  }
}
function saved(): Run | undefined {
  try {
    return JSON.parse(readFileSync(record, 'utf8'));
  } catch {
    return undefined;
  }
}
function live(run: Run | undefined): run is Run {
  return !!run && !!run.identity && identity(run.pid) === run.identity;
}
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function health() {
  try {
    const r = await fetch(`http://localhost:${port}/attestation/options`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        username: 'manager-health',
        displayName: 'Manager health',
        authenticatorSelection: {},
      }),
      signal: AbortSignal.timeout(1000),
    });
    return r.ok && (await r.json()).status === 'ok';
  } catch {
    return false;
  }
}
async function stop() {
  const run = saved();
  if (!live(run)) return;
  process.kill(run.pid, 'SIGTERM');
  for (let i = 0; i < 50; i++) {
    if (!live(run)) return;
    await wait(100);
  }
  throw Error('Server did not stop; no SIGKILL was sent');
}
async function start(target: 'native' | 'wasm') {
  if (live(saved())) throw Error('Managed server already running; use restart');
  const profile = process.env.FIDO_MDS_PROFILE ?? 'mds3.0';
  if (!['mds3.0', 'mds3.1.1'].includes(profile)) throw Error('Invalid FIDO_MDS_PROFILE');
  const command =
    target === 'native'
      ? resolve(cwd, 'target/release/examples/conformance_server')
      : process.execPath;
  const args = target === 'native' ? [] : [resolve(cwd, 'local/conformance/server.ts')];
  const log = resolve(directory, `${port}-${target}-${randomUUID()}.log`);
  const fd = openSync(log, 'wx', 0o600);
  const child = spawn(command, args, {
    cwd,
    detached: true,
    stdio: ['ignore', fd, fd],
    env: {
      ...process.env,
      FIDO_PORT: String(port),
      FIDO_MDS_PROFILE: profile,
      FIDO_TARGET: 'wasm',
      FIDO_DB: 'file',
      FIDO_TIMING: '1',
    },
  });
  closeSync(fd);
  await new Promise<void>((ok, no) => {
    child.once('spawn', ok);
    child.once('error', no);
  });
  const pid = child.pid!;
  child.unref();
  const run: Run = { pid, identity: identity(pid), target, log, port };
  writeFileSync(record, JSON.stringify(run, null, 2) + '\n', { mode: 0o600 });
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    if (!live(run)) throw Error(`Startup failed; inspect ${log}`);
    if (await health()) {
      console.log(JSON.stringify({ ...run, url: `http://localhost:${port}`, healthy: true }));
      return;
    }
    await wait(100);
  }
  await stop();
  throw Error(`Server did not become ready; inspect ${log}`);
}
const [action = 'status', target = 'native'] = process.argv.slice(2);
if (!['native', 'wasm'].includes(target)) throw Error('Target must be native or wasm');
if (action === 'status') {
  const run = saved();
  console.log(
    JSON.stringify({ run, running: live(run), healthy: live(run) ? await health() : false }),
  );
} else if (action === 'stop') await stop();
else if (action === 'start') await start(target as 'native' | 'wasm');
else if (action === 'restart') {
  await stop();
  await start(target as 'native' | 'wasm');
} else
  throw Error('Usage: node local/conformance/manage.ts status|start|restart|stop [native|wasm]');
