import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
let built = false;
export async function withRustHaipWallet(
  config: unknown,
  run: (keys: any, command: (value: unknown) => Promise<any>) => Promise<void>,
): Promise<void> {
  const cwd = new URL('../../..', import.meta.url).pathname;
  if (!built) {
    execFileSync(
      'cargo',
      ['build', '-q', '-p', 'mikaki-identity', '--example', 'haip_wallet', '--locked', '--offline'],
      { cwd, timeout: 60000 },
    );
    built = true;
  }
  const child = spawn(`${cwd}/target/debug/examples/haip_wallet`, [], {
    cwd,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const closed = once(child, 'close');
  const timeout = setTimeout(() => child.kill(), 60000);
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  let errors = '';
  child.stderr.on('data', (chunk) => {
    errors = (errors + String(chunk)).slice(0, 4096);
  });
  const read = async () => {
    const result = await lines.next();
    assert.equal(result.done, false, `Rust HAIP bridge exited: ${errors}`);
    assert.ok(result.value.length <= 96 * 1024);
    return JSON.parse(result.value);
  };
  const command = async (value: unknown) => {
    child.stdin.write(JSON.stringify(value) + '\n');
    return read();
  };
  try {
    const keys = await command(config);
    await run(keys, command);
    assert.equal((await command({ command: 'finish' })).state, 'closed');
    child.stdin.end();
    const [code] = await closed;
    assert.equal(code, 0, `Rust HAIP bridge failed: ${errors}`);
  } finally {
    clearTimeout(timeout);
    if (child.exitCode === null) child.kill();
  }
}
