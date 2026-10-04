import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { once } from 'node:events';
let built = false;
export async function receiveWithRustEncryption(
  metadata: unknown,
  payload: unknown,
  send: (wire: string) => Promise<string>,
): Promise<any> {
  const cwd = new URL('../../..', import.meta.url).pathname;
  if (!built) {
    execFileSync(
      'cargo',
      [
        'build',
        '-q',
        '-p',
        'mikaki-identity',
        '--example',
        'issuance_wallet',
        '--locked',
        '--offline',
      ],
      { cwd, timeout: 60000 },
    );
    built = true;
  }
  const child = spawn(`${cwd}/target/debug/examples/issuance_wallet`, [], {
    cwd,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const closed = once(child, 'close');
  const timeout = setTimeout(() => child.kill(), 30000);
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  // Fixture errors contain no payload logging; bound stderr without publishing it.
  let errors = '';
  child.stderr.on('data', (chunk) => {
    errors = (errors + String(chunk)).slice(0, 4096);
  });
  const line = async () => {
    const result = await lines.next();
    assert.equal(result.done, false, `Rust encryption bridge exited: ${errors}`);
    assert.ok(result.value.length <= 96 * 1024);
    return JSON.parse(result.value);
  };
  try {
    child.stdin.write(JSON.stringify({ metadata, payload }) + '\n');
    const request = await line();
    assert.equal(typeof request.request, 'string');
    const response = await send(request.request);
    child.stdin.end(JSON.stringify({ response }) + '\n');
    const issued = await line();
    const [code] = await closed;
    assert.equal(code, 0, `Rust decryption failed: ${errors}`);
    return issued;
  } finally {
    clearTimeout(timeout);
    if (child.exitCode === null) child.kill();
  }
}
