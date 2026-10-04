import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { copyFile, mkdir } from 'node:fs/promises';
import { createServer } from 'node:http';
import { promisify } from 'node:util';
import { multipazCommit } from './multipaz-wallet.ts';

/** SDK format/signature verification only: decrypted synthetic public proof material stays in memory. */
export async function verifyNativeWithMultipaz(input: {
  sd: string;
  mdoc: string;
  nonce: string;
  at: number;
  issuer: string;
  issuer_key: object;
  holder_sd: object;
  holder_mdoc: object;
  recipient_thumbprint: string;
}) {
  const checkout = process.env.MIKAKI_MULTIPAZ_PRESENTATION_CHECKOUT;
  if (!checkout) return;
  assert.ok(checkout.startsWith('/private/tmp/'));
  const run = promisify(execFile);
  const head = await run('git', ['rev-parse', 'HEAD'], { cwd: checkout });
  assert.equal(head.stdout.trim(), multipazCommit);
  const tracked = await run('git', ['status', '--porcelain', '--untracked-files=no'], {
    cwd: checkout,
  });
  assert.equal(tracked.stdout.trim(), '', 'SDK tracked sources must remain unchanged');
  await mkdir(`${checkout}/multipaz/src/jvmTest/kotlin/org/multipaz/mdoc/response`, {
    recursive: true,
  });
  await copyFile(
    new URL('../multipaz/MikakiPresentationTest.kt', import.meta.url),
    `${checkout}/multipaz/src/jvmTest/kotlin/org/multipaz/mdoc/response/MikakiPresentationTest.kt`,
  );
  const payload = JSON.stringify(input);
  assert.ok(Buffer.byteLength(payload) <= 96 * 1024);
  const expected = Buffer.from(`Bearer ${randomBytes(32).toString('base64url')}`);
  let served = false;
  const server = createServer((req, res) => {
    const supplied = Buffer.from(req.headers.authorization ?? '');
    if (
      req.method !== 'GET' ||
      req.url !== '/' ||
      served ||
      supplied.length !== expected.length ||
      !timingSafeEqual(supplied, expected)
    ) {
      res.writeHead(403).end();
      return;
    }
    served = true;
    res
      .writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
      .end(payload);
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  try {
    await new Promise<void>((resolve, reject) => {
      const child = spawn(
        './gradlew',
        [
          ':multipaz:jvmTest',
          '--offline',
          '--rerun',
          '--tests',
          '*MikakiPresentationTest',
          '--no-daemon',
          '--max-workers=2',
          '--console=plain',
        ],
        {
          cwd: checkout,
          env: {
            ...process.env,
            MIKAKI_MULTIPAZ_BRIDGE: `http://127.0.0.1:${address.port}/`,
            MIKAKI_MULTIPAZ_BRIDGE_SECRET: expected.toString().slice('Bearer '.length),
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      let output = '';
      const collect = (chunk: Buffer) => {
        output = (output + chunk.toString()).slice(-12000);
      };
      child.stdout.on('data', collect);
      child.stderr.on('data', collect);
      const timer = setTimeout(() => child.kill('SIGTERM'), 14 * 60 * 1000);
      child.on('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (code === 0) resolve();
        else reject(new Error(`Multipaz presentation SDK test failed (${code}):\n${output}`));
      });
    });
    assert.equal(served, true, 'SDK test must consume the native presentation');
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}
