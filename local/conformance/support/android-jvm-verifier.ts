import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import type { JWK } from 'jose';

/** Test classpath only: production distribution has no fixture-root entry point. */
export async function androidJvmVerifier() {
  const classpath = await readFile(
    new URL(
      '../../../services/android-attestation-verifier/build/integration-classpath.txt',
      import.meta.url,
    ),
    'utf8',
  );
  const token = randomBytes(32).toString('base64url');
  const child = spawn(
    process.env.JAVA_HOME ? join(process.env.JAVA_HOME, 'bin/java') : 'java',
    ['-cp', classpath, 'app.mikaki.attestation.IntegrationFixtureKt'],
    {
      env: { ...process.env, MIKAKI_ANDROID_VERIFIER_TOKEN: token },
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  );
  // Capture only bounded diagnostics and never print fixture protocol/evidence on success.
  let diagnostics = '';
  child.stderr.on('data', (chunk: Buffer) => {
    diagnostics = (diagnostics + chunk.toString()).slice(-2048);
  });
  const lines = createInterface({ input: child.stdout });
  const iterator = lines[Symbol.asyncIterator]();
  const next = async (): Promise<Record<string, unknown>> => {
    let timer: NodeJS.Timeout | undefined;
    try {
      const line = await Promise.race([
        iterator.next(),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(Error('JVM fixture timeout')), 15000);
        }),
      ]);
      assert.ok(!line.done, `JVM fixture exited: ${diagnostics}`);
      assert.ok(line.value.length < 65536);
      return JSON.parse(line.value) as Record<string, unknown>;
    } finally {
      clearTimeout(timer);
    }
  };
  const closed = once(child, 'exit');
  const stop = async () => {
    child.stdin.end();
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000);
    try {
      await closed;
    } finally {
      clearTimeout(timer);
      lines.close();
    }
  };
  try {
    const ready = await next();
    assert.equal(typeof ready.policy_hash, 'string');
    assert.match(String(ready.verify_url), /^http:\/\/127\.0\.0\.1:[0-9]+\/verify$/);
    const command = async (body: unknown) => {
      child.stdin.write(`${JSON.stringify(body)}\n`);
      return next();
    };
    return {
      policy: String(ready.policy_hash),
      token,
      url: String(ready.verify_url),
      stop,
      async certificates(challenge: string, publicKey: JWK, options = {}) {
        const response = await command({
          command: 'certificate',
          challenge,
          public_key: publicKey,
          ...options,
        });
        assert.ok(Array.isArray(response.certificate_chain));
        return response.certificate_chain as string[];
      },
      async status(mode: 'good' | 'unavailable' | 'stale' | 'revoked') {
        assert.equal((await command({ command: 'status', mode })).ok, true);
      },
    };
  } catch (error) {
    await stop();
    throw error;
  }
}
