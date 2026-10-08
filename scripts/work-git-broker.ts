/** Trusted local copy adapter. Only an explicitly supplied private broker is used. */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { PreparedGitCopy } from './work-git-copy.ts';
import { localGit } from './work-git-disclosure.ts';
import {
  readbackBody,
  MAX_GIT_BYTES,
  boundedBody,
} from '../crates/work-effect-worker/git-protocol.ts';
export type PrivateGitBroker = (request: Request) => Promise<Response>;
export async function copyThroughBroker(
  copy: PreparedGitCopy,
  attempts: { upload: string; readback: () => Promise<string> },
  broker: PrivateGitBroker,
) {
  if (
    Object.keys(attempts).sort().join(',') !== 'readback,upload' ||
    typeof attempts.readback !== 'function' ||
    !/^[A-Za-z0-9_-]{43}$/.test(attempts.upload) ||
    copy.uploadBody().length > MAX_GIT_BYTES
  )
    throw new Error('git_copy_invalid');
  const call = async (attempt: string, bytes: Uint8Array) => {
    const response = await broker(
      new Request('https://private.invalid/copy', {
        method: 'POST',
        headers: { 'X-Mikaki-Attempt-ID': attempt, 'X-Mikaki-Copy': JSON.stringify(copy.manifest) },
        body: new Uint8Array(bytes).buffer,
      }),
    );
    if (
      response.status !== 200 ||
      !/^[a-f0-9]{64}$/.test(response.headers.get('X-Mikaki-Git-Plan') ?? '')
    ) {
      await response.body?.cancel();
      throw new Error('git_copy_unconfirmed');
    }
    return { body: await boundedBody(response), plan: response.headers.get('X-Mikaki-Git-Plan')! };
  };
  const uploaded = await call(attempts.upload, copy.uploadBody());
  copy.acknowledge(uploaded.body);
  const readbackId = await attempts.readback();
  if (readbackId === attempts.upload || !/^[A-Za-z0-9_-]{43}$/.test(readbackId))
    throw new Error('git_copy_invalid');
  const readback = await call(readbackId, readbackBody(copy.manifest));
  const dir = await mkdtemp(join(tmpdir(), 'mikaki-git-readback-'));
  try {
    execFileSync('git', ['init', '--bare', '--quiet', dir], {
      env: { PATH: process.env.PATH, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
      stdio: 'ignore',
      timeout: 10000,
    });
    localGit(
      dir,
      ['index-pack', '--stdin', '--strict'],
      Buffer.from(readback.body),
      {},
      MAX_GIT_BYTES,
    );
    localGit(dir, ['update-ref', copy.manifest.ref, copy.manifest.commit, '0'.repeat(40)]);
    const facts = await copy.verifyReadback(dir);
    return { ...facts, upload_plan: uploaded.plan, readback_plan: readback.plan };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
