import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, realpath, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { ownedMultipazCheckout } from './wallet-multipaz-checkout.ts';

test('SDK execution requires an owned checkout protected from shared-directory replacement', async (t) => {
  if (!process.getuid) return t.skip('POSIX ownership is required by the SDK runner');
  const workspace = await mkdtemp(join(tmpdir(), 'mikaki-sdk-ownership-'));
  try {
    const checkout = join(workspace, 'sdk');
    await mkdir(checkout, { mode: 0o700 });
    assert.equal(await ownedMultipazCheckout(checkout), await realpath(checkout));
    const alias = join(workspace, 'alias');
    await symlink(checkout, alias);
    assert.equal(await ownedMultipazCheckout(alias), await realpath(checkout));

    for (const mode of [0o770, 0o777, 0o1777]) {
      await chmod(checkout, mode);
      await assert.rejects(ownedMultipazCheckout(checkout), /must not permit/);
      await assert.rejects(ownedMultipazCheckout(alias), /must not permit/);
    }
    await chmod(checkout, 0o700);
    await chmod(workspace, 0o777);
    await assert.rejects(ownedMultipazCheckout(checkout), /must not permit/);
  } finally {
    await chmod(workspace, 0o700);
    await rm(workspace, { recursive: true, force: true });
  }
});
