import assert from 'node:assert/strict';
import { chmod, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { readAccessPrivateInput } from './access-private-input.ts';

test('private operator input rejects symlinks, permissive modes, directories and oversized files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-access-input-'));
  const path = join(directory, 'input.json');
  try {
    await writeFile(path, '{"client":"synthetic"}', { mode: 0o600 });
    assert.deepEqual(await readAccessPrivateInput(path), { client: 'synthetic' });
    await symlink(path, join(directory, 'link.json'));
    await assert.rejects(readAccessPrivateInput(join(directory, 'link.json')));
    await chmod(path, 0o644);
    await assert.rejects(readAccessPrivateInput(path), /owner-only/);
    await assert.rejects(readAccessPrivateInput(directory), /owner-only/);
    await chmod(path, 0o600);
    await writeFile(path, 'x'.repeat(16385));
    await assert.rejects(readAccessPrivateInput(path), /owner-only/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
