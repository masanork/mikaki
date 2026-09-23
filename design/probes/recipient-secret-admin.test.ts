import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

const root = new URL('../..', import.meta.url).pathname;
const manifest = join(root, 'design/probes/pqc/Cargo.toml');
const admin = join(root, 'scripts/recipient-secret-admin.ts');
const config = join(root, 'crates/userinfo-claim-worker/wrangler.production.jsonc');

test('secret preflight verifies a matching owner-only seed without printing it', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mikaki-recipient-secret-'));
  try {
    const seed = join(directory, 'seed.txt');
    const publicRecord = join(directory, 'public.json');
    const generated = spawnSync(
      'cargo',
      [
        'run',
        '--locked',
        '--quiet',
        '--manifest-path',
        manifest,
        '--bin',
        'recipient_key',
        '--',
        'generate',
        seed,
        publicRecord,
        'VAULT_USERINFO_MLKEM_TEST',
        '1',
      ],
      { cwd: root, encoding: 'utf8' },
    );
    assert.equal(generated.status, 0, generated.stderr);
    const command = [
      admin,
      '--seed',
      seed,
      '--public',
      publicRecord,
      '--store-id',
      '0'.repeat(32),
      '--config',
      config,
      '--apply',
      'no',
    ];
    const checked = spawnSync(process.execPath, command, { cwd: root, encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stderr);
    const secret = (await readFile(seed, 'utf8')).trim();
    assert.ok(!checked.stdout.includes(secret));
    assert.ok(!checked.stderr.includes(secret));
    await chmod(seed, 0o644);
    const rejected = spawnSync(process.execPath, command, { cwd: root, encoding: 'utf8' });
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /owner-only regular file/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
