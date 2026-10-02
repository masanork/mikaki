import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const script = fileURLToPath(new URL('./publish-metrics.sh', import.meta.url));
const files = ['history.json', 'code-size.svg', 'coverage.svg', 'dependency-inventory.md'];

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'mikaki-metrics-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const remote = join(root, 'remote.git');
  const seed = join(root, 'seed');
  const worker = join(root, 'worker');
  const other = join(root, 'other');
  function git(cwd, ...args) {
    const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  }
  git(root, 'init', '--bare', '--initial-branch=main', remote);
  git(root, 'clone', remote, seed);
  git(seed, 'config', 'user.name', 'Test');
  git(seed, 'config', 'user.email', 'test@example.invalid');
  mkdirSync(join(seed, 'metrics'));
  for (const file of files) writeFileSync(join(seed, 'metrics', file), 'initial\n');
  git(seed, 'add', '.');
  git(seed, 'commit', '-m', 'Measured source');
  git(seed, 'push', 'origin', 'main');
  const source = git(seed, 'rev-parse', 'HEAD');
  git(root, 'clone', remote, worker);
  git(root, 'clone', remote, other);
  git(other, 'config', 'user.name', 'Test');
  git(other, 'config', 'user.email', 'test@example.invalid');
  writeFileSync(join(worker, 'metrics', 'history.json'), 'updated\n');
  function advance() {
    writeFileSync(join(other, 'feature.txt'), 'new feature\n');
    git(other, 'add', '.');
    git(other, 'commit', '-m', 'New feature');
    git(other, 'push', 'origin', 'main');
    return git(other, 'rev-parse', 'HEAD');
  }
  function publish() {
    return spawnSync('bash', [script], {
      cwd: worker,
      env: { ...process.env, GITHUB_SHA: source },
      encoding: 'utf8',
    });
  }
  return { remote, worker, other, source, git, advance, publish };
}

test('current-source metrics publish as a normal fast-forward', (t) => {
  const f = fixture(t);
  const result = f.publish();
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.git(f.remote, 'show', 'main:metrics/history.json'), 'updated');
  assert.equal(f.git(f.remote, 'rev-parse', 'main^'), f.source);
});

test('a newer main skips old measurements without committing them', (t) => {
  const f = fixture(t);
  const latest = f.advance();
  assert.equal(f.publish().status, 0);
  assert.equal(f.git(f.remote, 'rev-parse', 'main'), latest);
  assert.equal(f.git(f.worker, 'rev-parse', 'HEAD'), f.source);
  assert.equal(f.git(f.remote, 'show', 'main:metrics/history.json'), 'initial');
});

test('a merge racing the push is preserved and treated as a stale run', (t) => {
  const f = fixture(t);
  writeFileSync(
    join(f.worker, '.git', 'hooks', 'pre-push'),
    `#!/usr/bin/env bash\nset -e\nprintf 'feature\\n' > '${f.other}/feature.txt'\ngit -C '${f.other}' add feature.txt\ngit -C '${f.other}' commit -m 'Concurrent merge'\ngit -C '${f.other}' push origin main\n`,
    { mode: 0o755 },
  );
  const result = f.publish();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /advanced during publication/);
  assert.equal(f.git(f.remote, 'show', 'main:feature.txt'), 'feature');
  assert.equal(f.git(f.remote, 'show', 'main:metrics/history.json'), 'initial');
});

test('a rejected push with unchanged main remains a failure', (t) => {
  const f = fixture(t);
  writeFileSync(join(f.remote, 'hooks', 'pre-receive'), '#!/bin/sh\nexit 1\n', {
    mode: 0o755,
  });
  const result = f.publish();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /failed while main was unchanged/);
  assert.equal(f.git(f.remote, 'rev-parse', 'main'), f.source);
});
