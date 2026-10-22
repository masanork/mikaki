import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  budget,
  corpusManifest,
  execute,
  statistics,
  successful,
  type Execution,
} from './run-webauthn-fuzz.ts';

const complete = `Done 1000 runs in 3 second(s)\nstat::number_of_executed_units: 1000\nstat::average_exec_per_sec: 333\nstat::new_units_added: 8\nstat::peak_rss_mb: 120\n`;
const finished: Execution = {
  exit_code: 0,
  signal: null,
  timed_out: false,
  interrupted: false,
  wall_seconds: 3.5,
};
const fixture = (t: { after: (fn: () => void) => void }) => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-fuzz-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
};

test('only bounded decimal exploration budgets are accepted', () => {
  assert.equal(budget('1'), 1);
  assert.equal(budget('1800'), 1800);
  for (const input of ['0', '1801', '-1', '', '01', '1.5', '1e3', ' 30', '30\n', '30; echo unsafe'])
    assert.throws(() => budget(input));
});

test('a passing exploration needs complete consistent measured statistics', () => {
  assert.deepEqual(successful(finished, complete, 3), {
    executions: 1000,
    fuzz_seconds: 3,
    average_exec_per_second: 333,
    peak_rss_mb: 120,
    new_units_added: 8,
  });
  for (const log of [
    '',
    complete.replace('Done 1000', 'Done 999'),
    complete.replace('stat::peak_rss_mb: 120\n', ''),
    complete + 'stat::peak_rss_mb: 10\n',
    complete + 'Done 1000 runs in 3 second(s)',
    complete.replace('3 second(s)', '99999999999999999999 second(s)'),
    complete.replace('1000', '0'),
  ])
    assert.throws(() => statistics(log));
  assert.throws(() => successful(finished, complete, 4), /budget/);
  assert.throws(() => successful({ ...finished, wall_seconds: 0.1 }, complete, 3), /budget/);
  assert.throws(
    () => successful(finished, complete.replace('peak_rss_mb: 120', 'peak_rss_mb: 1025'), 3),
    /RSS/,
  );
});

test('successful-looking output cannot override process failures or sanitizer findings', () => {
  for (const execution of [
    { ...finished, exit_code: 77 },
    { ...finished, exit_code: null, signal: 'SIGKILL' as const },
    { ...finished, timed_out: true },
    { ...finished, interrupted: true },
  ])
    assert.throws(() => successful(execution, complete, 3));
  for (const marker of [
    'ERROR: libFuzzer: deadly signal',
    'ERROR: AddressSanitizer: heap-buffer-overflow',
    'SUMMARY: UndefinedBehaviorSanitizer: bounds',
  ])
    assert.throws(() => successful(finished, complete + marker, 3));
});

test('copied corpus bytes match their hashes and reject unsafe entries', (t) => {
  const root = fixture(t);
  const source = join(root, 'source');
  const destination = join(root, 'copy');
  mkdirSync(source);
  mkdirSync(destination);
  const input = Buffer.from([0, 255, 2]);
  writeFileSync(join(source, 'seed'), input);
  const manifest = corpusManifest(source, 3, destination);
  assert.deepEqual(manifest, {
    count: 1,
    bytes: 3,
    files: [{ name: 'seed', bytes: 3, sha256: createHash('sha256').update(input).digest('hex') }],
  });
  assert.deepEqual(readFileSync(join(destination, 'seed')), input);
  assert.throws(() => corpusManifest(source, 2), /invalid corpus/);
  symlinkSync(join(source, 'seed'), join(source, 'link'));
  assert.throws(() => corpusManifest(source, 3), /invalid corpus/);
  rmSync(join(source, 'link'));
  mkdirSync(join(source, 'nested'));
  assert.throws(() => corpusManifest(source, 3), /invalid corpus/);
  symlinkSync(source, join(root, 'directory-link'));
  assert.throws(() => corpusManifest(join(root, 'directory-link'), 3), /directory/);
  const empty = join(root, 'empty');
  mkdirSync(empty);
  assert.throws(() => corpusManifest(empty, 3), /count/);
});

test('actual child exits and timeouts remain failures with retained output', async (t) => {
  const root = fixture(t);
  const failed = await execute(
    process.execPath,
    ['-e', 'console.error("inert failure"); process.exit(77)'],
    { cwd: root, env: {}, log: join(root, 'failed.log'), timeoutMs: 2000 },
  );
  assert.equal(failed.exit_code, 77);
  assert.match(readFileSync(join(root, 'failed.log'), 'utf8'), /inert failure/);
  assert.throws(() => successful(failed, complete, 1));
  const timedOut = await execute(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
    cwd: root,
    env: {},
    log: join(root, 'timeout.log'),
    timeoutMs: 100,
  });
  assert.equal(timedOut.timed_out, true);
  assert.equal(timedOut.signal, 'SIGKILL');
  assert.throws(() => successful(timedOut, complete, 1));
  const grandchild =
    'setTimeout(() => require("node:fs").writeFileSync("escaped", "unexpected"), 500)';
  const parent = `const child = require('node:child_process').spawn(process.execPath, ['-e', ${JSON.stringify(grandchild)}], { stdio: 'ignore' }); require('node:fs').writeFileSync('descendant.pid', String(child.pid)); setInterval(() => {}, 1000);`;
  await execute(process.execPath, ['-e', parent], {
    cwd: root,
    env: {},
    log: join(root, 'group.log'),
    timeoutMs: 200,
  });
  assert.ok(existsSync(join(root, 'descendant.pid')));
  await new Promise((resolve) => setTimeout(resolve, 600));
  assert.equal(
    existsSync(join(root, 'escaped')),
    false,
    'timeout must kill the fuzzer descendant, not just Cargo',
  );
  await assert.rejects(
    execute(join(root, 'not-installed'), [], {
      cwd: root,
      env: {},
      log: join(root, 'absent.log'),
      timeoutMs: 100,
    }),
  );
});

test('invalid CLI budgets replace old passing evidence without starting tools', (t) => {
  const root = fixture(t);
  // Use an isolated copy of the actual entrypoint, with no tool installation.
  const scripts = join(root, 'scripts');
  mkdirSync(scripts);
  const entrypoint = join(scripts, 'run-webauthn-fuzz.ts');
  writeFileSync(entrypoint, readFileSync(new URL('run-webauthn-fuzz.ts', import.meta.url)));
  const output = join(root, 'artifacts/webauthn-fuzz/registration');
  mkdirSync(output, { recursive: true });
  writeFileSync(join(output, 'report.json'), JSON.stringify({ status: 'passed' }));
  const child = spawnSync(process.execPath, [entrypoint, 'registration', '0'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 5000,
  });
  assert.equal(child.status, 1, child.stderr);
  const report = JSON.parse(readFileSync(join(output, 'report.json'), 'utf8'));
  assert.equal(report.status, 'failed');
  assert.match(report.error, /duration/);
  assert.ok(report.execution_id);
  assert.equal(existsSync(join(root, 'target')), false);
});

test('relative or empty tool homes fail before any executable can run', (t) => {
  const root = fixture(t);
  mkdirSync(join(root, 'scripts'));
  const entry = join(root, 'scripts/run-webauthn-fuzz.ts');
  writeFileSync(entry, readFileSync(new URL('run-webauthn-fuzz.ts', import.meta.url)));
  mkdirSync(join(root, 'target/fuzz-tools/bin'), { recursive: true });
  writeFileSync(join(root, 'target/fuzz-tools/bin/cargo-fuzz'), 'not an executable');
  for (const invalid of [
    { CARGO_HOME: '' },
    { CARGO_HOME: 'relative' },
    { RUSTUP_HOME: '' },
    { RUSTUP_HOME: 'relative' },
  ]) {
    const child = spawnSync(process.execPath, [entry, 'registration', '1'], {
      cwd: root,
      env: { ...process.env, ...invalid },
      encoding: 'utf8',
      timeout: 5000,
    });
    assert.equal(child.status, 1);
    const report = JSON.parse(
      readFileSync(join(root, 'artifacts/webauthn-fuzz/registration/report.json'), 'utf8'),
    );
    assert.equal(report.status, 'failed');
    assert.match(report.error, /HOME must be absolute/);
    assert.equal(report.execution, undefined);
  }
});
