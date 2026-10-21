import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import test from 'node:test';
import { evaluateReport, scan } from './check-dependency-advisories.ts';

const root = '/fixture';
const now = new Date('2026-10-21T00:00:00Z');
const paths = ['Cargo.lock', 'app/package-lock.json', 'service/gradle.lockfile'];
function report() {
  return {
    results: paths.map((path, i) => ({
      source: { path: join(root, path), type: 'lockfile' },
      packages: [
        {
          package: {
            name: 'example',
            version: '1.0.0',
            ecosystem: ['crates.io', 'npm', 'Maven'][i],
          },
          vulnerabilities: [] as object[],
        },
      ],
    })),
  };
}
function advisory(informational?: string) {
  return {
    id: 'RUSTSEC-2000-0001',
    summary: 'Fixture vulnerability',
    affected: [{ database_specific: informational ? { informational } : {} }],
  };
}
const exception = {
  lockfile: 'Cargo.lock',
  package: 'example',
  version: '1.0.0',
  advisory: 'RUSTSEC-2000-0001',
  owner: 'reviewer',
  reason: 'Synthetic policy fixture',
  expires: '2026-11-20',
};

test('all three ecosystems require complete, unique, nonempty report coverage', () => {
  assert.equal(evaluateReport(report(), paths, root, [], now).graphs.length, 3);
  for (const mutate of [
    (r: ReturnType<typeof report>) => {
      r.results.pop();
    },
    (r: ReturnType<typeof report>) => {
      r.results.push(r.results[0]);
    },
    (r: ReturnType<typeof report>) => {
      r.results[0].packages = [];
    },
    (r: ReturnType<typeof report>) => {
      r.results[0].source.path = '/outside/Cargo.lock';
    },
    (r: ReturnType<typeof report>) => {
      r.results[0].packages[0].package.ecosystem = 'npm';
    },
  ]) {
    const r = report();
    mutate(r);
    assert.throws(() => evaluateReport(r, paths, root, [], now));
  }
  for (const malformed of [{}, { results: null }, { results: [{}] }]) {
    assert.throws(() => evaluateReport(malformed, paths, root, [], now));
  }
});

test('unsound and unknown advisories block; only pure unmaintained notices are warnings', () => {
  const r = report();
  for (const information of [undefined, 'unsound', 'unmaintained']) {
    r.results[0].packages[0].vulnerabilities = [advisory(information)];
    const result = evaluateReport(r, paths, root, [], now);
    assert.equal(result.blocked.length, information === 'unmaintained' ? 0 : 1);
    assert.equal(result.maintenance.length, information === 'unmaintained' ? 1 : 0);
  }
  r.results[0].packages[0].vulnerabilities = [
    {
      ...advisory('unmaintained'),
      affected: [...advisory('unmaintained').affected, ...advisory('unsound').affected],
    },
  ];
  assert.equal(evaluateReport(r, paths, root, [], now).blocked.length, 1);
});

test('exceptions expire and cannot cover a different graph, package, version or advisory', () => {
  const r = report();
  r.results[0].packages[0].vulnerabilities = [advisory()];
  assert.equal(evaluateReport(r, paths, root, [exception], now).accepted.length, 1);
  for (const replacement of [
    { lockfile: 'app/package-lock.json' },
    { package: 'other' },
    { version: '2.0.0' },
    { advisory: 'RUSTSEC-2000-0002' },
    { expires: '2026-10-21' },
    { expires: '2026-02-30' },
    { owner: '' },
    { version: '*' },
    { extra: true },
  ])
    assert.throws(() => evaluateReport(r, paths, root, [{ ...exception, ...replacement }], now));
  assert.throws(() => evaluateReport(r, paths, root, [exception, exception], now));
  assert.throws(() => evaluateReport(report(), paths, root, [exception], now), /Stale exception/);
});

test('tool errors cannot pass using stale or partially produced reports', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-dependency-policy-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const args of [
    ['init', '--quiet'],
    ['add', 'Cargo.lock'],
  ]) {
    writeFileSync(join(directory, 'Cargo.lock'), 'version = 4\n');
    assert.equal(spawnSync('git', args, { cwd: directory }).status, 0);
  }
  const output = join(directory, 'output');
  mkdirSync(output);
  writeFileSync(join(output, 'osv.json'), JSON.stringify(report()));
  writeFileSync(join(output, 'summary.json'), '{}');
  const binary = join(directory, 'failing-scanner');
  writeFileSync(binary, '#!/bin/sh\nexit 2\n');
  chmodSync(binary, 0o755);
  assert.throws(() => scan(directory, binary, output), /OSV scan failed/);
  assert.ok(!existsSync(join(output, 'osv.json')));
  assert.ok(!existsSync(join(output, 'summary.json')));
  writeFileSync(binary, '#!/bin/sh\nexit 0\n');
  assert.throws(() => scan(directory, binary, output), /ENOENT/);
});

test('scanner children and Git cannot be shadowed through an inherited writable PATH', (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'mikaki-dependency-path-'));
  const previousPath = process.env.PATH;
  const previousMarker = process.env.MIKAKI_TEST_HIJACK_MARKER;
  t.after(() => {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    if (previousMarker === undefined) delete process.env.MIKAKI_TEST_HIJACK_MARKER;
    else process.env.MIKAKI_TEST_HIJACK_MARKER = previousMarker;
    rmSync(directory, { recursive: true, force: true });
  });
  writeFileSync(join(directory, 'Cargo.lock'), 'version = 4\n');
  for (const args of [
    ['init', '--quiet'],
    ['add', 'Cargo.lock'],
  ])
    assert.equal(spawnSync('/usr/bin/git', args, { cwd: directory }).status, 0);
  const malicious = join(directory, 'bin');
  mkdirSync(malicious);
  for (const name of ['git', 'mikaki_dependency_path_fixture_280']) {
    const command = join(malicious, name);
    writeFileSync(command, '#!/bin/sh\n: > "$MIKAKI_TEST_HIJACK_MARKER"\nexit 2\n');
    chmodSync(command, 0o755);
  }
  const marker = join(directory, 'hijacked');
  process.env.PATH = `${malicious}${delimiter}${previousPath ?? ''}`;
  process.env.MIKAKI_TEST_HIJACK_MARKER = marker;
  const probe = join(directory, 'probe');
  writeFileSync(probe, '#!/bin/sh\nexec mikaki_dependency_path_fixture_280\n');
  chmodSync(probe, 0o755);
  // The scanner's child command also receives only the fixed OS search path.
  assert.throws(() => scan(directory, probe, join(directory, 'output')), /OSV scan failed/);
  assert.ok(!existsSync(marker), 'neither shadow executable may run');
  assert.throws(
    () => scan(directory, 'osv-scanner', join(directory, 'output')),
    /absolute executable/,
  );
});
