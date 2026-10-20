import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

const gitleaks = process.env.MIKAKI_GITLEAKS_BIN || 'gitleaks';
const zizmor = process.env.MIKAKI_ZIZMOR_BIN || 'zizmor';

function fixture(t: { after: (cleanup: () => void) => void }): string {
  const root = mkdtempSync(join(tmpdir(), 'mikaki-security-check-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function run(binary: string, args: string[], cwd: string) {
  const result = spawnSync(binary, args, { cwd, encoding: 'utf8', timeout: 30_000 });
  if (result.error) throw result.error;
  assert.equal(result.signal, null, 'scanner must complete without a timeout or signal');
  return result;
}

function commit(root: string, message: string) {
  for (const args of [
    ['add', '.'],
    [
      '-c',
      'user.name=Security fixture',
      '-c',
      'user.email=security-fixture@example.invalid',
      '-c',
      'core.hooksPath=/dev/null',
      '-c',
      'commit.gpgsign=false',
      'commit',
      '--quiet',
      '-m',
      message,
    ],
  ]) {
    assert.equal(run('git', args, root).status, 0);
  }
}

test('Gitleaks accepts clean history and detects a new inert credential in an existing fixture path', (t) => {
  const root = fixture(t);
  assert.equal(run('git', ['init', '--quiet'], root).status, 0);
  copyFileSync(new URL('../.gitleaksignore', import.meta.url), join(root, '.gitleaksignore'));
  writeFileSync(join(root, 'README.md'), 'Disposable scanner fixture.\n');
  commit(root, 'clean fixture');
  // Keep reports outside the Git repository so their redacted contents are not committed.
  const reports = fixture(t);
  const report = join(reports, 'gitleaks.json');
  const args = [
    'git',
    '--log-opts=HEAD',
    '--ignore-gitleaks-allow',
    '--redact=100',
    '--no-banner',
    '--log-level=error',
    '--report-format=json',
    `--report-path=${report}`,
    '.',
  ];
  assert.equal(run(gitleaks, args, root).status, 0);
  assert.deepEqual(JSON.parse(readFileSync(report, 'utf8')), []);

  // Construct an inert provider-shaped value at runtime; it is never a real credential.
  const inert = [
    'ghp',
    createHash('sha256').update('mikaki inert scanner fixture').digest('hex').slice(0, 36),
  ].join('_');
  const path = 'crates/webauthn/testdata/attestations.json';
  mkdirSync(dirname(join(root, path)), { recursive: true });
  writeFileSync(join(root, path), JSON.stringify({ token: inert }));
  commit(root, 'inert detection fixture');
  assert.equal(run(gitleaks, args, root).status, 1);
  const text = readFileSync(report, 'utf8');
  const findings = JSON.parse(text) as { RuleID: string; File: string; Secret: string }[];
  assert.ok(findings.some((finding) => finding.RuleID === 'github-pat' && finding.File === path));
  assert.ok(findings.every((finding) => finding.Secret === 'REDACTED'));
  assert.ok(!text.includes(inert), 'reports must redact the complete credential');
});

function audit(root: string) {
  return run(
    zizmor,
    [
      '--offline',
      '--strict-collection',
      '--min-severity=medium',
      '--format=json',
      '--no-progress',
      root,
    ],
    root,
  );
}

test('zizmor accepts a safe workflow and rejects shell interpolation of untrusted event data', (t) => {
  const root = fixture(t);
  const workflow = join(root, '.github/workflows/fixture.yml');
  mkdirSync(dirname(workflow), { recursive: true });
  const prefix =
    'name: Scanner fixture\non: issues\npermissions:\n  contents: read\njobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n';
  writeFileSync(workflow, `${prefix}      - run: echo safe\n`);
  assert.equal(audit(root).status, 0);
  writeFileSync(workflow, `${prefix}      - run: echo "${'${{ github.event.issue.title }}'}"\n`);
  const result = audit(root);
  assert.notEqual(result.status, 0);
  const findings = JSON.parse(result.stdout) as { ident: string; ignored: boolean }[];
  assert.ok(findings.some((finding) => finding.ident === 'template-injection' && !finding.ignored));
});

test('zizmor fails collection when one workflow is malformed', (t) => {
  const root = fixture(t);
  const workflows = join(root, '.github/workflows');
  mkdirSync(workflows, { recursive: true });
  writeFileSync(
    join(workflows, 'valid.yml'),
    'name: Valid\non: push\npermissions: {}\njobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo safe\n',
  );
  writeFileSync(join(workflows, 'broken.yml'), 'name: Broken\non: push\njobs: [\n');
  const result = audit(root);
  assert.equal(result.status, 1, 'a parse error must fail the scanner');
});
