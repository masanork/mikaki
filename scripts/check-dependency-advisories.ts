#!/usr/bin/env node
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  appendFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

type Exception = {
  lockfile: string;
  package: string;
  version: string;
  advisory: string;
  owner: string;
  reason: string;
  expires: string;
};
type Finding = {
  lockfile: string;
  package: string;
  version: string;
  advisory: string;
  summary: string;
};
type JsonObject = Record<string, unknown>;
function object(value: unknown): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Expected object');
  return value as JsonObject;
}
function string(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error('Expected nonempty string');
  return value;
}
function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error('Expected array');
  return value;
}
function key(f: Omit<Finding, 'summary'>): string {
  return JSON.stringify([f.lockfile, f.package, f.version, f.advisory]);
}
function ecosystem(path: string): string {
  switch (basename(path)) {
    case 'Cargo.lock':
      return 'crates.io';
    case 'package-lock.json':
      return 'npm';
    case 'gradle.lockfile':
    case 'buildscript-gradle.lockfile':
      return 'Maven';
    default:
      throw new Error(`Unsupported lockfile: ${path}`);
  }
}

function parseException(value: unknown, expected: string[], now: Date): Exception {
  const entry = object(value);
  const fields = ['lockfile', 'package', 'version', 'advisory', 'owner', 'reason', 'expires'];
  if (
    Object.keys(entry).length !== fields.length ||
    !fields.every((field) => Object.hasOwn(entry, field))
  )
    throw new Error('Invalid exception fields');
  for (const field of fields) string(entry[field]);
  const exception = entry as Exception;
  if (
    !expected.includes(exception.lockfile) ||
    /[*?]/.test(exception.package + exception.version + exception.advisory)
  )
    throw new Error('Exception must name an exact tracked graph, package, version and advisory');
  const expiry = Date.parse(exception.expires);
  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(exception.expires) ||
    !Number.isFinite(expiry) ||
    new Date(expiry).toISOString().slice(0, 10) !== exception.expires ||
    expiry <= now.getTime()
  )
    throw new Error(`Expired/invalid exception: ${key(exception)}`);
  return exception;
}
function parseExceptions(values: unknown, expected: string[], now: Date) {
  const scoped = new Map<string, Exception>();
  for (const value of array(values)) {
    const exception = parseException(value, expected, now);
    const id = key(exception);
    if (scoped.has(id)) throw new Error('Duplicate exception');
    scoped.set(id, exception);
  }
  return scoped;
}
function readAdvisory(value: unknown, lockfile: string, name: string, version: string) {
  const vulnerability = object(value);
  const finding: Finding = {
    lockfile,
    package: name,
    version,
    advisory: string(vulnerability.id),
    summary: string(vulnerability.summary),
  };
  const affected = array(vulnerability.affected);
  // "unsound" is actionable. Only pure maintenance notices are warning-only.
  const unmaintained =
    finding.advisory.startsWith('RUSTSEC-') &&
    affected.length > 0 &&
    affected.every((entry) => {
      const metadata = object(entry).database_specific;
      return metadata !== undefined && object(metadata).informational === 'unmaintained';
    });
  return { finding, unmaintained };
}
function readPackage(value: unknown, lockfile: string) {
  const item = object(value),
    pkg = object(item.package);
  if (pkg.ecosystem !== ecosystem(lockfile)) throw new Error(`Wrong ecosystem: ${lockfile}`);
  const name = string(pkg.name),
    version = string(pkg.version);
  const vulnerabilities = item.vulnerabilities === undefined ? [] : array(item.vulnerabilities);
  return vulnerabilities.map((v) => readAdvisory(v, lockfile, name, version));
}
function readGraph(value: unknown, expected: string[], root: string, seen: Set<string>) {
  const result = object(value),
    source = object(result.source),
    path = string(source.path);
  const lockfile = relative(root, isAbsolute(path) ? path : resolve(root, path)).replaceAll(
    '\\',
    '/',
  );
  if (source.type !== 'lockfile' || !expected.includes(lockfile) || seen.has(lockfile))
    throw new Error(`Unexpected/duplicate source: ${path}`);
  seen.add(lockfile);
  const packages = array(result.packages);
  if (!packages.length) throw new Error(`Empty graph: ${lockfile}`);
  return {
    graph: { lockfile, ecosystem: ecosystem(lockfile), packages: packages.length },
    findings: packages.flatMap((pkg) => readPackage(pkg, lockfile)),
  };
}

// Never trust exit code alone: OSV must return a nonempty graph for every requested input.
export function evaluateReport(
  report: unknown,
  expected: string[],
  root: string,
  exceptions: unknown,
  now = new Date(),
) {
  if (!expected.length || new Set(expected).size !== expected.length)
    throw new Error('Invalid targets');
  const scoped = parseExceptions(exceptions, expected, now);
  const seen = new Set<string>(),
    used = new Set<string>();
  const results = array(object(report).results).map((value) =>
    readGraph(value, expected, root, seen),
  );
  if (seen.size !== expected.length)
    throw new Error(`Missing graphs: ${expected.filter((p) => !seen.has(p)).join(', ')}`);
  const blocked: Finding[] = [],
    accepted: (Finding & { disposition: Exception })[] = [],
    maintenance: Finding[] = [];
  for (const { finding, unmaintained } of results.flatMap((result) => result.findings)) {
    const exception = scoped.get(key(finding));
    if (exception) {
      used.add(key(finding));
      accepted.push({ ...finding, disposition: exception });
    } else if (unmaintained) maintenance.push(finding);
    else blocked.push(finding);
  }
  for (const id of scoped.keys())
    if (!used.has(id)) throw new Error(`Stale exception; remove after review: ${id}`);
  return { graphs: results.map((result) => result.graph), blocked, accepted, maintenance };
}

// Git comes from the OS, and child processes cannot select tools from a writable
// checkout, generated directory or inherited custom PATH.
function toolEnvironment() {
  return { ...process.env, PATH: '/usr/bin:/bin' };
}
function git(root: string, args: string[]) {
  return execFileSync('/usr/bin/git', args, {
    cwd: root,
    encoding: 'utf8',
    env: toolEnvironment(),
  });
}

export function scan(root: string, binary: string, output: string) {
  if (!isAbsolute(binary)) throw new Error('OSV scanner must have an absolute executable path');
  const tracked = git(root, ['ls-files', '-z']).split('\0');
  const targets = tracked.filter((p) =>
    ['Cargo.lock', 'package-lock.json', 'gradle.lockfile', 'buildscript-gradle.lockfile'].includes(
      basename(p),
    ),
  );
  targets.sort((a, b) => a.localeCompare(b, 'en'));
  if (!targets.length) throw new Error('No tracked lockfiles');
  const inputs = targets.map((lockfile) => {
    const path = join(root, lockfile);
    if (!lstatSync(path).isFile()) throw new Error(`Missing/nonregular lockfile: ${lockfile}`);
    return { lockfile, sha256: createHash('sha256').update(readFileSync(path)).digest('hex') };
  });
  mkdirSync(output, { recursive: true });
  // Remove old reports before invocation; a tool failure cannot reuse yesterday's clean scan.
  const reportPath = join(output, 'osv.json');
  rmSync(reportPath, { force: true });
  rmSync(join(output, 'summary.json'), { force: true });
  const temporary = mkdtempSync(join(tmpdir(), 'mikaki-osv-'));
  try {
    const config = join(temporary, 'osv-scanner.toml');
    writeFileSync(config, '# No scanner-side vulnerability suppression.\n');
    const result = spawnSync(
      binary,
      [
        'scan',
        'source',
        '--no-resolve',
        '--no-call-analysis=go',
        '--no-call-analysis=rust',
        '--all-packages',
        '--all-vulns',
        `--config=${config}`,
        '--format=json',
        `--output-file=${reportPath}`,
        ...targets.map((p) => `--lockfile=${p}`),
      ],
      { cwd: root, stdio: 'inherit', timeout: 300_000, env: toolEnvironment() },
    );
    if (result.error) throw result.error;
    if (result.signal || (result.status !== 0 && result.status !== 1)) {
      throw new Error(`OSV scan failed: status=${result.status} signal=${result.signal}`);
    }
    const verdict = evaluateReport(
      JSON.parse(readFileSync(reportPath, 'utf8')),
      targets,
      root,
      JSON.parse(readFileSync(join(root, '.github/dependency-advisory-exceptions.json'), 'utf8')),
    );
    if (
      result.status === 1 &&
      !verdict.blocked.length &&
      !verdict.accepted.length &&
      !verdict.maintenance.length
    ) {
      throw new Error('OSV reported failure without advisory evidence');
    }
    const summary = {
      source: git(root, ['rev-parse', 'HEAD']).trim(),
      workingTreeDirty: !!git(root, ['status', '--porcelain', '--untracked-files=no']).trim(),
      scannedAt: new Date().toISOString(),
      tool: execFileSync(binary, ['--version'], {
        encoding: 'utf8',
        env: toolEnvironment(),
      }).trim(),
      inputs,
      ...verdict,
    };
    writeFileSync(join(output, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
    console.log(
      `${targets.length} graphs: ${verdict.blocked.length} blocking, ${verdict.accepted.length} scoped exceptions, ${verdict.maintenance.length} maintenance notices`,
    );
    for (const finding of verdict.blocked) console.error(JSON.stringify(finding));
    if (process.env.GITHUB_STEP_SUMMARY)
      appendFileSync(
        process.env.GITHUB_STEP_SUMMARY,
        `\n## Dependency policy\n\n${targets.length} lockfile graphs scanned; ` +
          `${verdict.blocked.length} blocking findings, ${verdict.accepted.length} exact expiring exceptions, ` +
          `${verdict.maintenance.length} maintenance notices. See the dependency-advisories artifact for scope, input hashes and dispositions.\n`,
      );
    return verdict.blocked.length ? 1 : 0;
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const root = git(process.cwd(), ['rev-parse', '--show-toplevel']).trim();
    process.exitCode = scan(
      root,
      process.env.MIKAKI_OSV_BIN || join(root, 'local/generated/security-tools/osv-scanner'),
      join(root, 'artifacts/dependencies'),
    );
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}
