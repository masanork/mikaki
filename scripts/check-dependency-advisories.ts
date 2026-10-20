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
  const scoped = new Map<string, Exception>();
  for (const value of array(exceptions)) {
    const entry = object(value);
    const fields = ['lockfile', 'package', 'version', 'advisory', 'owner', 'reason', 'expires'];
    if (Object.keys(entry).sort().join() !== fields.sort().join())
      throw new Error('Invalid exception fields');
    for (const field of fields) string(entry[field]);
    const e = entry as Exception;
    if (!expected.includes(e.lockfile) || /[*?]/.test(e.package + e.version + e.advisory)) {
      throw new Error('Exception must name an exact tracked graph, package, version and advisory');
    }
    if (
      !/^\d{4}-\d{2}-\d{2}$/.test(e.expires) ||
      !Number.isFinite(Date.parse(e.expires)) ||
      new Date(e.expires).toISOString().slice(0, 10) !== e.expires ||
      Date.parse(e.expires) <= now.getTime()
    )
      throw new Error(`Expired/invalid exception: ${key(e)}`);
    if (scoped.has(key(e))) throw new Error('Duplicate exception');
    scoped.set(key(e), e);
  }
  const seen = new Set<string>();
  const used = new Set<string>();
  const graphs: { lockfile: string; ecosystem: string; packages: number }[] = [];
  const blocked: Finding[] = [];
  const accepted: (Finding & { disposition: Exception })[] = [];
  const maintenance: Finding[] = [];
  for (const value of array(object(report).results)) {
    const result = object(value);
    const source = object(result.source);
    const path = string(source.path);
    const lockfile = relative(root, isAbsolute(path) ? path : resolve(root, path))
      .split('\\')
      .join('/');
    if (source.type !== 'lockfile' || !expected.includes(lockfile) || seen.has(lockfile)) {
      throw new Error(`Unexpected/duplicate source: ${path}`);
    }
    seen.add(lockfile);
    const packages = array(result.packages);
    if (!packages.length) throw new Error(`Empty graph: ${lockfile}`);
    graphs.push({ lockfile, ecosystem: ecosystem(lockfile), packages: packages.length });
    for (const value of packages) {
      const item = object(value);
      const pkg = object(item.package);
      if (pkg.ecosystem !== ecosystem(lockfile)) throw new Error(`Wrong ecosystem: ${lockfile}`);
      const name = string(pkg.name),
        version = string(pkg.version);
      for (const value of item.vulnerabilities === undefined ? [] : array(item.vulnerabilities)) {
        const vulnerability = object(value);
        const finding = {
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
        const exception = scoped.get(key(finding));
        if (exception) {
          used.add(key(finding));
          accepted.push({ ...finding, disposition: exception });
        } else if (unmaintained) maintenance.push(finding);
        else blocked.push(finding);
      }
    }
  }
  if (seen.size !== expected.length)
    throw new Error(`Missing graphs: ${expected.filter((p) => !seen.has(p)).join(', ')}`);
  for (const id of scoped.keys())
    if (!used.has(id)) throw new Error(`Stale exception; remove after review: ${id}`);
  return { graphs, blocked, accepted, maintenance };
}

export function scan(root: string, binary: string, output: string) {
  const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split(
    '\0',
  );
  const targets = tracked
    .filter((p) =>
      [
        'Cargo.lock',
        'package-lock.json',
        'gradle.lockfile',
        'buildscript-gradle.lockfile',
      ].includes(basename(p)),
    )
    .sort();
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
      { cwd: root, stdio: 'inherit', timeout: 300_000 },
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
      source: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
      workingTreeDirty: !!execFileSync('git', ['status', '--porcelain', '--untracked-files=no'], {
        cwd: root,
        encoding: 'utf8',
      }).trim(),
      scannedAt: new Date().toISOString(),
      tool: execFileSync(binary, ['--version'], { encoding: 'utf8' }).trim(),
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
    const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
    process.exitCode = scan(
      root,
      process.env.MIKAKI_OSV_BIN || 'osv-scanner',
      join(root, 'artifacts/dependencies'),
    );
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}
