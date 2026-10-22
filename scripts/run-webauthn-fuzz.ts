import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { delimiter, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const targets = {
  registration: 65_538,
  assertion: 65_538,
  android: 16_416,
  metadata: 131_074,
} as const;
export const toolchain = 'nightly-2026-09-21';
const root = fileURLToPath(new URL('../', import.meta.url));
const sha256 = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');
const save = (path: string, value: unknown) =>
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });

export function budget(value: string) {
  assert.match(value, /^[1-9]\d{0,3}$/, 'duration must be a decimal integer');
  const seconds = Number(value);
  assert.equal(String(seconds), value, 'duration must be a canonical decimal integer');
  assert.ok(seconds <= 1800, 'duration must be at most 1800 seconds');
  return seconds;
}

/** Flat, bounded, regular files only; copy the same bytes that were hashed. */
export function corpusManifest(directory: string, maxLength: number, copyTo?: string) {
  assert.ok(
    lstatSync(directory).isDirectory() && !lstatSync(directory).isSymbolicLink(),
    'invalid corpus directory',
  );
  const entries = readdirSync(directory).sort((a, b) => a.localeCompare(b));
  assert.ok(entries.length > 0 && entries.length <= 20_000, 'invalid corpus file count');
  let bytes = 0;
  const files = entries.map((name) => {
    const path = join(directory, name);
    const stat = lstatSync(path);
    assert.ok(stat.isFile() && stat.size <= maxLength, 'invalid corpus entry');
    bytes += stat.size;
    assert.ok(bytes <= 64 * 1024 * 1024, 'corpus exceeds 64 MiB');
    const data = readFileSync(path);
    assert.equal(data.length, stat.size, 'corpus changed while reading');
    if (copyTo) writeFileSync(join(copyTo, name), data, { flag: 'wx', mode: 0o600 });
    return { name, bytes: data.length, sha256: sha256(data) };
  });
  return { count: files.length, bytes, files };
}

export type Execution = {
  exit_code: number | null;
  signal: NodeJS.Signals | null;
  timed_out: boolean;
  interrupted: boolean;
  wall_seconds: number;
};

/** A timeout kills the whole owned process group, including Cargo's fuzzer child. */
export function execute(
  binary: string,
  args: string[],
  {
    cwd,
    env,
    log,
    timeoutMs,
  }: { cwd: string; env: NodeJS.ProcessEnv; log: string; timeoutMs: number },
): Promise<Execution> {
  return new Promise((resolveRun, reject) => {
    const fd = openSync(log, 'w', 0o600);
    const start = performance.now();
    const child = spawn(binary, args, { cwd, env, detached: true, stdio: ['ignore', fd, fd] });
    closeSync(fd);
    let timedOut = false;
    let interrupted = false;
    const kill = () => {
      if (child.pid) {
        try {
          process.kill(-child.pid, 'SIGKILL');
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
        }
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, timeoutMs);
    const interrupt = () => {
      interrupted = true;
      kill();
    };
    process.once('SIGTERM', interrupt);
    process.once('SIGINT', interrupt);
    const cleanup = () => {
      clearTimeout(timer);
      process.removeListener('SIGTERM', interrupt);
      process.removeListener('SIGINT', interrupt);
    };
    child.once('error', () => {
      cleanup();
      reject(new Error('fuzzer process could not start'));
    });
    child.once('close', (code, signal) => {
      cleanup();
      resolveRun({
        exit_code: code,
        signal,
        timed_out: timedOut,
        interrupted,
        wall_seconds: (performance.now() - start) / 1000,
      });
    });
  });
}

export function statistics(log: string) {
  const completions = [...log.matchAll(/Done (\d+) runs in (\d+) second\(s\)/g)];
  const value = (name: string) => {
    const matches = [...log.matchAll(new RegExp(String.raw`^stat::${name}:\s+(\d+)\s*$`, 'gm'))];
    assert.equal(matches.length, 1, `missing or duplicate ${name}`);
    const n = Number(matches[0][1]);
    assert.ok(Number.isSafeInteger(n), 'invalid fuzzer statistic');
    return n;
  };
  assert.equal(completions.length, 1, 'missing or duplicate completed fuzz run');
  const done = completions[0];
  const executions = value('number_of_executed_units');
  assert.ok(executions > 0 && Number(done[1]) === executions, 'inconsistent execution count');
  const peakRss = value('peak_rss_mb');
  assert.ok(peakRss > 0, 'missing measured RSS');
  const seconds = Number(done[2]);
  assert.ok(Number.isSafeInteger(seconds) && seconds >= 0, 'invalid fuzz duration');
  return {
    executions,
    fuzz_seconds: seconds,
    average_exec_per_second: value('average_exec_per_sec'),
    peak_rss_mb: peakRss,
    new_units_added: value('new_units_added'),
  };
}

export function successful(execution: Execution, log: string, seconds: number) {
  assert.equal(execution.exit_code, 0, 'fuzzer exited unsuccessfully');
  assert.equal(execution.signal, null, 'fuzzer was interrupted');
  assert.equal(execution.timed_out, false, 'fuzzer exceeded its wall deadline');
  assert.equal(execution.interrupted, false, 'fuzzer was interrupted by the caller');
  const stats = statistics(log);
  assert.ok(
    stats.fuzz_seconds >= seconds && execution.wall_seconds >= seconds,
    'requested exploration budget was not completed',
  );
  assert.ok(stats.peak_rss_mb <= 1024, 'fuzzer exceeded its RSS budget');
  assert.doesNotMatch(
    log,
    /ERROR: (?:libFuzzer|AddressSanitizer|LeakSanitizer)|SUMMARY: (?:AddressSanitizer|UndefinedBehaviorSanitizer)/,
    'fuzzer reported a finding',
  );
  return stats;
}

function command(
  binary: string,
  args: string[],
  { env, cwd }: { env: NodeJS.ProcessEnv; cwd: string },
) {
  const result = spawnSync(binary, args, {
    cwd,
    env,
    encoding: 'utf8',
    timeout: 30_000,
    maxBuffer: 1024 * 1024,
  });
  assert.ok(!result.error && result.status === 0, 'metadata command failed');
  return result.stdout.trim();
}

function tools(directory: string) {
  const home = process.env.CARGO_HOME ?? join(homedir(), '.cargo');
  assert.ok(home.length > 0 && isAbsolute(home), 'CARGO_HOME must be absolute');
  const cargo = join(home, 'bin/cargo');
  const rustc = join(home, 'bin/rustc');
  const fuzz = join(directory, 'target/fuzz-tools/bin/cargo-fuzz');
  assert.ok(existsSync(fuzz), 'install pinned cargo-fuzz into target/fuzz-tools');
  const rustup = process.env.RUSTUP_HOME ?? join(homedir(), '.rustup');
  assert.ok(rustup.length > 0 && isAbsolute(rustup), 'RUSTUP_HOME must be absolute');
  const env = {
    HOME: homedir(),
    CARGO_HOME: home,
    RUSTUP_HOME: rustup,
    TMPDIR: tmpdir(),
    PATH: [dirname(fuzz), dirname(cargo), '/usr/bin', '/bin'].join(delimiter),
    RUSTUP_TOOLCHAIN: toolchain,
    CARGO_NET_OFFLINE: 'true',
    CARGO_TERM_COLOR: 'never',
    RUST_BACKTRACE: '1',
    ASAN_OPTIONS: 'color=never',
    LANG: 'C',
  };
  assert.equal(
    command(cargo, [`+${toolchain}`, 'fuzz', '--version'], { env, cwd: directory }),
    'cargo-fuzz 0.13.2',
  );
  return {
    cargo,
    env,
    metadata: {
      cargo_fuzz: '0.13.2',
      cargo_fuzz_sha256: sha256(readFileSync(fuzz)),
      rustc: command(rustc, [`+${toolchain}`, '-vV'], { env, cwd: directory }),
      sanitizer: 'address',
      cfg_fuzzing: true,
    },
  };
}

/** Each invocation gets a private working corpus; previous mutations are never auto-imported. */
export async function campaign(
  target: string,
  duration: string,
  { directory = root, canary = false } = {},
) {
  const maximum = canary ? 64 : targets[target as keyof typeof targets];
  assert.ok(
    maximum && (canary ? target === 'harness_canary' : Object.hasOwn(targets, target)),
    'unknown fuzz target',
  );
  const output = join(directory, 'artifacts/webauthn-fuzz', target);
  mkdirSync(output, { recursive: true });
  const reportPath = join(output, 'report.json');
  const id = randomUUID();
  const run = join(output, 'runs', id);
  const corpus = join(run, 'corpus');
  const findings = join(run, 'findings');
  mkdirSync(corpus, { recursive: true });
  mkdirSync(findings);
  const report: Record<string, unknown> = {
    format: 'mikaki-webauthn-fuzz-v1',
    target,
    execution_id: id,
    started_at: new Date().toISOString(),
    status: 'incomplete',
    qualification: canary ? 'harness-canary-only' : 'bounded-parser-exploration-only',
  };
  save(reportPath, report);
  let log = '';
  try {
    const seconds = budget(duration);
    const selected = tools(directory);
    const git = (args: string[]) =>
      command('/usr/bin/git', args, { env: selected.env, cwd: directory });
    const commit = git(['rev-parse', 'HEAD']);
    const state = git(['status', '--porcelain', '--untracked-files=all']);
    assert.ok(!process.env.CI || state.length === 0, 'CI requires a clean source tree');
    const lock = sha256(readFileSync(join(directory, 'fuzz/Cargo.lock')));
    Object.assign(report, {
      source_commit: commit,
      source_clean: state.length === 0,
      fuzz_lock_sha256: lock,
      tools: selected.metadata,
      requested_seconds: seconds,
      limits: {
        max_length: maximum,
        input_timeout_seconds: 10,
        rss_limit_mb: 1024,
        wall_timeout_seconds: seconds + 120,
      },
    });
    if (canary) writeFileSync(join(corpus, 'canary'), 'mikaki fuzz harness canary v1');
    const initial = canary
      ? corpusManifest(corpus, maximum)
      : corpusManifest(join(directory, 'fuzz/corpus', target), maximum, corpus);
    save(join(run, 'input-manifest.json'), initial);
    report.initial_corpus = { count: initial.count, bytes: initial.bytes };
    save(reportPath, report);
    const logPath = join(run, 'fuzzer.log');
    const execution = await execute(
      selected.cargo,
      [
        `+${toolchain}`,
        'fuzz',
        'run',
        target,
        corpus,
        '--sanitizer',
        'address',
        '--',
        `-max_total_time=${seconds}`,
        `-max_len=${maximum}`,
        '-timeout=10',
        '-rss_limit_mb=1024',
        '-print_final_stats=1',
        `-artifact_prefix=${findings}/`,
      ],
      { cwd: directory, env: selected.env, log: logPath, timeoutMs: (seconds + 120) * 1000 },
    );
    report.execution = execution;
    assert.ok(lstatSync(logPath).size <= 32 * 1024 * 1024, 'fuzzer log exceeds 32 MiB');
    log = readFileSync(logPath, 'utf8');
    assert.equal(git(['rev-parse', 'HEAD']), commit, 'source commit changed during fuzzing');
    assert.equal(
      git(['status', '--porcelain', '--untracked-files=all']),
      state,
      'source tree changed during fuzzing',
    );
    assert.equal(
      sha256(readFileSync(join(directory, 'fuzz/Cargo.lock'))),
      lock,
      'fuzz lockfile changed during fuzzing',
    );
    const final = corpusManifest(corpus, maximum);
    save(join(run, 'output-manifest.json'), final);
    report.final_corpus = { count: final.count, bytes: final.bytes };
    report.findings = readdirSync(findings).length;
    report.statistics = successful(execution, log, seconds);
    assert.equal(report.findings, 0, 'fuzzer produced a finding artifact');
    report.status = 'passed';
  } catch (error) {
    report.status = 'failed';
    report.error =
      error instanceof assert.AssertionError ? error.message : 'fuzz campaign could not complete';
  }
  report.finished_at = new Date().toISOString();
  save(reportPath, report);
  save(join(run, 'report.json'), report);
  return { report, log };
}

function expectedCanaryFailure(report: Record<string, unknown>, log: string) {
  const execution = report.execution as Execution | undefined;
  if (report.status !== 'failed' || !execution) return false;
  if ((execution.exit_code ?? 0) <= 0 || execution.timed_out || execution.interrupted) return false;
  return (
    log.includes('mikaki fuzz harness canary v1') && log.includes('ERROR: libFuzzer: deadly signal')
  );
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(realpathSync(resolve(process.argv[1]))).href
) {
  try {
    const selfTest = process.argv[2] === 'self-test';
    const { report, log } = await campaign(
      selfTest ? 'harness_canary' : process.argv[2],
      selfTest ? '1' : process.argv[3],
      { canary: selfTest },
    );
    const detected = selfTest && expectedCanaryFailure(report, log);
    console.log(
      JSON.stringify({
        target: report.target,
        status: report.status,
        canary_detected: detected,
        execution_id: report.execution_id,
      }),
    );
    if (selfTest ? !detected : report.status !== 'passed') process.exitCode = 1;
  } catch {
    console.error(
      'Fuzz campaign rejected: expected a known target and 1..1800 seconds, or self-test',
    );
    process.exitCode = 1;
  }
}
