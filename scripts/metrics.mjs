#!/usr/bin/env node
// Project size, test-code, native Rust coverage, and direct dependency tracker.
// No third-party packages are needed; snapshots and SVG charts are CI artifacts.
import { execFileSync } from 'node:child_process';
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  copyFileSync,
  appendFileSync,
  readdirSync,
} from 'node:fs';
import { dirname, extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const value = (name, fallback) => {
  const i = args.indexOf(name);
  return i < 0 ? fallback : args[i + 1];
};
const outputDir = value('--output-dir', 'artifacts/metrics');
const coveragePath = value('--coverage', 'artifacts/native-coverage.json');
const snapshotPath = value('--snapshot-file', null);
const persist = args.includes('--record');
const HISTORY = join(ROOT, 'metrics', 'history.json');
const CODE_EXT = new Set(['.rs', '.js', '.mjs', '.ts', '.tsx', '.jsx', '.svelte']);
const GENERATED = [
  /(^|\/)target\//,
  /(^|\/)pkg\//,
  /(^|\/)dist\//,
  /^local\/generated\//,
  /^local\/conformance\//,
  /(^|\/)examples\//,
  /^design\/probes\//,
];

function run(command, argv) {
  return execFileSync(command, argv, {
    cwd: ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
}
function trackedFiles() {
  return run('git', ['ls-files', '-co', '--exclude-standard']).split('\n').filter(Boolean);
}
function lines(text) {
  if (!text) return 0;
  const count = text.split('\n').length;
  return text.endsWith('\n') ? count - 1 : count;
}
function isTestFile(path) {
  return (
    /(^|\/)(test|tests)\//.test(path) ||
    /(?:^|\/)(?:tests?|test)\.rs$/.test(path) ||
    /\.(?:test|spec)\.(?:[cm]?[jt]sx?|svelte)$/.test(path)
  );
}

// Count inline Rust #[cfg(test)] modules separately for a useful implementation/test stack.
function inlineRustTestLines(text) {
  const source = text.split('\n');
  let count = 0;
  let pending = false;
  let depth = 0;
  let inside = false;
  for (const line of source) {
    const t = line.trim();
    if (!inside) {
      if (/^#\[cfg\(test\)\]/.test(t)) {
        pending = true;
        continue;
      }
      if (!pending) continue;
      if (!t || t.startsWith('//') || t.startsWith('#[')) continue;
      if (/^(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+/.test(t)) {
        inside = true;
        pending = false;
        count++;
        for (const ch of line) {
          if (ch === '{') depth++;
          else if (ch === '}') depth--;
        }
        if (depth <= 0) inside = false;
      } else pending = false;
    } else {
      count++;
      for (const ch of line) {
        if (ch === '{') depth++;
        else if (ch === '}') depth--;
      }
      if (depth <= 0) {
        inside = false;
        depth = 0;
      }
    }
  }
  return count;
}

function codeSize() {
  const result = {
    implementationLines: 0,
    testLines: 0,
    implementationFiles: 0,
    testFiles: 0,
    byLanguage: {},
  };
  for (const path of trackedFiles()) {
    if (!/^(crates|local)\//.test(path) || GENERATED.some((re) => re.test(path))) continue;
    const ext = extname(path).toLowerCase();
    if (!CODE_EXT.has(ext)) continue;
    let text;
    try {
      text = readFileSync(join(ROOT, path), 'utf8');
    } catch {
      continue;
    }
    let count = lines(text);
    const rust = ext === '.rs';
    const testFile = isTestFile(path);
    if (rust && !testFile) {
      const inline = inlineRustTestLines(text);
      result.testLines += inline;
      count -= inline;
    }
    if (testFile) {
      result.testLines += count;
      result.testFiles++;
    } else {
      result.implementationLines += count;
      result.implementationFiles++;
    }
    const lang = rust
      ? 'rust'
      : ['.ts', '.tsx'].includes(ext)
        ? 'typescript'
        : ext === '.svelte'
          ? 'svelte'
          : 'javascript';
    result.byLanguage[lang] ??= { implementationLines: 0, testLines: 0 };
    if (testFile) result.byLanguage[lang].testLines += count;
    else result.byLanguage[lang].implementationLines += count;
    // Inline Rust test lines are assigned to Rust tests above.
    if (rust && !testFile) result.byLanguage[lang].testLines += inlineRustTestLines(text);
  }
  return result;
}

function countSourceLines(dir, extensions, skipNestedModules = false) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return 0;
  }
  let total = 0;
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (skipNestedModules && entry.name === 'node_modules') continue;
      total += countSourceLines(join(dir, entry.name), extensions, skipNestedModules);
    } else if (entry.isFile() && extensions.has(extname(entry.name).toLowerCase())) {
      try {
        const text = readFileSync(join(dir, entry.name), 'utf8');
        total += extensions.has('.rs')
          ? Math.max(0, lines(text) - inlineRustTestLines(text))
          : lines(text);
      } catch {
        /* unreadable package file */
      }
    }
  }
  return total;
}

function dependencies() {
  const npm = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const lock = JSON.parse(readFileSync(join(ROOT, 'package-lock.json'), 'utf8'));
  const npmRuntimeNames = Object.keys(npm.dependencies ?? {}).sort();
  const npmDevNames = Object.keys(npm.devDependencies ?? {}).sort();
  let npmRuntimeLines = 0;
  let npmRuntimePackages = 0;
  for (const [path, info] of Object.entries(lock.packages ?? {})) {
    if (!path.startsWith('node_modules/') || info.dev === true) continue;
    const count = countSourceLines(join(ROOT, path), new Set(['.js', '.mjs', '.cjs']), true);
    if (count > 0) {
      npmRuntimeLines += count;
      npmRuntimePackages++;
    }
  }

  const metadata = JSON.parse(
    run('cargo', [
      'metadata',
      '--format-version',
      '1',
      '--filter-platform',
      'wasm32-unknown-unknown',
    ]),
  );
  const workspacePackages = metadata.packages.filter((p) =>
    metadata.workspace_members.includes(p.id),
  );
  const workspaceNames = new Set(workspacePackages.map((p) => p.name));
  const rust = { runtime: new Set(), build: new Set(), dev: new Set() };
  for (const pkg of workspacePackages) {
    for (const dep of pkg.dependencies) {
      if (workspaceNames.has(dep.name) || !dep.source) continue;
      const kind = dep.kind ?? 'runtime';
      if (kind === 'dev') rust.dev.add(dep.name);
      else if (kind === 'build') rust.build.add(dep.name);
      else rust.runtime.add(dep.name);
    }
  }

  const packagesById = new Map(metadata.packages.map((pkg) => [pkg.id, pkg]));
  const nodesById = new Map((metadata.resolve?.nodes ?? []).map((node) => [node.id, node]));
  const visited = new Set();
  const pending = [...metadata.workspace_members];
  while (pending.length) {
    const id = pending.pop();
    if (visited.has(id)) continue;
    visited.add(id);
    for (const dep of nodesById.get(id)?.deps ?? []) {
      if (dep.dep_kinds.some((kind) => kind.kind == null || kind.kind === 'normal'))
        pending.push(dep.pkg);
    }
  }
  let rustRuntimeLines = 0;
  let rustRuntimePackages = 0;
  for (const id of visited) {
    const pkg = packagesById.get(id);
    if (!pkg?.source || workspaceNames.has(pkg.name)) continue;
    const srcDir = join(dirname(pkg.manifest_path), 'src');
    const count = countSourceLines(srcDir, new Set(['.rs']));
    if (count > 0) {
      rustRuntimeLines += count;
      rustRuntimePackages++;
    }
  }

  return {
    npm: { runtime: npmRuntimeNames.length, dev: npmDevNames.length },
    rust: { runtime: rust.runtime.size, build: rust.build.size, dev: rust.dev.size },
    sourceLines: {
      npmRuntime: npmRuntimeLines,
      rustRuntime: rustRuntimeLines,
      total: npmRuntimeLines + rustRuntimeLines,
    },
    sourcePackages: { npmRuntime: npmRuntimePackages, rustRuntime: rustRuntimePackages },
    names: {
      npmRuntime: npmRuntimeNames,
      npmDev: npmDevNames,
      rustRuntime: [...rust.runtime].sort(),
      rustBuild: [...rust.build].sort(),
      rustDev: [...rust.dev].sort(),
    },
  };
}

function coverage() {
  if (!existsSync(join(ROOT, coveragePath))) return null;
  const doc = JSON.parse(readFileSync(join(ROOT, coveragePath), 'utf8'));
  const totals = doc.data?.[0]?.totals;
  if (!totals) return null;
  return {
    lines: {
      covered: totals.lines.covered,
      count: totals.lines.count,
      percent: totals.lines.percent,
    },
    regions: {
      covered: totals.regions.covered,
      count: totals.regions.count,
      percent: totals.regions.percent,
    },
    functions: {
      covered: totals.functions.covered,
      count: totals.functions.count,
      percent: totals.functions.percent,
    },
  };
}

function snapshot() {
  if (snapshotPath) return JSON.parse(readFileSync(join(ROOT, snapshotPath), 'utf8'));
  let commit = 'working-tree';
  try {
    commit = run('git', ['rev-parse', '--short', 'HEAD']);
  } catch {
    /* local source archive */
  }
  return {
    date: new Date().toISOString().slice(0, 10),
    commit,
    code: codeSize(),
    dependencies: dependencies(),
    coverage: coverage(),
  };
}

const esc = (s) =>
  String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const COLORS = { rust: '#e57038', frontend: '#8657a6', tests: '#28a176' };
const FILLS = { rust: '#e5703833', frontend: '#8657a633', tests: '#28a17633' };
function fmtK(value) {
  return value >= 1000 ? `${Math.floor(value / 1000)}k` : String(value);
}
function xPosition(date, start, end, left, width) {
  const span = Math.max(1, Date.parse(end) - Date.parse(start));
  return left + ((Date.parse(date) - Date.parse(start)) / span) * width;
}
function yTicks(max) {
  const rough = max / 5;
  const magnitude = 10 ** Math.floor(Math.log10(Math.max(rough, 1)));
  const normalized = rough / magnitude;
  const step = (normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10) * magnitude;
  const ticks = [];
  for (let tick = 0; tick <= max + step / 10; tick += step) ticks.push(tick);
  return { step, ticks };
}
function stackValues(row) {
  const language = row.code.byLanguage;
  return [
    language.rust?.implementationLines ?? 0,
    (language.javascript?.implementationLines ?? 0) +
      (language.typescript?.implementationLines ?? 0) +
      (language.svelte?.implementationLines ?? 0),
    row.code.testLines,
  ];
}
function stackedGrowthChart(history) {
  const rows = history.slice(-90);
  const W = 900,
    H = 390,
    left = 76,
    right = 150,
    top = 91,
    bottom = 324;
  const plotW = W - left - right,
    plotH = bottom - top;
  const stacks = rows.map(stackValues);
  const totals = stacks.map((values) => values.reduce((sum, v) => sum + v, 0));
  const max = Math.max(1, ...totals);
  const { ticks } = yTicks(max * 1.08);
  const yMax = ticks.at(-1) || max;
  const start = rows[0]?.date ?? new Date().toISOString().slice(0, 10);
  const end = rows.at(-1)?.date ?? start;
  const xp = (date) =>
    rows.length <= 1 ? left + plotW / 2 : xPosition(date, start, end, left, plotW);
  const yp = (value) => bottom - (value / yMax) * plotH;
  let body = '';
  for (const tick of ticks) {
    const y = yp(tick);
    body += `<path d="M${left} ${y}H${W - right}" stroke="#e5e7eb"/><text x="${left - 10}" y="${y + 4}" text-anchor="end" font-family="system-ui,sans-serif" font-size="11" fill="#667085">${fmtK(tick)}</text>`;
  }
  const colors = [COLORS.rust, COLORS.frontend, COLORS.tests];
  const fills = [FILLS.rust, FILLS.frontend, FILLS.tests];
  // Keep the chart focused on code maintained in this repository.
  for (let layer = 0; layer < 3; layer++) {
    const lower = rows.map((_, i) => stacks[i].slice(0, layer).reduce((sum, v) => sum + v, 0));
    const upper = rows.map((_, i) => lower[i] + stacks[i][layer]);
    if (!rows.length) continue;
    const upperPath = rows
      .map((row, i) => `${i ? 'L' : 'M'}${xp(row.date).toFixed(1)},${yp(upper[i]).toFixed(1)}`)
      .join(' ');
    const lowerPath = [...rows]
      .reverse()
      .map((row, ri) => {
        const i = rows.length - 1 - ri;
        return `L${xp(row.date).toFixed(1)},${yp(lower[i]).toFixed(1)}`;
      })
      .join(' ');
    body += `<path d="${upperPath} ${lowerPath} Z" fill="${fills[layer]}"/><path d="${rows.map((row, i) => `${i ? 'L' : 'M'}${xp(row.date).toFixed(1)},${yp(upper[i]).toFixed(1)}`).join(' ')}" fill="none" stroke="${colors[layer]}" stroke-width="1.4"/>`;
  }
  if (rows.length === 1) {
    let baseline = bottom;
    stacks[0].forEach((value, i) => {
      const height = (value / yMax) * plotH;
      body += `<rect x="${xp(rows[0].date) - 6}" y="${baseline - height}" width="12" height="${height}" fill="${colors[i]}"/>`;
      baseline -= height;
    });
  }
  body += `<path d="M${left} ${top}V${bottom}H${W - right}" fill="none" stroke="#98a2b3"/>`;
  const labelIndexes =
    rows.length <= 8
      ? rows.map((_, i) => i)
      : [
          ...new Set([
            0,
            Math.floor((rows.length - 1) / 3),
            Math.floor(((rows.length - 1) * 2) / 3),
            rows.length - 1,
          ]),
        ];
  for (const i of labelIndexes) {
    const x = xp(rows[i].date);
    body += `<text x="${x}" y="${bottom + 20}" text-anchor="middle" font-family="system-ui,sans-serif" font-size="10" fill="#667085">${esc(rows[i].date)}</text>`;
  }
  body += `<text x="${left}" y="42" font-family="system-ui,sans-serif" font-size="20" font-weight="700" fill="#172033">Codebase growth</text><text x="${left}" y="64" font-family="system-ui,sans-serif" font-size="12" fill="#667085">Physical source lines · daily snapshots · latest 90 days</text>`;
  const legend = [
    {
      name: 'Rust impl',
      color: COLORS.rust,
      value: rows.at(-1)?.code.byLanguage.rust?.implementationLines ?? 0,
    },
    {
      name: 'JS / TS impl',
      color: COLORS.frontend,
      value:
        (rows.at(-1)?.code.byLanguage.javascript?.implementationLines ?? 0) +
        (rows.at(-1)?.code.byLanguage.typescript?.implementationLines ?? 0) +
        (rows.at(-1)?.code.byLanguage.svelte?.implementationLines ?? 0),
    },
    { name: 'tests', color: COLORS.tests, value: rows.at(-1)?.code.testLines ?? 0 },
  ];
  legend.forEach((item, i) => {
    const y = 112 + i * 29;
    body += `<rect x="${W - right + 15}" y="${y - 9}" width="12" height="12" fill="${item.color}"/><text x="${W - right + 35}" y="${y + 1}" font-family="system-ui,sans-serif" font-size="10" fill="#344054">${item.name}</text><text x="${W - 9}" y="${y + 1}" text-anchor="end" font-family="system-ui,sans-serif" font-size="10" fill="#172033">${item.value.toLocaleString()}</text>`;
  });
  if (rows.length) {
    const last = rows.at(-1),
      latestTotal = totals.at(-1);
    body += `<text x="${W - right + 15}" y="280" font-family="system-ui,sans-serif" font-size="11" fill="#667085">Today</text><text x="${W - right + 15}" y="299" font-family="system-ui,sans-serif" font-size="15" font-weight="700" fill="#172033">${fmtK(latestTotal)} lines</text><text x="${W - right + 15}" y="316" font-family="system-ui,sans-serif" font-size="10" fill="#667085">${esc(last.commit)}</text>`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><rect width="100%" height="100%" fill="#fff"/>${body}</svg>\n`;
}
function lineChart(title, subtitle, history, series, max, suffix = '') {
  const rows = history.slice(-90);
  const W = 900,
    H = 390,
    left = 76,
    right = 80,
    top = 91,
    bottom = 324;
  const plotW = W - left - right,
    plotH = bottom - top;
  const start = rows[0]?.date ?? new Date().toISOString().slice(0, 10),
    end = rows.at(-1)?.date ?? start;
  const xp = (date) =>
    rows.length <= 1 ? left + plotW / 2 : xPosition(date, start, end, left, plotW);
  const yp = (value) => bottom - (value / max) * plotH;
  let body = '';
  for (let i = 0; i <= 4; i++) {
    const value = (max * i) / 4,
      y = yp(value);
    body += `<path d="M${left} ${y}H${W - right}" stroke="#e5e7eb"/><text x="${left - 10}" y="${y + 4}" text-anchor="end" font-family="system-ui,sans-serif" font-size="11" fill="#667085">${value.toFixed(max === 100 ? 0 : 1)}${suffix}</text>`;
  }
  series.forEach((item) => {
    const points = rows
      .map((row) => ({ x: xp(row.date), y: yp(item.value(row)) }))
      .filter((p) => Number.isFinite(p.y));
    if (points.length) {
      body += `<path d="${points.map((p, i) => `${i ? 'L' : 'M'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')}" fill="none" stroke="${item.color}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>`;
      for (const p of points)
        body += `<circle cx="${p.x}" cy="${p.y}" r="3.5" fill="${item.color}"/>`;
    }
  });
  if (!series.some((item) => rows.some((row) => Number.isFinite(item.value(row))))) {
    body += `<text x="${left + plotW / 2}" y="${top + plotH / 2}" text-anchor="middle" font-family="system-ui,sans-serif" font-size="13" fill="#667085">No successful native coverage snapshot recorded yet</text>`;
  }
  body += `<path d="M${left} ${top}V${bottom}H${W - right}" fill="none" stroke="#98a2b3"/>`;
  const labelIndexes =
    rows.length <= 8
      ? rows.map((_, i) => i)
      : [
          ...new Set([
            0,
            Math.floor((rows.length - 1) / 3),
            Math.floor(((rows.length - 1) * 2) / 3),
            rows.length - 1,
          ]),
        ];
  for (const i of labelIndexes)
    body += `<text x="${xp(rows[i].date)}" y="${bottom + 20}" text-anchor="middle" font-family="system-ui,sans-serif" font-size="10" fill="#667085">${esc(rows[i].date)}</text>`;
  body += `<text x="${left}" y="42" font-family="system-ui,sans-serif" font-size="20" font-weight="700" fill="#172033">${esc(title)}</text><text x="${left}" y="64" font-family="system-ui,sans-serif" font-size="12" fill="#667085">${esc(subtitle)}</text>`;
  series.forEach((item, i) => {
    const x = left + i * 170;
    body += `<path d="M${x} 366h18" stroke="${item.color}" stroke-width="3"/><text x="${x + 24}" y="370" font-family="system-ui,sans-serif" font-size="11" fill="#344054">${esc(item.label)}</text>`;
  });
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><rect width="100%" height="100%" fill="#fff"/>${body}</svg>\n`;
}

function readHistory() {
  try {
    return JSON.parse(readFileSync(HISTORY, 'utf8'));
  } catch {
    return [];
  }
}
function writeReports(current, history) {
  mkdirSync(join(ROOT, outputDir), { recursive: true });
  writeFileSync(join(ROOT, outputDir, 'current.json'), JSON.stringify(current, null, 2) + '\n');
  const depGroups = [
    ['Rust runtime', current.dependencies.names.rustRuntime],
    ['Rust build', current.dependencies.names.rustBuild],
    ['Rust development', current.dependencies.names.rustDev],
    ['npm runtime', current.dependencies.names.npmRuntime],
    ['npm development', current.dependencies.names.npmDev],
  ];
  const depMarkdown = [
    '# Direct dependency inventory',
    '',
    `Snapshot: \`${current.date}\` / commit \`${current.commit}\``,
    '',
    `Runtime dependency source: ${current.dependencies.sourceLines.total.toLocaleString()} lines total ` +
      `(${current.dependencies.sourceLines.npmRuntime.toLocaleString()} npm, ${current.dependencies.sourceLines.rustRuntime.toLocaleString()} Rust; ` +
      `${current.dependencies.sourcePackages.npmRuntime} npm packages, ${current.dependencies.sourcePackages.rustRuntime} Rust crates in the resolved runtime graph).`,
    '',
    '| Scope | Count | Direct dependencies |',
    '|---|---:|---|',
    ...depGroups.map(
      ([name, names]) =>
        `| ${name} | ${names.length} | ${names.length ? names.map((x) => `\`${x}\``).join(', ') : '—'} |`,
    ),
    '',
    'The inventory lists direct manifest dependencies; the source-line total includes transitive packages resolved for the runtime.',
    '',
  ].join('\n');
  writeFileSync(join(ROOT, outputDir, 'dependency-inventory.md'), depMarkdown);
  writeFileSync(join(ROOT, outputDir, 'code-size.svg'), stackedGrowthChart(history));
  writeFileSync(
    join(ROOT, outputDir, 'coverage.svg'),
    lineChart(
      'Native Rust coverage',
      'cargo llvm-cov: workspace excluding mikaki-browser-wasm and mikaki-worker; tests.rs ignored; inline tests remain instrumented',
      history,
      [
        { label: 'lines', color: '#2563eb', value: (r) => r.coverage?.lines.percent },
        { label: 'regions', color: '#f59e0b', value: (r) => r.coverage?.regions.percent },
      ],
      100,
      '%',
    ),
  );
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    const c = current.code,
      cov = current.coverage;
    const markdown = [
      '## Project metrics',
      '',
      '| Metric | Current |',
      '|---|---:|',
      `| Implementation | ${c.implementationLines.toLocaleString()} lines |`,
      `| Tests | ${c.testLines.toLocaleString()} lines |`,
      `| Native Rust line coverage | ${cov ? `${cov.lines.percent.toFixed(1)}% (${cov.lines.covered}/${cov.lines.count})` : 'unavailable'} |`,
      `| Native Rust region coverage | ${cov ? `${cov.regions.percent.toFixed(1)}% (${cov.regions.covered}/${cov.regions.count})` : 'unavailable'} |`,
      `| Declared runtime direct dependencies | Rust ${current.dependencies.rust.runtime}, npm ${current.dependencies.npm.runtime} |`,
      `| Runtime dependency source | ${current.dependencies.sourceLines.total.toLocaleString()} lines (${current.dependencies.sourceLines.npmRuntime.toLocaleString()} npm + ${current.dependencies.sourceLines.rustRuntime.toLocaleString()} Rust) |`,
      `| Development direct dependencies | Rust ${current.dependencies.rust.dev}, build ${current.dependencies.rust.build}, npm ${current.dependencies.npm.dev} |`,
      '',
      '| Language | Implementation | Tests |',
      '|---|---:|---:|',
      ...Object.entries(c.byLanguage).map(
        ([lang, sizes]) =>
          `| ${lang} | ${sizes.implementationLines.toLocaleString()} | ${sizes.testLines.toLocaleString()} |`,
      ),
      '',
      `Declared Rust runtime dependencies: ${current.dependencies.names.rustRuntime.map((x) => `\`${x}\``).join(', ') || '—'}`,
      `Declared npm runtime dependencies: ${current.dependencies.names.npmRuntime.map((x) => `\`${x}\``).join(', ') || '—'}`,
      '',
      'Stacked project code growth, coverage trend, and dependency inventory are in the `authentication-measurements` artifact.',
      '',
    ].join('\n');
    appendFileSync(summaryPath, markdown);
  }
}

const current = snapshot();
let history = readHistory();
if (persist) {
  const todayIndex = history.findIndex((entry) => entry.date === current.date);
  if (todayIndex >= 0) history[todayIndex] = current;
  else history.push(current);
  history.sort((a, b) => a.date.localeCompare(b.date));
  mkdirSync(dirname(HISTORY), { recursive: true });
  writeFileSync(HISTORY, JSON.stringify(history, null, 2) + '\n');
}
const chartHistory = [...history];
if (!persist) {
  const todayIndex = chartHistory.findIndex((entry) => entry.date === current.date);
  if (todayIndex >= 0) chartHistory[todayIndex] = current;
  else chartHistory.push(current);
  chartHistory.sort((a, b) => a.date.localeCompare(b.date));
}
writeReports(current, chartHistory);
if (persist) {
  for (const file of ['code-size.svg', 'coverage.svg', 'dependency-inventory.md']) {
    copyFileSync(join(ROOT, outputDir, file), join(ROOT, 'metrics', file));
  }
}
const c = current.code;
console.log(`Code: ${c.implementationLines} implementation + ${c.testLines} test lines`);
console.log(
  `Coverage: ${current.coverage ? `${current.coverage.lines.percent.toFixed(1)}% lines / ${current.coverage.regions.percent.toFixed(1)}% regions` : 'not available'}`,
);
console.log(
  `Runtime dependency source: ${current.dependencies.sourceLines.total} lines (${current.dependencies.sourceLines.npmRuntime} npm + ${current.dependencies.sourceLines.rustRuntime} Rust)`,
);
