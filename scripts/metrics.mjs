#!/usr/bin/env node
// Project size, test-code, native Rust coverage, and direct dependency tracker.
// No third-party packages are needed; snapshots and SVG charts are CI artifacts.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync, appendFileSync } from 'node:fs';
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
  return execFileSync(command, argv, { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
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
  return /(^|\/)(test|tests)\//.test(path) || /(?:^|\/)(?:tests?|test)\.rs$/.test(path) || /\.(?:test|spec)\.(?:[cm]?[jt]sx?|svelte)$/.test(path);
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
      if (/^#\[cfg\(test\)\]/.test(t)) { pending = true; continue; }
      if (!pending) continue;
      if (!t || t.startsWith('//') || t.startsWith('#[')) continue;
      if (/^(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+/.test(t)) {
        inside = true;
        pending = false;
        count++;
        for (const ch of line) { if (ch === '{') depth++; else if (ch === '}') depth--; }
        if (depth <= 0) inside = false;
      } else pending = false;
    } else {
      count++;
      for (const ch of line) { if (ch === '{') depth++; else if (ch === '}') depth--; }
      if (depth <= 0) { inside = false; depth = 0; }
    }
  }
  return count;
}

function codeSize() {
  const result = { implementationLines: 0, testLines: 0, implementationFiles: 0, testFiles: 0, byLanguage: {} };
  for (const path of trackedFiles()) {
    if (!/^(crates|local)\//.test(path) || GENERATED.some((re) => re.test(path))) continue;
    const ext = extname(path).toLowerCase();
    if (!CODE_EXT.has(ext)) continue;
    let text;
    try { text = readFileSync(join(ROOT, path), 'utf8'); } catch { continue; }
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
    const lang = rust ? 'rust' : ['.ts', '.tsx'].includes(ext) ? 'typescript' : ext === '.svelte' ? 'svelte' : 'javascript';
    result.byLanguage[lang] ??= { implementationLines: 0, testLines: 0 };
    if (testFile) result.byLanguage[lang].testLines += count;
    else result.byLanguage[lang].implementationLines += count;
    if (rust && !testFile) result.byLanguage[lang].testLines += 0;
    // Inline Rust test lines are assigned to Rust tests above.
    if (rust && !testFile) result.byLanguage[lang].testLines += inlineRustTestLines(text);
  }
  return result;
}

function dependencies() {
  const npm = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const npmRuntime = Object.keys(npm.dependencies ?? {}).length;
  const npmDev = Object.keys(npm.devDependencies ?? {}).length;
  const metadata = JSON.parse(run('cargo', ['metadata', '--format-version', '1', '--no-deps']));
  const workspaceNames = new Set(metadata.packages.map((p) => p.name));
  const rust = { runtime: new Set(), build: new Set(), dev: new Set() };
  for (const pkg of metadata.packages) {
    for (const dep of pkg.dependencies) {
      if (workspaceNames.has(dep.name) || !dep.source) continue;
      const kind = dep.kind ?? 'runtime';
      if (kind === 'dev') rust.dev.add(dep.name);
      else if (kind === 'build') rust.build.add(dep.name);
      else rust.runtime.add(dep.name);
    }
  }
  return {
    npm: { runtime: npmRuntime, dev: npmDev },
    rust: { runtime: rust.runtime.size, build: rust.build.size, dev: rust.dev.size },
    names: {
      npmRuntime: Object.keys(npm.dependencies ?? {}).sort(),
      npmDev: Object.keys(npm.devDependencies ?? {}).sort(),
      rustRuntime: [...rust.runtime].sort(), rustBuild: [...rust.build].sort(), rustDev: [...rust.dev].sort(),
    },
  };
}

function coverage() {
  if (!existsSync(join(ROOT, coveragePath))) return null;
  const doc = JSON.parse(readFileSync(join(ROOT, coveragePath), 'utf8'));
  const totals = doc.data?.[0]?.totals;
  if (!totals) return null;
  return {
    lines: { covered: totals.lines.covered, count: totals.lines.count, percent: totals.lines.percent },
    regions: { covered: totals.regions.covered, count: totals.regions.count, percent: totals.regions.percent },
    functions: { covered: totals.functions.covered, count: totals.functions.count, percent: totals.functions.percent },
  };
}

function snapshot() {
  let commit = 'working-tree';
  try { commit = run('git', ['rev-parse', '--short', 'HEAD']); } catch { /* local source archive */ }
  return { date: new Date().toISOString().slice(0, 10), commit, code: codeSize(), dependencies: dependencies(), coverage: coverage() };
}

const esc = (s) => String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
function svgFrame(title, subtitle, body) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="900" height="390" viewBox="0 0 900 390"><rect width="100%" height="100%" fill="#fff"/><text x="56" y="42" font-family="system-ui,sans-serif" font-size="22" font-weight="700" fill="#172033">${esc(title)}</text><text x="56" y="67" font-family="system-ui,sans-serif" font-size="12" fill="#667085">${esc(subtitle)}</text>${body}</svg>\n`;
}
const COLORS = { implementation: '#2563eb', tests: '#f59e0b', rust: '#2563eb', npm: '#f59e0b', dev: '#94a3b8', build: '#8b5cf6' };
function axes(max, suffix = '') {
  const xs = [70, 860]; const ys = [105, 310];
  let out = `<path d="M${xs[0]} ${ys[0]}V${ys[1]}H${xs[1]}" fill="none" stroke="#98a2b3"/>`;
  for (let i = 0; i <= 4; i++) {
    const y = ys[1] - (ys[1] - ys[0]) * i / 4;
    const v = Math.round(max * i / 4);
    out += `<path d="M${xs[0]} ${y}H${xs[1]}" stroke="#eaecf0"/><text x="60" y="${y + 4}" text-anchor="end" font-family="system-ui,sans-serif" font-size="11" fill="#667085">${v}${suffix}</text>`;
  }
  return out;
}
function xAt(i, n) { return n <= 1 ? 465 : 80 + i * 770 / (n - 1); }
function codeChart(history) {
  const rows = history.slice(-60); const max = Math.max(1, ...rows.map((x) => x.code.implementationLines + x.code.testLines));
  let body = axes(max);
  rows.forEach((x, i) => {
    const x0 = xAt(i, rows.length), bw = Math.max(4, Math.min(28, 700 / Math.max(rows.length, 1)));
    const hImpl = 205 * x.code.implementationLines / max, hTest = 205 * x.code.testLines / max;
    body += `<rect x="${x0 - bw / 2}" y="${310 - hImpl}" width="${bw}" height="${hImpl}" fill="${COLORS.implementation}"/><rect x="${x0 - bw / 2}" y="${310 - hImpl - hTest}" width="${bw}" height="${hTest}" fill="${COLORS.tests}"/>`;
    if (i === 0 || i === rows.length - 1 || (rows.length < 12)) body += `<text x="${x0}" y="330" text-anchor="middle" font-family="system-ui,sans-serif" font-size="10" fill="#667085">${esc(x.date)}</text>`;
  });
  body += `<rect x="650" y="355" width="12" height="12" fill="${COLORS.implementation}"/><text x="668" y="366" font-family="system-ui,sans-serif" font-size="12" fill="#344054">implementation</text><rect x="790" y="355" width="12" height="12" fill="${COLORS.tests}"/><text x="808" y="366" font-family="system-ui,sans-serif" font-size="12" fill="#344054">tests</text>`;
  return svgFrame('Codebase size', 'Handwritten Rust / JavaScript / TypeScript / Svelte in crates/ and local/; physical lines', body);
}
function lineChart(title, subtitle, history, series, max, suffix = '') {
  const rows = history.slice(-60); let body = axes(max, suffix);
  series.forEach((s, si) => {
    const points = rows.map((row, i) => {
      const value = s.value(row);
      return value == null ? null : `${xAt(i, rows.length)},${310 - 205 * value / max}`;
    }).filter(Boolean);
    if (points.length) body += `<polyline points="${points.join(' ')}" fill="none" stroke="${s.color}" stroke-width="3"/>`;
    rows.forEach((row, i) => { const v = s.value(row); if (v != null) body += `<circle cx="${xAt(i, rows.length)}" cy="${310 - 205 * v / max}" r="3.5" fill="${s.color}"/>`; });
    body += `<rect x="${70 + si * 205}" y="355" width="12" height="12" fill="${s.color}"/><text x="88" y="366" font-family="system-ui,sans-serif" font-size="12" fill="#344054">${esc(s.label)}</text>`;
  });
  rows.forEach((x, i) => { if (i === 0 || i === rows.length - 1 || rows.length < 12) body += `<text x="${xAt(i, rows.length)}" y="330" text-anchor="middle" font-family="system-ui,sans-serif" font-size="10" fill="#667085">${esc(x.date)}</text>`; });
  return svgFrame(title, subtitle, body);
}
function dependencyChart(history) {
  const rows = history.slice(-60); const max = Math.max(1, ...rows.map((r) => r.dependencies.npm.runtime + r.dependencies.rust.runtime));
  let body = axes(max);
  rows.forEach((r, i) => {
    const x0 = xAt(i, rows.length), bw = Math.max(4, Math.min(28, 700 / Math.max(rows.length, 1)));
    const a = 205 * r.dependencies.rust.runtime / max, b = 205 * r.dependencies.npm.runtime / max;
    body += `<rect x="${x0 - bw / 2}" y="${310 - a}" width="${bw}" height="${a}" fill="${COLORS.rust}"/><rect x="${x0 - bw / 2}" y="${310 - a - b}" width="${bw}" height="${b}" fill="${COLORS.npm}"/>`;
    const dev = r.dependencies.rust.dev + r.dependencies.npm.dev, build = r.dependencies.rust.build;
    body += `<circle cx="${x0}" cy="${310 - (a + b)}" r="${Math.max(2, Math.min(8, dev / 2))}" fill="${COLORS.dev}" stroke="#fff" stroke-width="1"/>`;
    if (i === 0 || i === rows.length - 1 || rows.length < 12) body += `<text x="${x0}" y="330" text-anchor="middle" font-family="system-ui,sans-serif" font-size="10" fill="#667085">${esc(r.date)}</text>`;
    if (build > 0 && i === rows.length - 1) body += `<text x="${x0 + 6}" y="${305 - a - b}" font-family="system-ui,sans-serif" font-size="10" fill="#6b4eff">build ${build}</text>`;
  });
  body += `<rect x="500" y="355" width="12" height="12" fill="${COLORS.rust}"/><text x="518" y="366" font-family="system-ui,sans-serif" font-size="12" fill="#344054">Rust runtime</text><rect x="620" y="355" width="12" height="12" fill="${COLORS.npm}"/><text x="638" y="366" font-family="system-ui,sans-serif" font-size="12" fill="#344054">npm runtime</text><circle cx="780" cy="361" r="6" fill="${COLORS.dev}"/><text x="792" y="366" font-family="system-ui,sans-serif" font-size="12" fill="#344054">dev deps (size = count)</text>`;
  return svgFrame('Direct dependencies', 'Unique direct dependency names; runtime stack, dev dependency bubble, build count annotation', body);
}

function readHistory() {
  try { return JSON.parse(readFileSync(HISTORY, 'utf8')); } catch { return []; }
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
    '# Direct dependency inventory', '',
    `Snapshot: \`${current.date}\` / commit \`${current.commit}\``, '',
    '| Scope | Count | Direct dependencies |', '|---|---:|---|',
    ...depGroups.map(([name, names]) => `| ${name} | ${names.length} | ${names.length ? names.map((x) => `\`${x}\``).join(', ') : '—'} |`),
    '', 'Cargo and npm transitive dependencies are not included.', '',
  ].join('\n');
  writeFileSync(join(ROOT, outputDir, 'dependency-inventory.md'), depMarkdown);
  writeFileSync(join(ROOT, outputDir, 'code-size.svg'), codeChart(history));
  writeFileSync(join(ROOT, outputDir, 'coverage.svg'), lineChart('Native Rust coverage', 'cargo llvm-cov: workspace excluding sakimori-worker; tests.rs ignored; inline tests remain instrumented', history, [
    { label: 'lines', color: '#2563eb', value: (r) => r.coverage?.lines.percent },
    { label: 'regions', color: '#f59e0b', value: (r) => r.coverage?.regions.percent },
  ], 100, '%'));
  writeFileSync(join(ROOT, outputDir, 'dependencies.svg'), dependencyChart(history));
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    const c = current.code, cov = current.coverage;
    const markdown = [
      '## Project metrics', '',
      '| Metric | Current |', '|---|---:|',
      `| Implementation | ${c.implementationLines.toLocaleString()} lines |`,
      `| Tests | ${c.testLines.toLocaleString()} lines |`,
      `| Native Rust line coverage | ${cov ? `${cov.lines.percent.toFixed(1)}% (${cov.lines.covered}/${cov.lines.count})` : 'unavailable'} |`,
      `| Native Rust region coverage | ${cov ? `${cov.regions.percent.toFixed(1)}% (${cov.regions.covered}/${cov.regions.count})` : 'unavailable'} |`,
      `| Declared runtime direct dependencies | Rust ${current.dependencies.rust.runtime}, npm ${current.dependencies.npm.runtime} |`,
      `| Development direct dependencies | Rust ${current.dependencies.rust.dev}, build ${current.dependencies.rust.build}, npm ${current.dependencies.npm.dev} |`,
      '', '| Language | Implementation | Tests |', '|---|---:|---:|',
      ...Object.entries(c.byLanguage).map(([lang, sizes]) => `| ${lang} | ${sizes.implementationLines.toLocaleString()} | ${sizes.testLines.toLocaleString()} |`),
      '', `Declared Rust runtime dependencies: ${current.dependencies.names.rustRuntime.map((x) => `\`${x}\``).join(', ') || '—'}`,
      `Declared npm runtime dependencies: ${current.dependencies.names.npmRuntime.map((x) => `\`${x}\``).join(', ') || '—'}`,
      '', 'Code size, coverage, and dependency trend charts plus the full dependency inventory are in the `authentication-measurements` artifact.', '',
    ].join('\n');
    appendFileSync(summaryPath, markdown);
  }
}

const current = snapshot();
let history = readHistory();
if (persist) {
  if (history.at(-1)?.commit === current.commit) history[history.length - 1] = current;
  else history.push(current);
  mkdirSync(dirname(HISTORY), { recursive: true });
  writeFileSync(HISTORY, JSON.stringify(history, null, 2) + '\n');
}
const chartHistory = [...history];
if (!persist) {
  if (chartHistory.at(-1)?.commit === current.commit) chartHistory[chartHistory.length - 1] = current;
  else chartHistory.push(current);
}
writeReports(current, chartHistory);
if (persist) {
  for (const file of ['code-size.svg', 'coverage.svg', 'dependencies.svg', 'dependency-inventory.md']) {
    copyFileSync(join(ROOT, outputDir, file), join(ROOT, 'metrics', file));
  }
}
const c = current.code;
console.log(`Code: ${c.implementationLines} implementation + ${c.testLines} test lines`);
console.log(`Coverage: ${current.coverage ? `${current.coverage.lines.percent.toFixed(1)}% lines / ${current.coverage.regions.percent.toFixed(1)}% regions` : 'not available'}`);
console.log(`Dependencies: ${current.dependencies.rust.runtime} Rust + ${current.dependencies.npm.runtime} npm runtime; ${current.dependencies.rust.dev + current.dependencies.npm.dev} dev`);
