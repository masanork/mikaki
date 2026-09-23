import { readdir, readFile, mkdir, writeFile } from 'node:fs/promises';
import { gzipSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';

const root = new URL('../', import.meta.url);
const files = [];
async function walk(path) {
  for (const entry of await readdir(new URL(path, root), { withFileTypes: true })) {
    if (['node_modules', 'pkg', 'dist', '.wrangler', 'generated', 'target'].includes(entry.name))
      continue;
    const name = `${path}/${entry.name}`;
    if (entry.isDirectory()) await walk(name);
    else if (/\.(rs|mjs|ts|svelte|sql)$/.test(name)) files.push(name);
  }
}
await walk('crates');
await walk('local');
const counts = await Promise.all(
  files.map(async (path) => {
    const text = await readFile(new URL(path, root), 'utf8');
    return {
      path,
      lines: text.split('\n').filter((line) => line.trim()).length,
      bytes: Buffer.byteLength(text),
    };
  }),
);
async function size(path) {
  const data = await readFile(new URL(path, root));
  return { path, raw: data.length, gzip: gzipSync(data).length };
}
const bundles = [await size('crates/worker/pkg/sakimori_worker_bg.wasm')];
for (const name of await readdir(new URL('local/ui/dist/assets', root)))
  bundles.push(await size(`local/ui/dist/assets/${name}`));
const coverage = JSON.parse(await readFile(new URL('artifacts/native-coverage.json', root), 'utf8'))
  .data[0].totals;
const cargo = JSON.parse(
  execFileSync('cargo', ['metadata', '--format-version', '1', '--locked'], { encoding: 'utf8' }),
);
const npm = JSON.parse(await readFile(new URL('package-lock.json', root), 'utf8'));
const report = {
  schema_version: 1,
  commit: process.env.GITHUB_SHA ?? null,
  toolchain: {
    rust: execFileSync('rustc', ['--version'], { encoding: 'utf8' }).trim(),
    node: process.version,
  },
  measurement: 'nonblank physical lines; includes inline tests; generated files excluded',
  native_coverage_scope:
    'auth, oidc, webauthn; default features; separate tests.rs excluded; excludes Wasm adapter, JS, Svelte and dependencies',
  files: counts.sort((a, b) => b.lines - a.lines),
  bundles,
  dependencies: {
    cargo_packages: cargo.packages.length,
    npm_packages: Object.keys(npm.packages).length - 1,
  },
  native_coverage: coverage,
};
await mkdir(new URL('artifacts/', root), { recursive: true });
await writeFile(new URL('artifacts/health.json', root), JSON.stringify(report, null, 2) + '\n');
const summary = `Native core coverage: lines ${coverage.lines.percent.toFixed(2)}%, regions ${coverage.regions.percent.toFixed(2)}%.\n\n| Bundle | Raw bytes | gzip bytes |\n|---|---:|---:|\n${bundles.map((b) => `| ${b.path} | ${b.raw} | ${b.gzip} |`).join('\n')}\n\nLine counts include inline tests and are a review aid. Native coverage excludes the Wasm adapter and JavaScript/Svelte.\n`;
await writeFile(new URL('artifacts/health.md', root), summary);
console.log(summary);
