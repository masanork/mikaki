/** Keep hand-written JavaScript out of product source trees. */
import { execFileSync } from 'node:child_process';
import { extname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const JAVASCRIPT_SUFFIXES = new Set(['.js', '.mjs', '.cjs', '.jsx']);

export function checkProductSources() {
  const listed = execFileSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', 'crates', 'local/ui'],
    { cwd: ROOT },
  );
  const found = listed
    .toString('utf8')
    .split('\0')
    .filter((name) => name && JAVASCRIPT_SUFFIXES.has(extname(name)))
    .sort();
  if (found.length)
    throw new Error(`Product JavaScript must be TypeScript source:\n${found.join('\n')}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  checkProductSources();
}
