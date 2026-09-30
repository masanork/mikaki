/** Check repository-owned Markdown destinations and headings without fetching external URLs. */
import { execFileSync } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import { dirname, resolve, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const files = [
  ...new Set(
    execFileSync(
      'git',
      ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', '*.md'],
      { cwd: root },
    )
      .toString()
      .split('\0')
      .filter(Boolean),
  ),
];
const errors: string[] = [];
let checked = 0;
let checkedFragments = 0;
const anchors = new Map<string, Set<string>>();

function visibleProse(source: string): string {
  // Code examples are not navigable links or headings. Keep newlines for diagnostics.
  return source.replace(/^(`{3,}|~{3,})[^\n]*\n[\s\S]*?^\1[^\n]*$/gm, (match) =>
    match.replace(/[^\n]/g, ' '),
  );
}

async function markdownAnchors(path: string): Promise<Set<string>> {
  const cached = anchors.get(path);
  if (cached) return cached;
  const source = visibleProse(await readFile(path, 'utf8'));
  const found = new Set<string>();
  const duplicates = new Map<string, number>();
  for (const line of source.split('\n')) {
    const heading = /^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$/.exec(line);
    if (heading) {
      const title = heading[1]
        .replace(/!?\[([^\]]+)\]\([^)]*\)/g, '$1')
        .replace(/<[^>]*>/g, '')
        .replace(/[`*_~]/g, '');
      const slug = title
        .toLowerCase()
        .replace(/[^\p{L}\p{N}_\s-]/gu, '')
        .replace(/\s/g, '-');
      const duplicate = duplicates.get(slug) ?? 0;
      duplicates.set(slug, duplicate + 1);
      found.add(duplicate ? `${slug}-${duplicate}` : slug);
    }
    for (const match of line.matchAll(
      /<(?:a|[a-z][\w-]*)\b[^>]*\b(?:id|name)=["']([^"']+)["'][^>]*>/gi,
    )) {
      found.add(match[1]);
    }
  }
  anchors.set(path, found);
  return found;
}

for (const file of files) {
  const source = await readFile(resolve(root, file), 'utf8');
  const prose = visibleProse(source);
  const destinations = [
    ...prose.matchAll(/!?\[[^\]\n]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+["'][^\n]*["'])?\s*\)/g),
    ...prose.matchAll(/^\s*\[[^\]]+\]:\s*(<[^>]+>|\S+)/gm),
  ];
  for (const match of destinations) {
    const destination = match[1].replace(/^<|>$/g, '');
    if (/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(destination)) continue;
    let target: string;
    let fragment: string;
    try {
      const [path, hash = ''] = destination.split('#', 2);
      target = decodeURIComponent(path.split('?')[0]);
      fragment = decodeURIComponent(hash);
    } catch {
      errors.push(
        `${file}:${prose.slice(0, match.index).split('\n').length}: invalid URL encoding: ${destination}`,
      );
      continue;
    }
    if (!target && !fragment) continue;
    const absolute = !target
      ? resolve(root, file)
      : target.startsWith('/')
        ? resolve(root, `.${target}`)
        : resolve(root, dirname(file), target);
    const local = relative(root, absolute);
    const line = prose.slice(0, match.index).split('\n').length;
    if (local === '..' || local.startsWith(`..${sep}`)) {
      errors.push(`${file}:${line}: destination escapes repository: ${destination}`);
      continue;
    }
    checked++;
    try {
      await stat(absolute);
      if (fragment && absolute.toLowerCase().endsWith('.md')) {
        checkedFragments++;
        if (!(await markdownAnchors(absolute)).has(fragment)) {
          errors.push(`${file}:${line}: missing heading #${fragment} in ${destination}`);
        }
      }
    } catch {
      errors.push(`${file}:${line}: missing destination: ${destination}`);
    }
  }
}
if (errors.length) {
  console.error(errors.join('\n'));
  process.exitCode = 1;
} else
  console.log(
    `docs: ${files.length} Markdown files; ${checked} local destinations and ${checkedFragments} heading fragments exist`,
  );
