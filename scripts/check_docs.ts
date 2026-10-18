/** Check repository-owned Markdown destinations and headings without fetching external URLs. */
import { execFileSync } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import { dirname, resolve, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { markdownReferences, type MarkdownReferences } from './markdown-links.ts';

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
const documents = new Map<string, MarkdownReferences>();

async function markdownDocument(path: string): Promise<MarkdownReferences> {
  const cached = documents.get(path);
  if (cached) return cached;
  const parsed = markdownReferences(await readFile(path, 'utf8'));
  documents.set(path, parsed);
  return parsed;
}

for (const file of files) {
  const document = await markdownDocument(resolve(root, file));
  for (const { url: destination, line } of document.destinations) {
    if (/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(destination)) continue;
    let target: string;
    let fragment: string;
    try {
      const [path, hash = ''] = destination.split('#', 2);
      target = decodeURIComponent(path.split('?')[0]);
      fragment = decodeURIComponent(hash);
    } catch {
      errors.push(`${file}:${line}: invalid URL encoding: ${destination}`);
      continue;
    }
    if (!target && !fragment) continue;
    const absolute = !target
      ? resolve(root, file)
      : target.startsWith('/')
        ? resolve(root, `.${target}`)
        : resolve(root, dirname(file), target);
    const local = relative(root, absolute);
    if (local === '..' || local.startsWith(`..${sep}`)) {
      errors.push(`${file}:${line}: destination escapes repository: ${destination}`);
      continue;
    }
    checked++;
    try {
      await stat(absolute);
      if (fragment && absolute.toLowerCase().endsWith('.md')) {
        checkedFragments++;
        if (!(await markdownDocument(absolute)).anchors.has(fragment)) {
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
