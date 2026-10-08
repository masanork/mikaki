/** Trusted local Git adapter. Explicit registered sources only; no network, checkout, OAuth or ledger. */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, realpath, stat, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';

export type GitSource = { repository: string; gitDir: string; commit: string };
export type ContextSource = GitSource & { paths: string[] };
export type GitDisclosure = {
  code: {
    repository: string;
    commit: string;
    tree: string;
    commits: string[];
    objects: number;
    object_bytes: number;
    head_files: number;
  };
  contexts: {
    repository: string;
    commit: string;
    tree: string;
    files: { path: string; blob: string; mode: string; content: string }[];
  }[];
  snapshot: { repository: string; commit: string; tree: string; parents: string[] };
};
const id = (v: string) => /^[A-Za-z0-9_.:-]{1,128}$/.test(v);
const oid = (v: string) => /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(v);
const order = (a: string, b: string) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const gitEnv = {
  PATH: process.env.PATH,
  LANG: 'C',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_NO_LAZY_FETCH: '1',
  GIT_TERMINAL_PROMPT: '0',
};
export function localGit(
  gitDir: string,
  args: string[],
  input?: Buffer | string,
  env: Record<string, string> = {},
  maxBuffer = 8 * 1024 * 1024,
) {
  try {
    return execFileSync(
      'git',
      [
        '--no-replace-objects',
        '-c',
        'protocol.allow=never',
        '-c',
        'core.hooksPath=/dev/null',
        '-c',
        'core.fsmonitor=false',
        '-c',
        'commit.gpgSign=false',
        '--git-dir',
        gitDir,
        ...args,
      ],
      {
        env: { ...gitEnv, ...env },
        input,
        timeout: 30000,
        maxBuffer,
        stdio: ['pipe', 'pipe', 'pipe'],
      },
    );
  } catch {
    throw new Error('git_disclosure_unavailable');
  } // no raw paths/content/diagnostics in normal errors
}
const text = (dir: string, args: string[], input?: Buffer | string, env?: Record<string, string>) =>
  utf8.decode(localGit(dir, args, input, env)).trim();
async function present(path: string) {
  try {
    await stat(path);
    return true;
  } catch (e) {
    if (e instanceof Error && 'code' in e && e.code === 'ENOENT') return false;
    throw e;
  }
}
function pathShape(path: string) {
  return (
    path.length > 0 &&
    Buffer.byteLength(path) <= 256 &&
    !/[\u0000-\u001f\u007f\\]/.test(path) &&
    path
      .split('/')
      .every(
        (part) =>
          part.length > 0 &&
          part !== '.' &&
          part !== '..' &&
          !part.toLowerCase().startsWith('.git'),
      )
  );
}
async function source(source: GitSource) {
  if (!id(source.repository) || !oid(source.commit)) throw new Error('invalid_git_source');
  const dir = await realpath(resolve(source.gitDir));
  if (
    !(await stat(dir)).isDirectory() ||
    text(dir, ['rev-parse', '--is-shallow-repository']) !== 'false'
  )
    throw new Error('unsupported_git_source');
  if (
    (await present(join(dir, 'info/grafts'))) ||
    (await present(join(dir, 'objects/info/alternates'))) ||
    (await readdir(join(dir, 'objects/pack')).catch(() => [] as string[])).some((name) =>
      name.endsWith('.promisor'),
    )
  )
    throw new Error('unsupported_git_source');
  if (text(dir, ['cat-file', '-t', source.commit]) !== 'commit')
    throw new Error('invalid_git_source');
  const tree = text(dir, ['rev-parse', `${source.commit}^{tree}`]);
  if (!oid(tree) || tree.length !== source.commit.length) throw new Error('invalid_git_source');
  return { dir, tree };
}
// Shared trusted inspection; consumers still select fixed registered sources.
export { source as inspectGitSource };
type Entry = { mode: string; type: string; blob: string; path: string };
function entries(dir: string, commit: string): Entry[] {
  const output = localGit(dir, ['ls-tree', '-r', '-z', '--full-tree', commit]);
  const parts = utf8.decode(output).split('\0');
  if (parts.pop() !== '') throw new Error('invalid_git_tree');
  if (parts.length > 8192) throw new Error('git_tree_capacity');
  return parts.map((part) => {
    const tab = part.indexOf('\t'),
      meta = part.slice(0, tab).split(' '),
      path = part.slice(tab + 1);
    if (tab < 0 || meta.length !== 3 || !oid(meta[2]!) || path.includes('\0'))
      throw new Error('invalid_git_tree');
    return { mode: meta[0]!, type: meta[1]!, blob: meta[2]!, path };
  });
}

function verifyObject(dir: string, object: string, type: string) {
  const body = localGit(dir, ['cat-file', type, object]);
  const digest = createHash(object.length === 40 ? 'sha1' : 'sha256')
    .update(`${type} ${body.length}\0`)
    .update(body)
    .digest('hex');
  if (digest !== object) throw new Error('invalid_git_object');
  return body.length;
}
function verifyContextTree(dir: string, commit: string, tree: string) {
  let bytes = verifyObject(dir, commit, 'commit') + verifyObject(dir, tree, 'tree');
  const parts = utf8.decode(localGit(dir, ['ls-tree', '-r', '-t', '-z', tree])).split('\0');
  if (parts.pop() !== '' || parts.length > 16384) throw new Error('git_tree_capacity');
  for (const part of parts) {
    const [mode, type, object] = part.slice(0, part.indexOf('\t')).split(' ');
    if (type === 'tree') {
      if (mode !== '040000' || !object || !oid(object)) throw new Error('invalid_git_tree');
      bytes += verifyObject(dir, object, 'tree');
      if (bytes > 67108864) throw new Error('git_tree_capacity');
    }
  }
}

export async function prepareGitDisclosure(
  code: GitSource,
  contexts: ContextSource[],
  outputParent: string,
  snapshotRepository: string,
): Promise<{ input: GitDisclosure; gitDir: string }> {
  if (
    !id(snapshotRepository) ||
    contexts.length > 4 ||
    contexts.reduce((n, c) => n + c.paths.length, 0) > 32 ||
    new Set([code.repository, snapshotRepository, ...contexts.map((c) => c.repository)]).size !==
      contexts.length + 2
  )
    throw new Error('invalid_git_selection');
  const inspected = await source(code);
  const selected = entries(inspected.dir, code.commit);
  const commits = text(inspected.dir, ['rev-list', '--max-count=4097', code.commit])
    .split('\n')
    .sort(order);
  if (commits.length > 4096 || commits.some((c) => !oid(c)) || !commits.includes(code.commit))
    throw new Error('git_history_capacity');
  const objects = text(inspected.dir, [
    'rev-list',
    '--objects',
    '--no-object-names',
    code.commit,
  ]).split('\n');
  if (objects.length > 65536 || objects.some((c) => !oid(c)))
    throw new Error('git_history_capacity');
  const sizes = text(
    inspected.dir,
    ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'],
    objects.join('\n') + '\n',
  ).split('\n');
  if (sizes.length !== objects.length) throw new Error('incomplete_git_history');
  let objectBytes = 0;
  for (const [index, line] of sizes.entries()) {
    const fields = line.split(' '),
      bytes = Number(fields[2]);
    if (
      fields.length !== 3 ||
      fields[0] !== objects[index] ||
      !['blob', 'tree', 'commit', 'tag'].includes(fields[1]!) ||
      !Number.isSafeInteger(bytes) ||
      bytes < 0
    )
      throw new Error('incomplete_git_history');
    objectBytes += bytes;
    if (objectBytes > 67108864) throw new Error('git_history_capacity');
  }
  // Verify the reachable bytes against their Git names; cat-file type/size
  // alone would accept a corrupt loose object whose filename is forged.
  const raw = localGit(
    inspected.dir,
    ['cat-file', '--batch'],
    objects.join('\n') + '\n',
    {},
    80 * 1024 * 1024,
  );
  let offset = 0;
  for (const [index, line] of sizes.entries()) {
    const end = raw.indexOf(10, offset);
    if (end < 0 || raw.subarray(offset, end).toString('ascii') !== line)
      throw new Error('invalid_git_object');
    const [, type, sizeText] = line.split(' '),
      size = Number(sizeText);
    const body = raw.subarray(end + 1, end + 1 + size);
    const digest = createHash(code.commit.length === 40 ? 'sha1' : 'sha256')
      .update(`${type} ${size}\0`)
      .update(body)
      .digest('hex');
    offset = end + size + 2;
    if (body.length !== size || raw[offset - 1] !== 10 || digest !== objects[index])
      throw new Error('invalid_git_object');
  }
  if (offset !== raw.length) throw new Error('invalid_git_object');
  const manifest: GitDisclosure = {
    code: {
      repository: code.repository,
      commit: code.commit,
      tree: inspected.tree,
      commits,
      objects: objects.length,
      object_bytes: objectBytes,
      head_files: selected.length,
    },
    contexts: [],
    snapshot: { repository: snapshotRepository, commit: '', tree: '', parents: [] },
  };
  let selectedBytes = 0;
  const dirs = new Set([inspected.dir]);
  for (const context of [...contexts].sort((a, b) => order(a.repository, b.repository))) {
    const s = await source(context);
    if (dirs.has(s.dir) || context.commit.length !== code.commit.length)
      throw new Error('ambiguous_git_source');
    dirs.add(s.dir);
    verifyContextTree(s.dir, context.commit, s.tree);
    const tree = new Map(entries(s.dir, context.commit).map((entry) => [entry.path, entry]));
    const paths = [...context.paths].sort(order);
    if (
      paths.length === 0 ||
      new Set(paths.map((p) => p.normalize('NFC').toLowerCase())).size !== paths.length
    )
      throw new Error('ambiguous_git_selection');
    const files = [];
    for (const path of paths) {
      if (!pathShape(path)) throw new Error('invalid_git_selection');
      const entry = tree.get(path);
      if (!entry || entry.type !== 'blob' || !['100644', '100755'].includes(entry.mode))
        throw new Error('unsupported_git_file');
      const size = Number(text(s.dir, ['cat-file', '-s', entry.blob]));
      if (!Number.isSafeInteger(size) || size > 16384 || selectedBytes + size > 131072)
        throw new Error('git_snapshot_capacity');
      const blob = localGit(s.dir, ['cat-file', 'blob', entry.blob]);
      if (blob.length !== size) throw new Error('invalid_git_blob');
      const content = utf8.decode(blob);
      const digest = createHash(code.commit.length === 40 ? 'sha1' : 'sha256')
        .update(`blob ${blob.length}\0`)
        .update(blob)
        .digest('hex');
      if (digest !== entry.blob) throw new Error('invalid_git_blob');
      if (
        /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(content) ||
        content.startsWith('version https://git-lfs.github.com/spec/v1\n')
      )
        throw new Error('unsupported_git_file');
      selectedBytes += size;
      files.push({ path, blob: entry.blob, mode: entry.mode, content });
    }
    manifest.contexts.push({
      repository: context.repository,
      commit: context.commit,
      tree: s.tree,
      files,
    });
  }
  // New object database only: no clone/fork/alternates, source refs, parents or
  // unselected historical objects. The caller owns this uniquely allocated dir.
  const gitDir = await mkdtemp(join(resolve(outputParent), 'snapshot-'));
  localGit(gitDir, [
    'init',
    '--bare',
    '--quiet',
    '--template=',
    '--object-format=' + (code.commit.length === 40 ? 'sha1' : 'sha256'),
  ]);
  const expected = new Map<string, string>();
  for (const [index, context] of manifest.contexts.entries())
    for (const file of context.files) {
      const path = `context/${String(index).padStart(2, '0')}/${file.path}`;
      const blob = text(gitDir, ['hash-object', '-w', '--stdin'], Buffer.from(file.content));
      if (blob !== file.blob) throw new Error('invalid_snapshot_blob');
      localGit(gitDir, ['update-index', '--add', '--cacheinfo', '100644', blob, path]);
      expected.set(path, blob);
    }
  const tree = text(gitDir, ['write-tree']);
  const commit = text(gitDir, ['commit-tree', tree], 'Mikaki selected context snapshot\n', {
    GIT_AUTHOR_NAME: 'Mikaki Snapshot',
    GIT_AUTHOR_EMAIL: 'snapshot@mikaki.invalid',
    GIT_COMMITTER_NAME: 'Mikaki Snapshot',
    GIT_COMMITTER_EMAIL: 'snapshot@mikaki.invalid',
    GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z',
    GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z',
  });
  localGit(gitDir, ['update-ref', 'refs/heads/snapshot', commit]);
  const header = text(gitDir, ['cat-file', 'commit', commit]).split('\n\n')[0]!;
  if (
    header.split('\n').some((line) => line.startsWith('parent ')) ||
    text(gitDir, ['rev-list', '--all', '--count']) !== '1'
  )
    throw new Error('snapshot_history_leak');
  const copied = entries(gitDir, commit);
  if (
    copied.length !== expected.size ||
    copied.some((e) => e.mode !== '100644' || e.type !== 'blob' || e.blob !== expected.get(e.path))
  )
    throw new Error('snapshot_selection_mismatch');
  localGit(gitDir, ['fsck', '--full', '--strict', '--no-reflogs']);
  manifest.snapshot = { repository: snapshotRepository, commit, tree, parents: [] };
  return { input: manifest, gitDir };
}
