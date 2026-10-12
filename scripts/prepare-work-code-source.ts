/** Fixed-commit code snapshot. No network, credentials, owner rows or external writes. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { inspectCodeSource, localGit } from './work-git-disclosure.ts';

const hash = (b: Uint8Array | string) => createHash('sha256').update(b).digest('hex');
const text = (dir: string, args: string[]) => localGit(dir, args).toString().trim();
const oid = z.string().regex(/^[a-f0-9]{40}$/);
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const sourceSchema = z.strictObject({
  source_id: z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
  source_revision: z.literal(1),
  role: z.literal('code'),
  label: z.string().min(1).max(160),
  repo_name: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/),
  commit: oid,
  tree: oid,
  files: z.array(z.never()).length(0),
  code: z.strictObject({
    commits: z.literal(1),
    history_digest: digest,
    objects: z.number().int().min(1).max(65536),
    object_bytes: z.number().int().min(0).max(67108864),
    head_files: z.number().int().min(0).max(8192),
  }),
});
const provenanceSchema = z.strictObject({
  format_version: z.literal(1),
  source_commit: oid,
  source_tree: oid,
  snapshot_commit: oid,
  original_history_included: z.literal(false),
  source_sha256: digest,
  bundle_sha256: digest,
});

/** Restore the bundle into an independent repository and recompute all facts.
 * Canonical Git checks the original selected tree, not mutable workspace files.
 */
export async function verifyWorkCodeSource(directory: string, canonicalGitDir: string) {
  const source = sourceSchema.parse(
    JSON.parse(await readFile(join(directory, 'source.json'), 'utf8')),
  );
  const provenance = provenanceSchema.parse(
    JSON.parse(await readFile(join(directory, 'provenance.json'), 'utf8')),
  );
  assert.equal(hash(JSON.stringify(source)), provenance.source_sha256);
  assert.equal(hash(await readFile(join(directory, 'source.bundle'))), provenance.bundle_sha256);
  assert.equal(source.commit, provenance.snapshot_commit);
  assert.equal(source.tree, provenance.source_tree);
  assert.equal(
    text(canonicalGitDir, ['rev-parse', `${provenance.source_commit}^{tree}`]),
    source.tree,
  );
  const parent = await mkdtemp(join(tmpdir(), 'mikaki-code-source-verify-'));
  const gitDir = join(parent, 'source.git');
  try {
    execFileSync('git', ['clone', '--bare', join(resolve(directory), 'source.bundle'), gitDir], {
      stdio: 'pipe',
    });
    assert.equal(
      text(gitDir, ['for-each-ref', '--format=%(refname) %(objectname)']),
      `refs/heads/baseline ${source.commit}`,
    );
    const verified = await inspectCodeSource({
      repository: source.repo_name,
      gitDir,
      commit: source.commit,
    });
    assert.deepEqual(verified.commits, [source.commit]);
    assert.equal(
      text(gitDir, ['cat-file', 'commit', source.commit]).split('\n\n')[1],
      `mikaki Work code snapshot of ${provenance.source_commit}\nOriginal Git history excluded.`,
    );
    assert.deepEqual(source.code, {
      commits: 1,
      history_digest: hash(source.commit + '\n'),
      objects: verified.objects,
      object_bytes: verified.object_bytes,
      head_files: verified.head_files,
    });
    localGit(gitDir, ['fsck', '--full', '--strict', '--no-reflogs']);
    const physical = text(gitDir, [
      'cat-file',
      '--batch-all-objects',
      '--batch-check=%(objectname)',
    ]).split('\n');
    const reachable = text(gitDir, [
      'rev-list',
      '--objects',
      '--no-object-names',
      source.commit,
    ]).split('\n');
    assert.deepEqual(physical.sort(), reachable.sort());
    return { source, provenance };
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
}
export async function prepareWorkCodeSource(
  gitDir: string,
  commit: string,
  outputParent: string,
  sourceId = 'mikaki-code-snapshot',
  repoName = 'mikaki-work-source',
  label = 'mikaki（mainのコードスナップショット・過去の履歴なし）',
) {
  assert.match(commit, /^[a-f0-9]{40}$/);
  assert.match(sourceId, /^[A-Za-z0-9_.:-]{1,128}$/);
  assert.match(repoName, /^[a-z0-9][a-z0-9_-]{0,63}$/);
  assert.ok(label.length > 0 && Buffer.byteLength(label) <= 160 && !/\p{Cc}/u.test(label));
  gitDir = resolve(gitDir);
  assert.equal(text(gitDir, ['cat-file', '-t', commit]), 'commit');
  const original = localGit(gitDir, ['cat-file', 'commit', commit]);
  assert.equal(
    createHash('sha1').update(`commit ${original.length}\0`).update(original).digest('hex'),
    commit,
  );
  const tree = text(gitDir, ['rev-parse', `${commit}^{tree}`]);
  assert.match(tree, /^[a-f0-9]{40}$/);
  const entries = text(gitDir, ['ls-tree', '-r', tree]);
  assert.ok(!/^160000 /m.test(entries), 'Submodule data is not included in a code snapshot');
  const objects = text(gitDir, ['rev-list', '--objects', '--no-object-names', tree]).split('\n');
  assert.ok(objects.length <= 65536 && objects.every((id) => /^[a-f0-9]{40}$/.test(id)));
  const sizes = localGit(
    gitDir,
    ['cat-file', '--batch-check=%(objectsize)'],
    objects.join('\n') + '\n',
  )
    .toString()
    .trim()
    .split('\n')
    .map(Number);
  assert.equal(sizes.length, objects.length);
  assert.ok(sizes.every((n) => Number.isSafeInteger(n) && n >= 0));
  assert.ok(
    sizes.reduce((a, b) => a + b, 0) <= 64 * 1024 * 1024,
    'Code snapshot exceeds Work capacity',
  );
  const pack = localGit(
    gitDir,
    ['pack-objects', '--stdout', '--no-reuse-object', '--window=0', '--threads=1'],
    objects.join('\n') + '\n',
    {},
    64 * 1024 * 1024,
  );
  await mkdir(outputParent, { recursive: true });
  const directory = await mkdtemp(join(outputParent, 'code-source-'));
  const repository = join(directory, 'source.git');
  execFileSync('git', ['init', '--bare', repository], { stdio: 'pipe' });
  localGit(repository, ['index-pack', '--stdin', '--strict'], pack);
  const timestamp = text(gitDir, ['show', '-s', '--format=%ct', commit]);
  assert.match(timestamp, /^\d{1,12}$/);
  const snapshot = localGit(
    repository,
    ['commit-tree', tree],
    `mikaki Work code snapshot of ${commit}\nOriginal Git history excluded.\n`,
    {
      GIT_AUTHOR_NAME: 'mikaki Work source',
      GIT_AUTHOR_EMAIL: 'work-source@mikaki.invalid',
      GIT_COMMITTER_NAME: 'mikaki Work source',
      GIT_COMMITTER_EMAIL: 'work-source@mikaki.invalid',
      GIT_AUTHOR_DATE: `${timestamp} +0000`,
      GIT_COMMITTER_DATE: `${timestamp} +0000`,
    },
  )
    .toString()
    .trim();
  localGit(repository, ['update-ref', 'refs/heads/baseline', snapshot]);
  const verified = await inspectCodeSource({
    repository: repoName,
    gitDir: repository,
    commit: snapshot,
  });
  assert.equal(verified.commits.length, 1);
  assert.equal(verified.tree, tree);
  const source = {
    source_id: sourceId,
    source_revision: 1,
    role: 'code',
    label,
    repo_name: repoName,
    commit: snapshot,
    tree,
    files: [],
    code: {
      commits: 1,
      history_digest: hash(snapshot + '\n'),
      objects: verified.objects,
      object_bytes: verified.object_bytes,
      head_files: verified.head_files,
    },
  };
  const bundle = join(directory, 'source.bundle');
  localGit(repository, ['bundle', 'create', bundle, 'refs/heads/baseline']);
  const provenance = {
    format_version: 1,
    source_commit: commit,
    source_tree: tree,
    snapshot_commit: snapshot,
    original_history_included: false,
    source_sha256: hash(JSON.stringify(source)),
    bundle_sha256: hash(await readFile(bundle)),
  };
  for (const [name, value] of [
    ['source.json', source],
    ['provenance.json', provenance],
  ] as const)
    await writeFile(join(directory, name), JSON.stringify(value, null, 2) + '\n', {
      flag: 'wx',
      mode: 0o600,
    });
  return { directory, source, provenance };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [gitDir, commit, parent] = process.argv.slice(2);
  assert.ok(
    gitDir && commit && parent && process.argv.length === 5,
    'Usage: prepare-work-code-source.ts GIT_DIR EXACT_COMMIT OUTPUT_PARENT',
  );
  const result = await prepareWorkCodeSource(gitDir, commit, resolve(parent));
  console.log(
    JSON.stringify({
      directory: result.directory,
      source: result.source,
      provenance: result.provenance,
    }),
  );
}
