/** Synthetic Git fixtures for local qualification/pilots only. */
import { mkdtemp } from 'node:fs/promises';
import { join } from 'node:path';
import { localGit } from './work-git-disclosure.ts';

export async function gitFixture(
  parent: string,
  name: string,
  files: Record<string, string>,
  previous?: string,
) {
  const dir = await mkdtemp(join(parent, `${name}-`));
  localGit(dir, ['init', '--bare', '--quiet', '--template=']);
  const put = (path: string, content: string) => {
    const blob = localGit(dir, ['hash-object', '-w', '--stdin'], content).toString().trim();
    localGit(dir, ['update-index', '--add', '--cacheinfo', '100644', blob, path]);
    return blob;
  };
  const env = {
    GIT_AUTHOR_NAME: 'Fixture',
    GIT_AUTHOR_EMAIL: 'fixture@mikaki.invalid',
    GIT_COMMITTER_NAME: 'Fixture',
    GIT_COMMITTER_EMAIL: 'fixture@mikaki.invalid',
    GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z',
    GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z',
  };
  let parentCommit: string | undefined, historicalBlob: string | undefined;
  if (previous) {
    historicalBlob = put('previous-only.md', previous);
    const tree = localGit(dir, ['write-tree']).toString().trim();
    parentCommit = localGit(dir, ['commit-tree', tree], 'Previous fixture version\n', env)
      .toString()
      .trim();
    localGit(dir, ['update-index', '--index-info'], '0 ' + '0'.repeat(40) + '\tprevious-only.md\n');
  }
  const blobs = new Map(Object.entries(files).map(([path, content]) => [path, put(path, content)]));
  const tree = localGit(dir, ['write-tree']).toString().trim();
  const commit = localGit(
    dir,
    ['commit-tree', tree, ...(parentCommit ? ['-p', parentCommit] : [])],
    'Current fixture version\n',
    env,
  )
    .toString()
    .trim();
  localGit(dir, ['update-ref', 'refs/heads/main', commit]);
  return { dir, commit, tree, blobs, historicalBlob, parentCommit };
}
