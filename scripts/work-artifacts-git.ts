/** Bounded operator Git transport and independent readback. No authority ledger. */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import type { Artifacts } from '@cloudflare/workers-types';
import { localGit } from './work-git-disclosure.ts';

export const ARTIFACTS_ACCOUNT = '4b749427a0c80c547e726a42aff4b6fc';
export const PROBE_NAMESPACE = 'mikaki-dev';
export async function probeRepositoryAbsent(artifacts: Pick<Artifacts, 'list'>, name: string) {
  probeRemote(name);
  let cursor: string | undefined, total: number | undefined;
  const ids = new Set<string>(),
    names = new Set<string>(),
    cursors = new Set<string>();
  for (let page = 0; page < 4; page++) {
    const result = await artifacts.list({ limit: 200, ...(cursor ? { cursor } : {}) });
    if (
      !Number.isSafeInteger(result.total) ||
      result.total < 0 ||
      result.total > 512 ||
      (total !== undefined && result.total !== total)
    )
      throw new Error('probe_repository_inventory_incomplete');
    total = result.total;
    for (const repo of result.repos) {
      if (ids.has(repo.id) || names.has(repo.name))
        throw new Error('probe_repository_inventory_incomplete');
      ids.add(repo.id);
      names.add(repo.name);
    }
    if (names.has(name)) return false;
    if (!result.cursor) {
      if (ids.size !== total) throw new Error('probe_repository_inventory_incomplete');
      return true;
    }
    if (cursors.has(result.cursor)) throw new Error('probe_repository_inventory_incomplete');
    cursor = result.cursor;
    cursors.add(cursor);
  }
  throw new Error('probe_repository_inventory_incomplete');
}
export function probeRemote(name: string) {
  if (!/^wk-[a-f0-9]{32}-(code|snapshot)$/.test(name)) throw new Error('invalid_probe_destination');
  return `https://${ARTIFACTS_ACCOUNT}.artifacts.cloudflare.net/git/${PROBE_NAMESPACE}/${name}.git`;
}
export function opaqueGitToken(token: unknown): asserts token is string {
  if (
    typeof token !== 'string' ||
    token.length < 16 ||
    token.length > 4096 ||
    /[\s\u0000-\u001f\u007f]/.test(token)
  )
    throw new Error('invalid_git_credential');
}
export function remoteGit(name: string, token: string, args: string[]) {
  opaqueGitToken(token);
  const remote = probeRemote(name);
  // Only an exact repo URL gets this ephemeral header. No helpers, redirects,
  // inherited Git configuration, hooks, credential arguments or persistent URL.
  const env = {
    PATH: process.env.PATH,
    LANG: 'C',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_NO_LAZY_FETCH: '1',
    GIT_CONFIG_COUNT: '7',
    GIT_CONFIG_KEY_0: `http.${remote}.extraHeader`,
    GIT_CONFIG_VALUE_0: `Authorization: Bearer ${token}`,
    GIT_CONFIG_KEY_1: 'credential.helper',
    GIT_CONFIG_VALUE_1: '',
    GIT_CONFIG_KEY_2: 'http.followRedirects',
    GIT_CONFIG_VALUE_2: 'false',
    GIT_CONFIG_KEY_3: 'protocol.version',
    GIT_CONFIG_VALUE_3: '1',
    GIT_CONFIG_KEY_4: 'core.hooksPath',
    GIT_CONFIG_VALUE_4: '/dev/null',
    GIT_CONFIG_KEY_5: 'protocol.allow',
    GIT_CONFIG_VALUE_5: 'never',
    GIT_CONFIG_KEY_6: 'protocol.https.allow',
    GIT_CONFIG_VALUE_6: 'always',
  };
  try {
    return execFileSync(
      'git',
      args.map((a) => (a === '@REMOTE@' ? remote : a)),
      {
        env,
        timeout: 60000,
        maxBuffer: 2 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    ).toString();
  } catch {
    throw new Error('probe_git_failed');
  } // diagnostics can contain credentials
}
export async function gitAdvertisement(name: string, token: string) {
  opaqueGitToken(token);
  const response = await fetch(`${probeRemote(name)}/info/refs?service=git-upload-pack`, {
    headers: { Authorization: `Bearer ${token}` },
    redirect: 'error',
    signal: AbortSignal.timeout(30000),
  });
  await response.body?.cancel();
  return response.status;
}
export function objectInventory(gitDir: string, commit?: string) {
  const objects = localGit(
    gitDir,
    commit
      ? ['rev-list', '--objects', '--no-object-names', commit]
      : ['rev-list', '--objects', '--no-object-names', '--all'],
  )
    .toString()
    .trim()
    .split('\n')
    .sort();
  if (objects.length > 65536 || objects.some((o) => !/^[a-f0-9]{40}$/.test(o)))
    throw new Error('invalid_probe_inventory');
  const inventory = localGit(
    gitDir,
    ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)'],
    objects.join('\n') + '\n',
  )
    .toString()
    .trim()
    .split('\n')
    .sort();
  if (inventory.length !== objects.length) throw new Error('incomplete_probe_inventory');
  let bytes = 0;
  for (const line of inventory) {
    const match = /^([a-f0-9]{40}) (commit|tree|blob|tag) (\d+)$/.exec(line);
    if (!match || !objects.includes(match[1]!)) throw new Error('invalid_probe_inventory');
    bytes += Number(match[3]);
    if (!Number.isSafeInteger(bytes) || bytes > 67108864)
      throw new Error('probe_inventory_capacity');
    const content = localGit(gitDir, ['cat-file', match[2]!, match[1]!]);
    if (
      content.length !== Number(match[3]) ||
      createHash('sha1').update(`${match[2]} ${content.length}\0`).update(content).digest('hex') !==
        match[1]
    )
      throw new Error('probe_object_hash_mismatch');
  }
  return {
    objects,
    inventory,
    bytes,
    sha256: createHash('sha256')
      .update(inventory.join('\n') + '\n')
      .digest('hex'),
  };
}
export function verifyGitReadback(
  gitDir: string,
  sourceDir: string,
  commit: string,
  tree: string,
  branch: 'work' | 'snapshot',
) {
  const expected = objectInventory(sourceDir, commit),
    actual = objectInventory(gitDir);
  const refs = localGit(gitDir, ['for-each-ref', '--format=%(refname) %(objectname)'])
    .toString()
    .trim();
  if (
    refs !== `refs/heads/${branch} ${commit}` ||
    localGit(gitDir, ['rev-parse', `${commit}^{tree}`])
      .toString()
      .trim() !== tree ||
    actual.inventory.join('\n') !== expected.inventory.join('\n')
  )
    throw new Error('probe_readback_mismatch');
  localGit(gitDir, ['fsck', '--full', '--strict', '--no-reflogs']);
  const commits = localGit(gitDir, ['rev-list', '--all']).toString().trim().split('\n');
  if (
    branch === 'snapshot' &&
    (commits.length !== 1 ||
      /^parent /m.test(localGit(gitDir, ['cat-file', 'commit', commit]).toString()))
  )
    throw new Error('probe_snapshot_history_leak');
  return {
    commit,
    tree,
    refs: [refs],
    commits: commits.length,
    objects: actual.objects.length,
    object_bytes: actual.bytes,
    inventory_sha256: actual.sha256,
    fsck: true,
  };
}
