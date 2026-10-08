/** Independent bounded Git archive verifier. No network, checkout or authority. */
import { createHash } from 'node:crypto';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { inspectGitSource, localGit, type GitSource } from './work-git-disclosure.ts';

export type CandidateGitFacts = {
  commit: string;
  tree: string;
  base_commit: string;
  objects: number;
  object_bytes: number;
  inventory_digest: string;
  bundle_digest: string;
  bundle_bytes: number;
};
const MAX_BUNDLE = 8 * 1024 * 1024,
  MAX_OBJECT_BYTES = 64 * 1024 * 1024;
const oid = (s: string) => /^[a-f0-9]{40}$/.test(s);
const text = (dir: string, args: string[]) => localGit(dir, args).toString().trim();
const header = (commit: string) =>
  Buffer.from(`# v2 git bundle\n${commit} refs/heads/retained-candidate\n\n`);
function inspect(dir: string, commit: string, tree: string, base: string) {
  if (![commit, tree, base].every(oid) || text(dir, ['rev-parse', `${commit}^{tree}`]) !== tree)
    throw new Error('candidate_git_binding');
  localGit(dir, ['merge-base', '--is-ancestor', base, commit]);
  const objects = text(dir, ['rev-list', '--objects', '--no-object-names', commit])
    .split('\n')
    .sort();
  if (
    objects.length > 65536 ||
    new Set(objects).size !== objects.length ||
    objects.some((o) => !oid(o))
  )
    throw new Error('candidate_git_capacity');
  const commits = text(dir, ['rev-list', '--max-count=4097', commit]).split('\n');
  if (commits.length > 4096) throw new Error('candidate_git_capacity');
  // Hash raw bytes, not Git's declared names/type/size alone. One bounded batch
  // avoids spawning a process per object and catches forged loose object names.
  const raw = localGit(
    dir,
    ['cat-file', '--batch'],
    objects.join('\n') + '\n',
    {},
    80 * 1024 * 1024,
  );
  let offset = 0,
    bytes = 0;
  const lines: string[] = [];
  for (const object of objects) {
    const end = raw.indexOf(10, offset);
    if (end < 0) throw new Error('candidate_git_corrupt');
    const line = raw.subarray(offset, end).toString('ascii'),
      match = /^([a-f0-9]{40}) (commit|tree|blob) (\d+)$/.exec(line);
    if (!match || match[1] !== object) throw new Error('candidate_git_corrupt');
    const length = Number(match[3]);
    bytes += length;
    if (!Number.isSafeInteger(bytes) || bytes > MAX_OBJECT_BYTES)
      throw new Error('candidate_git_capacity');
    const body = raw.subarray(end + 1, end + 1 + length);
    if (
      body.length !== length ||
      raw[end + 1 + length] !== 10 ||
      createHash('sha1').update(`${match[2]} ${length}\0`).update(body).digest('hex') !== object
    )
      throw new Error('candidate_git_corrupt');
    offset = end + length + 2;
    lines.push(line);
  }
  if (offset !== raw.length) throw new Error('candidate_git_corrupt');
  return {
    objects,
    object_bytes: bytes,
    inventory_digest: createHash('sha256')
      .update(lines.join('\n') + '\n')
      .digest('hex'),
  };
}
export async function restoreCandidatePayload(
  bytes: Buffer,
  facts: CandidateGitFacts,
  parent: string,
) {
  if (
    !oid(facts.commit) ||
    bytes.length === 0 ||
    bytes.length > MAX_BUNDLE ||
    bytes.length !== facts.bundle_bytes ||
    createHash('sha256').update(bytes).digest('hex') !== facts.bundle_digest ||
    !bytes.subarray(0, header(facts.commit).length).equals(header(facts.commit))
  )
    throw new Error('candidate_bundle_binding');
  const dir = await mkdtemp(join(parent, 'candidate-restore-'));
  try {
    localGit(dir, ['init', '--bare', '--quiet', '--template=']);
    const path = join(dir, 'retained.bundle');
    await writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
    localGit(dir, ['bundle', 'verify', path]);
    if (
      text(dir, ['bundle', 'list-heads', path]) !== `${facts.commit} refs/heads/retained-candidate`
    )
      throw new Error('candidate_bundle_refs');
    localGit(dir, ['bundle', 'unbundle', path]);
    localGit(dir, ['update-ref', 'refs/heads/retained-candidate', facts.commit]);
    localGit(dir, ['fsck', '--full', '--strict', '--no-reflogs']);
    const observed = inspect(dir, facts.commit, facts.tree, facts.base_commit);
    const all = text(dir, ['cat-file', '--batch-all-objects', '--batch-check=%(objectname)'])
      .split('\n')
      .sort();
    if (
      all.join('\n') !== observed.objects.join('\n') ||
      observed.objects.length !== facts.objects ||
      observed.object_bytes !== facts.object_bytes ||
      observed.inventory_digest !== facts.inventory_digest
    )
      throw new Error('candidate_bundle_inventory');
    return { dir };
  } catch (error) {
    await rm(dir, { recursive: true, force: true });
    throw error;
  }
}
export async function prepareCandidatePayload(
  source: GitSource,
  tree: string,
  base: string,
  parent: string,
) {
  if (!oid(source.commit)) throw new Error('candidate_git_profile');
  const inspected = await inspectGitSource(source),
    inventory = inspect(inspected.dir, source.commit, tree, base);
  const pack = localGit(
    inspected.dir,
    ['pack-objects', '--stdout', '--window=0', '--threads=1'],
    inventory.objects.join('\n') + '\n',
    {},
    MAX_BUNDLE + 1,
  );
  const bytes = Buffer.concat([header(source.commit), pack]);
  if (bytes.length > MAX_BUNDLE) throw new Error('candidate_bundle_capacity');
  const facts: CandidateGitFacts = {
    commit: source.commit,
    tree,
    base_commit: base,
    objects: inventory.objects.length,
    object_bytes: inventory.object_bytes,
    inventory_digest: inventory.inventory_digest,
    bundle_digest: createHash('sha256').update(bytes).digest('hex'),
    bundle_bytes: bytes.length,
  };
  // Independent fresh-repo import checks prerequisites, dangling/extra objects,
  // exact commit/tree/ancestry and all raw bytes before producing adapter facts.
  const verified = await restoreCandidatePayload(bytes, facts, parent);
  await rm(verified.dir, { recursive: true, force: true });
  return { facts, bytes };
}
