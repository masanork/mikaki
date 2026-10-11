/** Operator-only sealed provisioning from an exact Native disclosure projection. */
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { mkdtemp, open, mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from 'zod';
import { disclosureSchema } from '../crates/worker/ui/work-preparation-view.ts';
import { gitRegistrySchema } from '../crates/work-git-host-worker/registry.ts';
import type { GitRegistry } from '../crates/work-git-host-worker/registry.ts';
import type { RegisteredGit } from './work-git-executor.ts';
import { localGit, inspectGitSource, prepareGitDisclosure } from './work-git-disclosure.ts';
import { objectInventory } from './work-artifacts-git.ts';
import { PreparedGitCopy } from './work-git-copy.ts';
import { boundedGitPack } from './work-git-readback.ts';
const sha256 = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');
const reviewSchema = z.strictObject({
  kind: z.literal('disclosure'),
  digest: z.string().regex(/^[a-f0-9]{64}$/),
  manifest: disclosureSchema,
  current_sources: z.literal(true),
});
const sourcesSchema = z
  .array(
    z.strictObject({
      source_id: z.string().regex(/^[A-Za-z0-9_.:-]{1,128}$/),
      source_revision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
      access_revision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
      gitDir: z.string().min(1).max(4096),
    }),
  )
  .min(1)
  .max(5);
// Open the selected regular file without following a last-component symlink.
export async function boundedHostFile(path: string, maximum: number) {
  const f = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const s = await f.stat();
    if (!s.isFile() || s.size > maximum) throw new Error('git_registry_invalid');
    const bytes = Buffer.alloc(s.size + 1);
    let n = 0;
    while (n < bytes.length) {
      const r = await f.read(bytes, n, bytes.length - n, n);
      if (!r.bytesRead) break;
      n += r.bytesRead;
    }
    if (n !== s.size) throw new Error('git_registry_invalid');
    return bytes.subarray(0, n);
  } finally {
    await f.close();
  }
}
/** Paths are trusted operator capabilities, never owner request fields. No network. */
export async function materializeGitRegistry(
  reviewInput: unknown,
  sourcesInput: unknown,
  outputParent: string,
) {
  const review = reviewSchema.parse(reviewInput),
    sources = sourcesSchema.parse(sourcesInput);
  const d = review.manifest;
  if (
    sources.length !== d.registered_sources.length ||
    new Set(sources.map((s) => s.source_id)).size !== sources.length
  )
    throw new Error('git_registry_source_mismatch');
  const source = (id: string) => {
    const binding = d.registered_sources.find((s) => s.source_id === id),
      local = sources.find((s) => s.source_id === id);
    if (
      !binding ||
      !local ||
      binding.source_revision !== local.source_revision ||
      binding.access_revision !== local.access_revision
    )
      throw new Error('git_registry_source_mismatch');
    return local.gitDir;
  };
  let scratch: string | undefined, directory: string | undefined;
  try {
    scratch = await mkdtemp(join(outputParent, 'git-materialize-'));
    const codeSource = {
      repository: d.code.repository,
      gitDir: source(d.code.repository),
      commit: d.code.commit,
    };
    const selected = await prepareGitDisclosure(
      codeSource,
      d.contexts.map((c) => ({
        repository: c.repository,
        gitDir: source(c.repository),
        commit: c.commit,
        paths: c.files.map((f) => f.path),
      })),
      scratch,
      d.snapshot.repository,
    );
    const actual = selected.input;
    if (
      actual.code.tree !== d.code.tree ||
      actual.code.commits.length !== d.code.commits ||
      sha256(actual.code.commits.map((c) => c + '\n').join('')) !== d.code.history_digest ||
      actual.code.objects !== d.code.objects ||
      actual.code.object_bytes !== d.code.object_bytes ||
      actual.code.head_files !== d.code.head_files ||
      actual.snapshot.commit !== d.snapshot.commit ||
      actual.snapshot.tree !== d.snapshot.tree
    )
      throw new Error('git_registry_source_mismatch');
    for (const [i, c] of d.contexts.entries()) {
      const a = actual.contexts[i];
      if (
        !a ||
        a.repository !== c.repository ||
        a.commit !== c.commit ||
        a.tree !== c.tree ||
        a.files.length !== c.files.length
      )
        throw new Error('git_registry_source_mismatch');
      for (const [j, f] of c.files.entries()) {
        const v = a.files[j];
        if (
          !v ||
          v.path !== f.path ||
          v.blob !== f.blob ||
          v.mode !== f.mode ||
          Buffer.byteLength(v.content) !== f.bytes ||
          sha256(v.content) !== f.sha256 ||
          f.snapshot_path !== `context/${String(i).padStart(2, '0')}/${f.path}`
        )
          throw new Error('git_registry_source_mismatch');
      }
    }
    const inspected = await inspectGitSource(codeSource);
    directory = await mkdtemp(join(outputParent, 'git-registry-'));
    const entries: GitRegistry['entries'][number][] = [];
    for (const role of ['task', 'snapshot'] as const) {
      const gitDir = role === 'task' ? inspected.dir : selected.gitDir;
      const facts = role === 'task' ? d.code : d.snapshot;
      const copy = await PreparedGitCopy.prepare(
        { gitDir, commit: facts.commit, tree: facts.tree },
        role,
      );
      const pack = copy.uploadBody().subarray(-copy.manifest.pack_bytes);
      const count = boundedGitPack(pack);
      if (count !== copy.manifest.objects) throw new Error('git_registry_pack_mismatch');
      await writeFile(join(directory, role + '.pack'), pack, { flag: 'wx', mode: 0o600 });
      entries.push({
        role,
        commit: facts.commit,
        tree: facts.tree,
        commits: role === 'task' ? d.code.commits : 1,
        objects: count,
        object_bytes: copy.manifest.object_bytes,
        inventory_sha256: copy.manifest.inventory_sha256,
        pack_bytes: pack.length,
        pack_sha256: sha256(pack),
      });
    }
    const registry = gitRegistrySchema.parse({
      format_version: 1,
      disclosure_digest: review.digest,
      entries,
    });
    const bytes = JSON.stringify(registry) + '\n';
    await writeFile(join(directory, 'registry.json'), bytes, { flag: 'wx', mode: 0o600 });
    return { directory, registry, registry_sha256: sha256(bytes) };
  } catch (e) {
    if (directory) await rm(directory, { recursive: true, force: true });
    throw e;
  } finally {
    if (scratch) await rm(scratch, { recursive: true, force: true });
  }
}
/** Cold start always rehashes and indexes into new private object databases. */
export async function loadGitRegistry(
  directory: string,
  expectedSha256: string,
  temporaryParent: string,
) {
  if (!/^[a-f0-9]{64}$/.test(expectedSha256)) throw new Error('git_registry_invalid');
  const bytes = await boundedHostFile(join(directory, 'registry.json'), 4096);
  if (sha256(bytes) !== expectedSha256) throw new Error('git_registry_mismatch');
  const registry = gitRegistrySchema.parse(
    JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)),
  );
  const runtime = await mkdtemp(join(temporaryParent, 'git-host-'));
  try {
    const registered: RegisteredGit[] = [];
    for (const entry of registry.entries) {
      const pack = await boundedHostFile(join(directory, entry.role + '.pack'), entry.pack_bytes);
      if (
        pack.length !== entry.pack_bytes ||
        sha256(pack) !== entry.pack_sha256 ||
        boundedGitPack(pack) !== entry.objects
      )
        throw new Error('git_registry_pack_mismatch');
      const gitDir = join(runtime, entry.role);
      await mkdir(gitDir, { mode: 0o700 });
      localGit(gitDir, ['init', '--bare', '--quiet', '--template=', '--object-format=sha1']);
      localGit(gitDir, ['index-pack', '--strict', '--stdin'], pack, {}, 1024 * 1024);
      localGit(gitDir, [
        'update-ref',
        `refs/heads/${entry.role === 'task' ? 'work' : 'snapshot'}`,
        entry.commit,
      ]);
      const inspected = await inspectGitSource({
        repository: entry.role,
        gitDir,
        commit: entry.commit,
      });
      const inventory = objectInventory(gitDir, entry.commit);
      const commits = localGit(gitDir, ['rev-list', entry.commit]).toString().trim().split('\n');
      const physical = localGit(gitDir, [
        'cat-file',
        '--batch-all-objects',
        '--batch-check=%(objectname) %(objecttype) %(objectsize)',
      ])
        .toString()
        .trim()
        .split('\n')
        .sort();
      if (
        inspected.tree !== entry.tree ||
        inventory.objects.length !== entry.objects ||
        inventory.bytes !== entry.object_bytes ||
        inventory.sha256 !== entry.inventory_sha256 ||
        physical.join('\n') !== inventory.inventory.join('\n') ||
        commits.length !== entry.commits ||
        (entry.role === 'snapshot' &&
          /^parent /m.test(localGit(gitDir, ['cat-file', 'commit', entry.commit]).toString()))
      )
        throw new Error('git_registry_object_mismatch');
      localGit(gitDir, ['fsck', '--full', '--strict', '--no-reflogs']);
      registered.push({
        disclosure_digest: registry.disclosure_digest,
        role: entry.role,
        gitDir,
        commit: entry.commit,
        tree: entry.tree,
      });
    }
    return {
      registry,
      registered,
      temporaryDirectory: runtime,
      close: () => rm(runtime, { recursive: true, force: true }),
    };
  } catch (e) {
    await rm(runtime, { recursive: true, force: true });
    throw e;
  }
}
