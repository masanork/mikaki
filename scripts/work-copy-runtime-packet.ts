/** Offline companion bytes only. No deployment, resource allocation or copy authority. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  lstat,
  mkdir,
  mkdtemp,
  opendir,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { basename, dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, version as esbuildVersion } from 'esbuild';
import { releaseSource } from './release-inventory.ts';
import { packetFile } from './work-authority-packet.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const kind = 'mikaki-work-copy-companions-v1';
const stage = 'offline-inputs-not-deployed-or-authorized';
const maximum = 16 * 1024 * 1024;
export const COPY_PACKET_LIMITS = { entries: 768, depth: 12, bytes: 64 * 1024 * 1024 } as const;
type Digest = { bytes: number; sha256: string };
type Member = { path: string; digest: Digest };
type Dependency = {
  path: string;
  archive: string;
  integrity: string;
  resolved: string;
  inputs: string[];
};
type Lock = { packages: Record<string, { integrity?: string; resolved?: string }> };
export type CopyRuntimeReceipt = { source_commit: string; manifest_sha256: string };

export const COPY_RUNTIME_MODULES = [
  ['copy', 'crates/work-copy-worker/worker.ts', 'WorkCopyStarter'],
  ['initial', 'crates/work-effect-worker/worker.ts', 'WorkEffectGate'],
  ['initial-reconcile', 'crates/work-effect-worker/reconcile.ts', 'WorkEffectReconciler'],
  ['initial-maintenance', 'crates/work-effect-worker/maintenance.ts', 'WorkArtifactsMaintenance'],
  ['mint', 'crates/work-effect-worker/mint.ts', 'WorkMintGate'],
  [
    'mint-maintenance',
    'crates/work-effect-worker/mint-maintenance.ts',
    'WorkMintArtifactsMaintenance',
  ],
  ['mint-reconcile', 'crates/work-effect-worker/mint-reconcile.ts', 'WorkMintReconciler'],
  ['mint-close', 'crates/work-effect-worker/mint-closure.ts', 'WorkMintCloser'],
  [
    'mint-refusal',
    'crates/work-effect-worker/mint-refusal-transport.ts',
    'WorkMintRefusalTransport',
  ],
  ['git', 'crates/work-effect-worker/git.ts', 'WorkGitGate'],
  ['git-transport', 'crates/work-effect-worker/git-transport.ts', 'WorkGitTransport'],
  ['preparation', 'crates/work-effect-worker/preparation.ts', 'WorkPreparationGate'],
  ['git-host', 'crates/work-git-host-worker/worker.ts', 'WorkGitHost'],
  ['checkpoint', 'crates/work-checkpoint-worker/worker.ts', 'WorkCheckpointService'],
] as const;

const prerequisites = {
  op_source_matched_attestation: 'required',
  current_native_disclosure_and_source_packet: 'required',
  sealed_git_packs_and_container_image: 'required',
  private_resource_version_and_binding_observations: 'required',
  active_wrapping_key_custody: 'required',
  current_owner_copy_consent: 'required',
  productive_provider_readback_and_credential_closure: 'required',
  execution_authorized: false,
  ai_delegation_authorized: false,
} as const;

function digest(bytes: Uint8Array): Digest {
  assert.ok(bytes.byteLength <= maximum, 'copy_packet_file_too_large');
  return { bytes: bytes.byteLength, sha256: createHash('sha256').update(bytes).digest('hex') };
}
function memberPath(path: unknown): asserts path is string {
  assert.ok(typeof path === 'string' && /^[A-Za-z0-9_@.\/-]+$/.test(path));
  assert.ok(!path.startsWith('/') && path.split('/').every((p) => p && p !== '.' && p !== '..'));
}
export async function copyRuntimeInventory(
  directory: string,
  prefix = '',
  budget?: { entries: number; bytes: number },
): Promise<Member[]> {
  const currentBudget = budget === undefined ? { entries: 0, bytes: 0 } : budget;
  assert.ok(prefix.split('/').length <= COPY_PACKET_LIMITS.depth, 'copy_packet_depth_limit');
  const found: Member[] = [];
  const entries = await opendir(join(directory, prefix));
  for await (const entry of entries) {
    assert.ok(++currentBudget.entries <= COPY_PACKET_LIMITS.entries, 'copy_packet_entry_limit');
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    memberPath(path);
    if (path === 'manifest.json') continue;
    const location = join(directory, path);
    const info = await lstat(location);
    assert.ok(!info.isSymbolicLink(), 'copy_packet_link_denied');
    if (info.isDirectory())
      found.push(...(await copyRuntimeInventory(directory, path, currentBudget)));
    else {
      assert.ok(info.isFile() && info.nlink === 1, 'copy_packet_member_denied');
      currentBudget.bytes += info.size;
      assert.ok(currentBudget.bytes <= COPY_PACKET_LIMITS.bytes, 'copy_packet_total_limit');
      found.push({ path, digest: digest(await packetFile(location, maximum)) });
    }
  }
  return found.sort((a, b) => a.path.localeCompare(b.path));
}
async function json(path: string, value: unknown) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
}
function decode(bytes: Buffer): unknown {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

function dependencyIntegrity(archive: Buffer, integrity: string) {
  assert.match(integrity, /^sha512-[A-Za-z0-9+/]{86}==$/, 'copy_dependency_integrity_required');
  assert.equal(
    'sha512-' + createHash('sha512').update(archive).digest('base64'),
    integrity,
    'copy_dependency_archive_changed',
  );
}
function archivedDependencyFile(archive: Buffer, path: string): Buffer {
  memberPath(path);
  return execFileSync('tar', ['-xzOf', '-', '--', `package/${path}`], {
    input: archive,
    stdio: ['pipe', 'pipe', 'pipe'],
    maxBuffer: maximum,
    timeout: 30000,
  });
}
function lockedDependency(lock: Lock, path: string) {
  memberPath(path);
  const owner = Object.keys(lock.packages)
    .filter((key) => key.startsWith('node_modules/') && path.startsWith(key + '/'))
    .sort((a, b) => b.length - a.length)[0];
  assert.ok(owner, 'copy_dependency_unlocked');
  const record = lock.packages[owner]!;
  assert.ok(record.resolved && record.integrity, 'copy_dependency_unlocked');
  const url = new URL(record.resolved);
  assert.ok(
    url.origin === 'https://registry.npmjs.org' &&
      !url.username &&
      !url.password &&
      !url.search &&
      !url.hash,
    'copy_dependency_registry_denied',
  );
  return { owner, integrity: record.integrity, resolved: record.resolved };
}

async function verifyDependencies(directory: string, value: unknown) {
  assert.ok(
    Array.isArray(value) && value.length > 0 && value.length <= 32,
    'copy_dependencies_denied',
  );
  const lock = decode(await packetFile(join(directory, 'inputs/package-lock.json'))) as Lock;
  const owners: string[] = [];
  for (const item of value as Dependency[]) {
    assert.deepEqual(Object.keys(item).sort(), [
      'archive',
      'inputs',
      'integrity',
      'path',
      'resolved',
    ]);
    memberPath(item.path);
    memberPath(item.archive);
    assert.equal(
      item.archive,
      `dependencies/${createHash('sha256').update(item.path).digest('hex')}.tgz`,
    );
    assert.ok(
      !owners.includes(item.path) && Array.isArray(item.inputs) && item.inputs.length <= 512,
    );
    owners.push(item.path);
    const expected = lockedDependency(lock, item.path + '/package.json');
    assert.deepEqual(expected, {
      owner: item.path,
      integrity: item.integrity,
      resolved: item.resolved,
    });
    const archive = await packetFile(join(directory, item.archive));
    dependencyIntegrity(archive, item.integrity);
    assert.ok(item.inputs.includes(`${item.path}/package.json`));
    assert.deepEqual(item.inputs, [...new Set(item.inputs)].sort());
    for (const path of item.inputs) {
      memberPath(path);
      assert.equal(lockedDependency(lock, path).owner, item.path);
      assert.deepEqual(
        await packetFile(join(directory, 'inputs', path)),
        archivedDependencyFile(archive, path.slice(item.path.length + 1)),
        'copy_dependency_input_changed',
      );
    }
  }
  return value as Dependency[];
}

export async function verifyCopyRuntimePacket(
  directoryInput: string,
  expected: CopyRuntimeReceipt,
) {
  assert.match(expected.source_commit, /^[a-f0-9]{40}$/);
  assert.match(expected.manifest_sha256, /^[a-f0-9]{64}$/);
  const directory = resolve(directoryInput);
  assert.equal(await realpath(directory), directory, 'copy_packet_directory_link_denied');
  const info = await lstat(join(directory, 'manifest.json'));
  assert.ok(info.isFile() && info.nlink === 1, 'copy_packet_manifest_denied');
  const bytes = await packetFile(join(directory, 'manifest.json'), maximum);
  assert.equal(digest(bytes).sha256, expected.manifest_sha256, 'copy_packet_manifest_changed');
  const value = decode(bytes);
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  const manifest = value as Record<string, unknown>;
  assert.deepEqual(Object.keys(manifest).sort(), [
    'dependencies',
    'kind',
    'members',
    'modules',
    'prerequisites',
    'source',
    'tools',
  ]);
  assert.equal(manifest.kind, kind);
  assert.deepEqual(manifest.source, { commit: expected.source_commit, clean: true });
  assert.deepEqual(manifest.prerequisites, prerequisites, 'copy_packet_authority_denied');
  const modules = COPY_RUNTIME_MODULES.map(([id, input, entrypoint]) => ({
    id,
    input,
    entrypoint,
    bundle: `workers/${id}.mjs`,
  }));
  assert.deepEqual(manifest.modules, modules, 'copy_packet_modules_denied');
  const actual = await copyRuntimeInventory(directory);
  assert.deepEqual(manifest.members, actual, 'copy_packet_members_changed');
  const dependencies = await verifyDependencies(directory, manifest.dependencies);
  const required = [
    ...modules.map((m) => m.bundle),
    'build.json',
    ...dependencies.map((d) => d.archive),
  ];
  for (const path of required)
    assert.ok(
      actual.some((m) => m.path === path),
      'copy_packet_missing_member',
    );
  for (const path of actual.map((m) => m.path))
    assert.ok(required.includes(path) || path.startsWith('inputs/'), 'copy_packet_extra_member');
  for (const path of modules.map((m) => m.input))
    assert.ok(
      actual.some((m) => m.path === `inputs/${path}`),
      'copy_packet_missing_source',
    );
  const buildInfo = decode(await packetFile(join(directory, 'build.json'))) as Record<
    string,
    unknown
  >;
  assert.equal(buildInfo.stage, stage);
  assert.equal(buildInfo.provenance, 'local-build-byte-inventory-not-signed-attestation');
  assert.deepEqual(buildInfo.tools, manifest.tools);
  return { ...expected, stage, modules: modules.length, members: actual.length };
}

export async function prepareCopyRuntimePacket(outputParent: string) {
  const source = releaseSource(root);
  assert.equal(source.clean, true, 'copy_packet_source_dirty');
  const parent = resolve(outputParent);
  const inside = relative(join(root, 'local/generated'), parent);
  assert.ok(
    inside && !inside.startsWith('..') && !inside.startsWith('/'),
    'copy_packet_output_denied',
  );
  // Refuse an existing linked ancestor before creating any directory through it.
  let ancestor = root;
  for (const part of relative(root, parent).split('/')) {
    ancestor = join(ancestor, part);
    const info = await lstat(ancestor).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== 'ENOENT') throw error;
      return null;
    });
    if (info)
      assert.ok(info.isDirectory() && !info.isSymbolicLink(), 'copy_packet_output_link_denied');
    else await mkdir(ancestor, { mode: 0o700 });
  }
  assert.equal(await realpath(parent), parent, 'copy_packet_output_link_denied');
  execFileSync('git', ['check-ignore', '--quiet', parent], { cwd: root, stdio: 'pipe' });
  const directory = await mkdtemp(join(parent, 'companions-'));
  const inputs = new Set([
    'package.json',
    'package-lock.json',
    'Cargo.toml',
    'Cargo.lock',
    'scripts/work-copy-runtime-packet.ts',
    'crates/worker/src/work_copy.rs',
    'crates/worker/src/work_store/copy_job.rs',
  ]);
  const sourceBytes = new Map<string, Buffer>();
  let inputBytes = 0;
  const retainInput = (name: string, bytes: Buffer) => {
    if (!sourceBytes.has(name)) inputBytes += bytes.length;
    assert.ok(
      sourceBytes.size + (sourceBytes.has(name) ? 0 : 1) <= 512 &&
        inputBytes <= COPY_PACKET_LIMITS.bytes,
      'copy_packet_inputs_too_large',
    );
    sourceBytes.set(name, bytes);
    inputs.add(name);
    return bytes;
  };
  const lock = decode(await packetFile(join(root, 'package-lock.json'))) as Lock;
  type LoadedDependency = { record: Dependency; archive: Buffer; names: Set<string> };
  const dependencies = new Map<string, LoadedDependency>();
  const dependencyLoads = new Map<string, Promise<LoadedDependency>>();
  const dependencyFile = async (name: string) => {
    const selected = lockedDependency(lock, name);
    let pending = dependencyLoads.get(selected.owner);
    if (!pending) {
      pending = (async () => {
        assert.ok(dependencyLoads.size < 32, 'copy_dependencies_denied');
        const scratch = await mkdtemp(join(directory, 'npm-cache-'));
        let archive: Buffer;
        try {
          const packed = JSON.parse(
            execFileSync(
              'npm',
              [
                'pack',
                '--offline',
                '--ignore-scripts',
                '--json',
                '--pack-destination',
                scratch,
                selected.resolved,
              ],
              {
                cwd: scratch,
                encoding: 'utf8',
                stdio: ['ignore', 'pipe', 'pipe'],
                maxBuffer: maximum,
                timeout: 30000,
              },
            ),
          );
          assert.ok(Array.isArray(packed) && packed.length === 1);
          const filename = packed[0]?.filename;
          assert.ok(typeof filename === 'string' && basename(filename) === filename);
          archive = await packetFile(join(scratch, filename));
        } finally {
          await rm(scratch, { recursive: true, force: true });
        }
        dependencyIntegrity(archive, selected.integrity);
        const names = new Set(
          execFileSync('tar', ['-tzf', '-'], {
            input: archive,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe'],
            maxBuffer: maximum,
            timeout: 30000,
          })
            .trimEnd()
            .split('\n'),
        );
        const location = `dependencies/${createHash('sha256').update(selected.owner).digest('hex')}.tgz`;
        await mkdir(join(directory, 'dependencies'), { recursive: true, mode: 0o700 });
        await writeFile(join(directory, location), archive, { flag: 'wx', mode: 0o600 });
        const saved = {
          archive,
          names,
          record: {
            path: selected.owner,
            archive: location,
            integrity: selected.integrity,
            resolved: selected.resolved,
            inputs: [] as string[],
          },
        };
        dependencies.set(selected.owner, saved);
        return saved;
      })();
      dependencyLoads.set(selected.owner, pending);
    }
    const saved = await pending;
    const directories = name
      .slice(selected.owner.length + 1)
      .split('/')
      .slice(0, -1);
    const metadata = Array.from(
      { length: directories.length + 1 },
      (_, n) => selected.owner + '/' + [...directories.slice(0, n), 'package.json'].join('/'),
    );
    const checked = [name];
    for (const path of metadata) {
      const member = 'package/' + path.slice(selected.owner.length + 1);
      if (saved.names.has(member)) checked.push(path);
      else {
        const info = await lstat(join(root, path)).catch((error: NodeJS.ErrnoException) => {
          if (error.code !== 'ENOENT') throw error;
          return null;
        });
        assert.equal(info, null, 'copy_dependency_metadata_injected');
      }
    }
    for (const path of checked) {
      const expected =
        sourceBytes.get(path) ??
        archivedDependencyFile(saved.archive, path.slice(selected.owner.length + 1));
      assert.deepEqual(
        await packetFile(join(root, path)),
        expected,
        'copy_dependency_input_changed',
      );
      retainInput(path, expected);
      if (!saved.record.inputs.includes(path)) saved.record.inputs.push(path);
    }
    return sourceBytes.get(name)!;
  };
  const committed = async (name: string) => {
    memberPath(name);
    const bytes = await packetFile(join(root, name));
    const gitBytes = execFileSync('git', ['cat-file', 'blob', `${source.commit}:${name}`], {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: maximum,
    });
    assert.deepEqual(bytes, gitBytes, 'copy_packet_source_changed');
    return retainInput(name, bytes);
  };
  const outputs = [];
  for (const [id, input, entrypoint] of COPY_RUNTIME_MODULES) {
    const result = await build({
      absWorkingDir: root,
      entryPoints: [input],
      bundle: true,
      write: false,
      platform: 'browser',
      format: 'esm',
      target: 'es2022',
      tsconfigRaw: { compilerOptions: { useDefineForClassFields: true } },
      external: ['cloudflare:workers'],
      metafile: true,
      logLevel: 'silent',
      preserveSymlinks: true,
      plugins: [
        {
          name: 'committed-project-inputs',
          setup(builder) {
            builder.onLoad({ filter: /\.[cm]?[tj]sx?$|\.json$/ }, async ({ path }) => {
              const name = relative(root, path).replaceAll('\\', '/');
              const bytes = name.startsWith('node_modules/')
                ? await dependencyFile(name)
                : await committed(name);
              return {
                contents: bytes,
                loader: extname(name) === '.json' ? 'json' : /\.[cm]?ts$/.test(name) ? 'ts' : 'js',
                resolveDir: dirname(path),
              };
            });
          },
        },
      ],
    });
    assert.equal(result.outputFiles.length, 1);
    const output = Object.values(result.metafile.outputs);
    assert.equal(output.length, 1);
    assert.ok(output[0]!.exports.includes(entrypoint) && output[0]!.exports.includes('default'));
    assert.ok(output[0]!.imports.every((i) => i.external && i.path === 'cloudflare:workers'));
    for (const name of Object.keys(result.metafile.inputs)) {
      memberPath(name);
      inputs.add(name);
    }
    const bundle = `workers/${id}.mjs`;
    await mkdir(join(directory, 'workers'), { recursive: true, mode: 0o700 });
    await writeFile(join(directory, bundle), result.outputFiles[0]!.contents, {
      flag: 'wx',
      mode: 0o600,
    });
    outputs.push({ id, input, entrypoint, bundle });
  }
  for (const name of [...inputs].sort()) {
    memberPath(name);
    if (!name.startsWith('node_modules/'))
      execFileSync('git', ['ls-files', '--error-unmatch', '--', name], {
        cwd: root,
        stdio: 'pipe',
      });
    const path = join(directory, 'inputs', name);
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await writeFile(path, sourceBytes.get(name) ?? (await committed(name)), {
      flag: 'wx',
      mode: 0o600,
    });
  }
  const tools = {
    node: process.version,
    esbuild: esbuildVersion,
    wrangler: JSON.parse(await readFile(join(root, 'node_modules/wrangler/package.json'), 'utf8'))
      .version as string,
  };
  await json(join(directory, 'build.json'), {
    stage,
    provenance: 'local-build-byte-inventory-not-signed-attestation',
    tools,
  });
  assert.deepEqual(releaseSource(root), source, 'copy_packet_source_changed');
  await json(join(directory, 'manifest.json'), {
    kind,
    source,
    tools,
    modules: outputs,
    dependencies: [...dependencies.values()].map(({ record }) => ({
      ...record,
      inputs: record.inputs.sort(),
    })),
    prerequisites,
    members: await copyRuntimeInventory(directory),
  });
  const receipt = {
    source_commit: source.commit,
    manifest_sha256: digest(await packetFile(join(directory, 'manifest.json'))).sha256,
  };
  const checked = await verifyCopyRuntimePacket(directory, receipt);
  assert.deepEqual(releaseSource(root), source, 'copy_packet_source_changed');
  return { directory, ...checked };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [mode, directory, hash, source, ...rest] = process.argv.slice(2);
    assert.ok(directory && rest.length === 0);
    if (mode === 'create') {
      assert.ok(!hash && !source);
      console.log(JSON.stringify(await prepareCopyRuntimePacket(directory), null, 2));
    } else {
      assert.ok(mode === 'verify' && hash && source);
      console.log(
        JSON.stringify(
          await verifyCopyRuntimePacket(directory, {
            manifest_sha256: hash,
            source_commit: source,
          }),
          null,
          2,
        ),
      );
    }
  } catch {
    console.error(
      'Copy runtime packet refused. Use a clean committed checkout, ignored output, and a retained source/manifest digest.',
    );
    process.exitCode = 1;
  }
}
