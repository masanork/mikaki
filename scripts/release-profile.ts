import assert from 'node:assert/strict';
import type { ReleaseSource } from './release-inventory.ts';
import type { measureWorkerUpload } from './worker-bundle-size.ts';

export type ReleaseProfile = 'default' | 'messaging-beta';
export function releaseProfile(value: unknown): ReleaseProfile {
  assert.ok(value === 'default' || value === 'messaging-beta', 'Unknown release profile');
  return value;
}

/** Inspect the compiled module without executing archive-supplied JavaScript. */
export function assertCompiledProfile(bytes: Uint8Array, profile: ReleaseProfile) {
  const markers = WebAssembly.Module.exports(new WebAssembly.Module(new Uint8Array(bytes))).filter(
    (item) => item.name.startsWith('mikaki_release_profile_'),
  );
  assert.deepEqual(
    markers,
    [{ name: `mikaki_release_profile_${profile.replace('-', '_')}`, kind: 'function' }],
    'Compiled release profile differs',
  );
}

export function releaseArguments(args: string[]) {
  let profile: ReleaseProfile = 'default';
  let selected = false;
  let allowDirty = false;
  const operands: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--profile') {
      assert.ok(!selected, 'Duplicate release profile');
      profile = releaseProfile(args[++i]);
      selected = true;
    } else if (arg === '--allow-dirty') {
      assert.ok(!allowDirty, 'Duplicate dirty option');
      allowDirty = true;
    } else {
      assert.ok(!arg.startsWith('-'), 'Unknown release option');
      operands.push(arg);
    }
  }
  return { profile, allowDirty, operands };
}

export const MESSAGING_PACKAGE_FILES = [
  'crates/worker/build-messaging-beta/index.js',
  'crates/worker/build-messaging-beta/index_bg.wasm',
  'crates/worker/build-messaging-beta/worker/service.mjs',
  'crates/worker/build-messaging-beta/worker/shim.mjs',
  'assets/chat/client.js',
  'assets/chat/crypto.wasm',
] as const;
export const MESSAGING_PACKAGE_ENTRYPOINTS = [
  'AgentStore',
  'ClaimStore',
  'OpAuthorityAdmin',
  'WorkCopyStore',
  'WorkEffectStore',
  'WorkGitStore',
  'WorkMintStore',
  'default',
];
export type MessagingQualification = {
  schema: 'mikaki-messaging-package-qualification-v2';
  source: ReleaseSource;
  profile: 'messaging-beta';
  runtime: { build_profile: 'messaging-beta'; source_commit: string; source_clean: boolean };
  entrypoints: string[];
  upload: Awaited<ReturnType<typeof measureWorkerUpload>>;
  files: { path: string; bytes: number; sha256: string }[];
};
