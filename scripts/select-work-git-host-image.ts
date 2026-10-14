/** Offline registry metadata selection. No login, upload, startup or copy authority. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { boundedHostFile } from './work-git-registry.ts';

const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const imageTypes = [
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
] as const;
const indexTypes = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
] as const;
const descriptor = z.object({
  mediaType: z.string().min(1).max(128),
  digest,
  size: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
});
const indexSchema = z.object({
  schemaVersion: z.literal(2),
  mediaType: z.enum(indexTypes),
  manifests: z
    .array(
      descriptor.extend({
        platform: z.object({ os: z.string(), architecture: z.string() }).optional(),
        annotations: z.record(z.string(), z.string()).optional(),
      }),
    )
    .min(1)
    .max(16),
});
const manifestSchema = z.object({
  schemaVersion: z.literal(2),
  mediaType: z.enum(imageTypes),
  config: descriptor.extend({
    mediaType: z.enum([
      'application/vnd.oci.image.config.v1+json',
      'application/vnd.docker.container.image.v1+json',
    ]),
  }),
  layers: z.array(descriptor).min(1).max(128),
});
const configSchema = z.object({
  os: z.literal('linux'),
  architecture: z.literal('amd64'),
  rootfs: z.object({ type: z.literal('layers'), diff_ids: z.array(digest).min(1).max(128) }),
});

export async function selectGitHostRuntimeImage(
  account: string,
  reference: string,
  read: (digest: string) => Promise<Uint8Array>,
) {
  assert.match(account, /^[a-f0-9]{32}$/);
  const selected = new RegExp(
    `^registry\\.cloudflare\\.com/${account}/([a-z0-9][a-z0-9._/-]{0,191})@(sha256:[a-f0-9]{64})$`,
  ).exec(reference);
  assert.ok(selected, 'git_host_image_reference_denied');
  assert.ok(selected[1]!.split('/').every((part) => /^[a-z0-9]+(?:[._-]+[a-z0-9]+)*$/.test(part)));
  const inputDigest = selected[2]!;
  const load = async (expected: string, maximum: number, size?: number) => {
    digest.parse(expected);
    const bytes = await read(expected);
    assert.ok(
      bytes instanceof Uint8Array && bytes.byteLength <= maximum,
      'image_metadata_oversize',
    );
    assert.equal(
      'sha256:' + createHash('sha256').update(bytes).digest('hex'),
      expected,
      'image_metadata_digest_mismatch',
    );
    if (size !== undefined) assert.equal(bytes.byteLength, size, 'image_metadata_size_mismatch');
    return JSON.parse(
      new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes),
    ) as unknown;
  };
  const input = await load(inputDigest, 65536);
  const index = indexSchema.safeParse(input);
  let runtimeDigest = inputDigest;
  let runtime = input;
  if (index.success) {
    const candidates = index.data.manifests.filter(
      (m) =>
        m.platform?.os === 'linux' &&
        m.platform.architecture === 'amd64' &&
        imageTypes.some((type) => type === m.mediaType) &&
        m.annotations?.['vnd.docker.reference.type'] !== 'attestation-manifest',
    );
    assert.equal(candidates.length, 1, 'image_platform_missing_or_ambiguous');
    const candidate = candidates[0]!;
    runtimeDigest = candidate.digest;
    runtime = await load(runtimeDigest, 65536, candidate.size);
  }
  const manifest = manifestSchema.parse(runtime);
  const config = configSchema.parse(
    await load(manifest.config.digest, 262144, manifest.config.size),
  );
  assert.equal(config.rootfs.diff_ids.length, manifest.layers.length, 'image_layer_count_mismatch');
  return {
    format_version: 1,
    input_reference: reference,
    input_digest: inputDigest,
    runtime_reference: `registry.cloudflare.com/${account}/${selected[1]}@${runtimeDigest}`,
    runtime_digest: runtimeDigest,
    runtime_media_type: manifest.mediaType,
    config_digest: manifest.config.digest,
    platform: { os: 'linux', architecture: 'amd64' },
    layers: manifest.layers.length,
    index_resolved: index.success,
    provider_startup_verified: false,
    program_hash_verified: false,
    copy_authorized: false,
    external_effects: false,
  } as const;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [account, reference, directory, ...rest] = process.argv.slice(2);
    assert.ok(account && reference && directory && rest.length === 0);
    const result = await selectGitHostRuntimeImage(account, reference, (sha) =>
      boundedHostFile(join(resolve(directory), sha.slice(7) + '.json'), 262144),
    );
    console.log(JSON.stringify(result, null, 2));
  } catch {
    console.error(
      'Git host image selection refused. Supply digest-matching manifest and Linux/amd64 config metadata.',
    );
    process.exitCode = 1;
  }
}
