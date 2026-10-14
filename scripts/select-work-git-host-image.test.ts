import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { selectGitHostRuntimeImage } from './select-work-git-host-image.ts';

const account = 'a'.repeat(32);
const type = 'application/vnd.oci.image.manifest.v1+json';
const ref = (digest: string) => `registry.cloudflare.com/${account}/mikaki-work-git-host@${digest}`;
function fixture(architecture = 'amd64') {
  const files = new Map<string, Buffer>();
  const put = (value: unknown) => {
    const bytes = Buffer.from(JSON.stringify(value));
    const digest = 'sha256:' + createHash('sha256').update(bytes).digest('hex');
    files.set(digest, bytes);
    return { digest, size: bytes.length };
  };
  const config = put({
    os: 'linux',
    architecture,
    rootfs: { type: 'layers', diff_ids: ['sha256:' + '1'.repeat(64)] },
    config: { Env: ['PRIVATE_VALUE=never-output'] },
  });
  const image = put({
    schemaVersion: 2,
    mediaType: type,
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', ...config },
    layers: [
      {
        mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
        digest: 'sha256:' + '2'.repeat(64),
        size: 123,
      },
    ],
  });
  const entry = { mediaType: type, ...image, platform: { os: 'linux', architecture: 'amd64' } };
  const index = put({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.index.v1+json',
    manifests: [
      entry,
      {
        mediaType: type,
        digest: 'sha256:' + '3'.repeat(64),
        size: 100,
        platform: { os: 'unknown', architecture: 'unknown' },
        annotations: { 'vnd.docker.reference.type': 'attestation-manifest' },
      },
    ],
  });
  const read = async (digest: string) => {
    const value = files.get(digest);
    assert.ok(value);
    return value;
  };
  return { files, put, config, image, entry, index, read };
}

test('index selects only its executable amd64 manifest and keeps config secrets out of its receipt', async () => {
  const f = fixture();
  const calls: string[] = [];
  const result = await selectGitHostRuntimeImage(account, ref(f.index.digest), async (digest) => {
    calls.push(digest);
    return f.read(digest);
  });
  assert.equal(result.runtime_reference, ref(f.image.digest));
  assert.equal(result.index_resolved, true);
  assert.deepEqual(calls, [f.index.digest, f.image.digest, f.config.digest]);
  assert.equal(result.provider_startup_verified, false);
  assert.equal(result.copy_authorized, false);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_VALUE|never-output/);
});
test('a directly pinned runtime manifest preserves its identity', async () => {
  const f = fixture();
  const result = await selectGitHostRuntimeImage(account, ref(f.image.digest), f.read);
  assert.equal(result.runtime_digest, f.image.digest);
  assert.equal(result.index_resolved, false);
});
test('Docker manifest lists resolve with independently checked Docker image config', async () => {
  const f = fixture();
  const manifest = JSON.parse(f.files.get(f.image.digest)!.toString()) as any;
  manifest.mediaType = 'application/vnd.docker.distribution.manifest.v2+json';
  manifest.config.mediaType = 'application/vnd.docker.container.image.v1+json';
  const image = f.put(manifest);
  const index = f.put({
    schemaVersion: 2,
    mediaType: 'application/vnd.docker.distribution.manifest.list.v2+json',
    manifests: [{ ...f.entry, ...image, mediaType: manifest.mediaType }],
  });
  const result = await selectGitHostRuntimeImage(account, ref(index.digest), f.read);
  assert.equal(result.runtime_digest, image.digest);
  assert.equal(result.runtime_media_type, manifest.mediaType);
});
test('missing, ambiguous, attestation-only and wrong config platforms refuse selection', async () => {
  const f = fixture();
  for (const manifests of [
    [{ ...f.entry, platform: { os: 'linux', architecture: 'arm64' } }],
    [f.entry, f.entry],
    [{ ...f.entry, annotations: { 'vnd.docker.reference.type': 'attestation-manifest' } }],
  ]) {
    const index = f.put({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.index.v1+json',
      manifests,
    });
    await assert.rejects(selectGitHostRuntimeImage(account, ref(index.digest), f.read));
  }
  const bad = fixture('arm64');
  await assert.rejects(selectGitHostRuntimeImage(account, ref(bad.index.digest), bad.read));
});
test('digest, descriptor size and configuration substitutions cannot change the selected image', async () => {
  for (const target of ['index', 'image', 'config'] as const) {
    const f = fixture();
    f.files.set(f[target].digest, Buffer.from('{}'));
    await assert.rejects(selectGitHostRuntimeImage(account, ref(f.index.digest), f.read));
  }
  const f = fixture();
  const index = f.put({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.index.v1+json',
    manifests: [{ ...f.entry, size: f.entry.size + 1 }],
  });
  await assert.rejects(selectGitHostRuntimeImage(account, ref(index.digest), f.read));
});
test('foreign, mutable and malformed references refuse before reading registry metadata', async () => {
  const f = fixture();
  for (const reference of [
    ref(f.index.digest).replace(account, 'b'.repeat(32)),
    ref(f.index.digest).replace('@' + f.index.digest, ':latest'),
    ref(f.index.digest) + '?secret=x',
    ref(f.index.digest).replace('/mikaki-work-git-host@', '/../host@'),
  ]) {
    await assert.rejects(
      selectGitHostRuntimeImage(account, reference, async () => {
        assert.fail('unexpected metadata read');
      }),
    );
  }
});
test('oversize metadata refuses without parsing or requesting another object', async () => {
  await assert.rejects(
    selectGitHostRuntimeImage(
      account,
      ref('sha256:' + '4'.repeat(64)),
      async () => new Uint8Array(65537),
    ),
  );
});
