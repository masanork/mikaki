/** Local code-only copy provisioning. Owner consent and productive effects stay Native. */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { disclosureSchema } from '../crates/worker/ui/work-preparation-view.ts';
import { verifyWorkCodeSource } from './prepare-work-code-source.ts';
import { prepareGitHostImage } from './prepare-work-git-host.ts';
import { boundedHostFile } from './work-git-registry.ts';

const reviewSchema = z.strictObject({
  kind: z.literal('disclosure'),
  digest: z.string().regex(/^[a-f0-9]{64}$/),
  manifest: disclosureSchema,
  current_sources: z.literal(true),
});

export async function prepareWorkCodeCopy(
  reviewInput: unknown,
  packetDirectory: string,
  canonicalGitDirectory: string,
  outputParent: string,
) {
  const review = reviewSchema.parse(reviewInput);
  const d = review.manifest;
  assert.ok(
    d.contexts.length === 0 && d.selected_bytes === 0 && d.registered_sources.length === 1,
    'Use a current code-only Native disclosure',
  );
  assert.ok(d.expires_at > Math.floor(Date.now() / 1000), 'The Native disclosure has expired');
  const packet = await verifyWorkCodeSource(packetDirectory, canonicalGitDirectory);
  const source = packet.source;
  assert.equal(d.code.repository, source.source_id);
  assert.equal(d.registered_sources[0]!.source_revision, source.source_revision);
  const { repository: _repository, ...code } = d.code;
  assert.deepEqual(code, { commit: source.commit, tree: source.tree, ...source.code });

  // Restore the exact retained bundle, not the packet's mutable working repository
  // or a caller-supplied path. Recheck the bytes before cloning to fence replacement.
  const bundle = await boundedHostFile(join(packetDirectory, 'source.bundle'), 64 * 1024 * 1024);
  assert.equal(createHash('sha256').update(bundle).digest('hex'), packet.provenance.bundle_sha256);
  const scratch = await mkdtemp(join(tmpdir(), 'mikaki-code-copy-'));
  try {
    const bundlePath = join(scratch, 'source.bundle');
    await writeFile(bundlePath, bundle, { flag: 'wx', mode: 0o600 });
    const gitDir = join(scratch, 'source.git');
    execFileSync('git', ['clone', '--bare', bundlePath, gitDir], {
      timeout: 30000,
      stdio: 'pipe',
    });
    await mkdir(outputParent, { recursive: true });
    const prepared = await prepareGitHostImage(
      review,
      [
        {
          source_id: source.source_id,
          source_revision: source.source_revision,
          access_revision: d.registered_sources[0]!.access_revision,
          gitDir,
        },
      ],
      outputParent,
    );
    const codeCopyReceipt = {
      format_version: 1,
      source_id: source.source_id,
      source_revision: source.source_revision,
      access_revision: d.registered_sources[0]!.access_revision,
      source_commit: packet.provenance.source_commit,
      snapshot_commit: source.commit,
      source_sha256: packet.provenance.source_sha256,
      bundle_sha256: packet.provenance.bundle_sha256,
      disclosure_digest: review.digest,
      registry_sha256: prepared.registry_sha256,
      original_history_included: false,
      owner_consent_recorded: false,
      external_effects: 0,
    };
    await writeFile(
      join(prepared.directory, 'code-copy-receipt.json'),
      JSON.stringify(codeCopyReceipt, null, 2) + '\n',
      { flag: 'wx', mode: 0o600 },
    );
    return { ...prepared, codeCopyReceipt };
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [reviewFile, packetDirectory, outputParent, ...rest] = process.argv.slice(2);
    assert.ok(reviewFile && packetDirectory && outputParent && rest.length === 0);
    const root = fileURLToPath(new URL('../', import.meta.url));
    const canonicalGitDirectory = execFileSync('git', ['rev-parse', '--absolute-git-dir'], {
      cwd: root,
      encoding: 'utf8',
      timeout: 30000,
    }).trim();
    const review = JSON.parse(
      new TextDecoder('utf-8', { fatal: true }).decode(await boundedHostFile(reviewFile, 65536)),
    );
    const prepared = await prepareWorkCodeCopy(
      review,
      resolve(packetDirectory),
      canonicalGitDirectory,
      resolve(outputParent),
    );
    console.log(JSON.stringify({ image: prepared.image, ...prepared.codeCopyReceipt }, null, 2));
  } catch {
    console.error(
      'Code copy preparation refused. Use the retained source packet and current Native code-only disclosure.',
    );
    process.exitCode = 1;
  }
}
