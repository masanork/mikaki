/** Local provisioning only. Does not deploy, mint, copy remotely or grant. */
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { build } from 'esbuild';
import { boundedHostFile, materializeGitRegistry } from './work-git-registry.ts';
export async function prepareGitHostImage(review: unknown, sources: unknown, parent: string) {
  const sealed = await materializeGitRegistry(review, sources, parent);
  const root = fileURLToPath(new URL('../', import.meta.url));
  const image = join(sealed.directory, 'image');
  await mkdir(image, { mode: 0o700 });
  await copyFile(join(root, 'crates/work-git-host-worker/Dockerfile'), join(image, 'Dockerfile'));
  await build({
    entryPoints: [join(root, 'crates/work-git-host-worker/container.ts')],
    outfile: join(image, 'host.mjs'),
    platform: 'node',
    format: 'esm',
    target: 'node26',
    bundle: true,
    logLevel: 'silent',
  });
  const receipt = {
    format_version: 1,
    registry_sha256: sealed.registry_sha256,
    disclosure_digest: sealed.registry.disclosure_digest,
    host_sha256: createHash('sha256')
      .update(await readFile(join(image, 'host.mjs')))
      .digest('hex'),
    dockerfile_sha256: createHash('sha256')
      .update(await readFile(join(image, 'Dockerfile')))
      .digest('hex'),
  };
  await writeFile(
    join(sealed.directory, 'image-receipt.json'),
    JSON.stringify(receipt, null, 2) + '\n',
    { mode: 0o600, flag: 'wx' },
  );
  return { ...sealed, image, receipt };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [reviewFile, sourceFile, outputParent, ...rest] = process.argv.slice(2);
    if (!reviewFile || !sourceFile || !outputParent || rest.length) throw new Error('usage');
    const decode = (b: Buffer) => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(b));
    const result = await prepareGitHostImage(
      decode(await boundedHostFile(reviewFile, 65536)),
      decode(await boundedHostFile(sourceFile, 32768)),
      resolve(outputParent),
    );
    console.log(JSON.stringify({ image: result.image, ...result.receipt }, null, 2));
  } catch {
    console.error(
      'Git host preparation refused. Use an exact Native disclosure record and matching operator source bindings.',
    );
    process.exitCode = 1;
  }
}
